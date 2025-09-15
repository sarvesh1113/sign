import os
from dotenv import load_dotenv
load_dotenv()  # Load .env vars

from fastapi import FastAPI, Depends, HTTPException, Request, Body
from sqlalchemy import Column, Integer, String, Text, ForeignKey, JSON, DateTime, select
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker, relationship
import datetime
from msgraph.generated.users.users_request_builder import UsersRequestBuilder
from msgraph import GraphServiceClient
from azure.identity import ClientSecretCredential
from email.parser import BytesParser
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
from msal import ConfidentialClientApplication
from starlette.middleware.sessions import SessionMiddleware
from pydantic import BaseModel
from typing import List
import asyncio
from aiosmtpd.controller import Controller
from aiosmtpd.handlers import Sink

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=os.getenv("SECRET_KEY"))

# DB Setup
Base = declarative_base()
engine = create_async_engine(os.getenv("DATABASE_URL"))
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

async def get_db():
    async with AsyncSessionLocal() as session:
        yield session

# Models
class Tenant(Base):
    __tablename__ = "tenants"
    id = Column(Integer, primary_key=True, index=True)
    ms_tenant_id = Column(String, unique=True)
    access_token = Column(Text)
    refresh_token = Column(Text)
    token_expires = Column(DateTime)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    ms_id = Column(String, unique=True)
    display_name = Column(String)
    job_title = Column(String)
    department = Column(String)
    email = Column(String)  # Added for email lookup
    tenant_id = Column(Integer, ForeignKey("tenants.id"))
    tenant = relationship("Tenant")

class Template(Base):
    __tablename__ = "templates"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    html = Column(Text)
    fields = Column(JSON)
    tenant_id = Column(Integer, ForeignKey("tenants.id"))

class Policy(Base):
    __tablename__ = "policies"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    conditions = Column(JSON)
    template_id = Column(Integer, ForeignKey("templates.id"))
    priority = Column(Integer)
    tenant_id = Column(Integer, ForeignKey("tenants.id"))

# Logic Functions
def get_msal_app():
    return ConfidentialClientApplication(
        client_id=os.getenv("AZURE_CLIENT_ID"),
        client_credential=os.getenv("AZURE_CLIENT_SECRET"),
        authority=f"https://login.microsoftonline.com/{os.getenv('AZURE_TENANT_ID')}"
    )

async def get_graph_client(access_token: str):
    # Use token directly for Graph (simplified; add refresh if expired)
    return GraphServiceClient(credentials=ClientSecretCredential(
        tenant_id=os.getenv("AZURE_TENANT_ID"),
        client_id=os.getenv("AZURE_CLIENT_ID"),
        client_secret=os.getenv("AZURE_CLIENT_SECRET")
    ))  # Note: For delegated, use token in requests

async def sync_users(tenant_id: int, db: AsyncSession):
    tenant = await db.get(Tenant, tenant_id)
    client = await get_graph_client(tenant.access_token)
    users = await client.users.get(select=['id', 'displayName', 'jobTitle', 'department', 'mail'])
    for ms_user in users.value:
        user = await db.execute(select(User).filter(User.ms_id == ms_user.id)).scalars().first()
        if not user:
            user = User(ms_id=ms_user.id)
        user.display_name = ms_user.display_name
        user.job_title = ms_user.job_title
        user.department = ms_user.department
        user.email = ms_user.mail
        user.tenant_id = tenant_id
        db.add(user)
    await db.commit()

async def get_user_by_email(db: AsyncSession, email: str):
    return (await db.execute(select(User).filter(User.email == email))).scalars().first()

async def get_policies_for_tenant(db: AsyncSession, tenant_id: int):
    return (await db.execute(select(Policy).filter(Policy.tenant_id == tenant_id).order_by(Policy.priority))).scalars().all()

async def get_template(db: AsyncSession, template_id: int):
    return await db.get(Template, template_id)

def match_conditions(user, conditions: dict) -> bool:
    return all(getattr(user, key, None) == value for key, value in conditions.items())

async def get_signature_for_user(db: AsyncSession, user_id: int, email_content: bytes) -> str:
    user = await db.get(User, user_id)
    policies = await get_policies_for_tenant(db, user.tenant_id)
    for policy in policies:
        if match_conditions(user, policy.conditions):
            template = await get_template(db, policy.template_id)
            sig = template.html
            for field in template.fields or []:
                value = getattr(user, field, "")
                sig = sig.replace(f"{{{field}}}", value)
            return sig
    return ""

def inject_signature(email_bytes: bytes, sig_html: str) -> bytes:
    parser = BytesParser()
    msg = parser.parsebytes(email_bytes)
    if msg.is_multipart():
        for part in msg.get_payload():
            if part.get_content_type() == 'text/html':
                body = part.get_payload(decode=True).decode()
                injection_point = body.rfind('</body>')
                if injection_point != -1:
                    body = body[:injection_point] + f"<br><div class='signature'>{sig_html}</div>" + body[injection_point:]
                else:
                    body += f"<br><div class='signature'>{sig_html}</div>"
                part.set_payload(body.encode())
    else:
        new_msg = MIMEMultipart()
        new_msg.attach(MIMEText(msg.get_payload(decode=True).decode(), 'plain'))
        new_msg.attach(MIMEText(sig_html, 'html'))
        msg = new_msg
    return msg.as_bytes()

# SMTP Handler
class SignatureHandler:
    async def handle_DATA(self, server, session, envelope):
        # Create a new database session for this request
        async with AsyncSessionLocal() as db:
            user = await get_user_by_email(db, envelope.mail_from)
            if not user:
                return '550 User not found'
            sig = await get_signature_for_user(db, user.id, envelope.content)
            processed_email = inject_signature(envelope.content, sig)
            with smtplib.SMTP(os.getenv("OUTBOUND_SMTP_SERVER"), os.getenv("OUTBOUND_SMTP_PORT")) as smtp:
                smtp.starttls()
                smtp.login(os.getenv("OUTBOUND_SMTP_USER"), os.getenv("OUTBOUND_SMTP_PASS"))
                smtp.sendmail(envelope.mail_from, envelope.rcpt_tos, processed_email)
        return '250 OK'

async def start_smtp():
    handler = SignatureHandler()
    smtp_host = os.getenv("SMTP_HOST", "localhost")
    smtp_port = int(os.getenv("SMTP_PORT", 2525))
    controller = Controller(handler, hostname=smtp_host, port=smtp_port)
    controller.start()

@app.on_event("startup")
async def startup():
    await init_db()
    asyncio.create_task(start_smtp())

# Pydantic Models
class TemplateCreate(BaseModel):
    name: str
    html: str
    fields: List[str]

class PolicyCreate(BaseModel):
    name: str
    conditions: dict
    template_id: int
    priority: int

class SendEmailRequest(BaseModel):
    to_email: str
    subject: str
    body: str
    from_email: str

class SetupRequest(BaseModel):
    ms_tenant_id: str

# Endpoints
@app.post("/setup")
async def setup_tenant(request: SetupRequest, db: AsyncSession = Depends(get_db)):
    tenant = Tenant(ms_tenant_id=request.ms_tenant_id)
    db.add(tenant)
    await db.commit()
    app = get_msal_app()
    auth_url = app.get_authorization_request_url(
        scopes=os.getenv("GRAPH_SCOPES").split(),
        redirect_uri=os.getenv("REDIRECT_URI"),
        state=request.ms_tenant_id
    )
    return {"message": "Tenant created. Redirect to auth URL for consent.", "auth_url": auth_url}

@app.get("/auth/callback")
async def auth_callback(request: Request, code: str = None, state: str = None, db: AsyncSession = Depends(get_db)):
    if not code:
        raise HTTPException(status_code=400, detail="Missing auth code")
    app = get_msal_app()
    result = app.acquire_token_by_authorization_code(
        code,
        scopes=os.getenv("GRAPH_SCOPES").split(),
        redirect_uri=os.getenv("REDIRECT_URI")
    )
    if "error" in result:
        raise HTTPException(status_code=400, detail=result.get("error_description"))
    ms_tenant_id = state
    tenant = (await db.execute(select(Tenant).filter(Tenant.ms_tenant_id == ms_tenant_id))).scalars().first()
    tenant.access_token = result.get("access_token")
    tenant.refresh_token = result.get("refresh_token")
    tenant.token_expires = datetime.datetime.now() + datetime.timedelta(seconds=result.get("expires_in", 3600))
    await db.commit()
    await sync_users(tenant.id, db)
    return {"message": "Auth successful, tokens stored, users synced."}

@app.post("/sync/{tenant_id}")
async def sync(tenant_id: int, db: AsyncSession = Depends(get_db)):
    await sync_users(tenant_id, db)
    return {"message": "Users synced"}

@app.post("/templates")
async def create_template(template: TemplateCreate, tenant_id: int, db: AsyncSession = Depends(get_db)):
    db_template = Template(**template.dict(), tenant_id=tenant_id)
    db.add(db_template)
    await db.commit()
    return db_template

@app.post("/policies")
async def create_policy(policy: PolicyCreate, tenant_id: int, db: AsyncSession = Depends(get_db)):
    db_policy = Policy(**policy.dict(), tenant_id=tenant_id)
    db.add(db_policy)
    await db.commit()
    return db_policy

@app.post("/send_email")
async def send_email(request: SendEmailRequest, db: AsyncSession = Depends(get_db)):
    user = await get_user_by_email(db, request.from_email)
    if not user:
        raise HTTPException(404, "User not found")
    sig_html = await get_signature_for_user(db, user.id, b"")
    msg = MIMEMultipart()
    msg['From'] = request.from_email
    msg['To'] = request.to_email
    msg['Subject'] = request.subject
    html_body = f"{request.body}<br><div class='signature'>{sig_html}</div>"
    msg.attach(MIMEText(html_body, 'html'))
    try:
        with smtplib.SMTP(os.getenv("OUTBOUND_SMTP_SERVER"), os.getenv("OUTBOUND_SMTP_PORT")) as smtp:
            smtp.starttls()
            smtp.login(os.getenv("OUTBOUND_SMTP_USER"), os.getenv("OUTBOUND_SMTP_PASS"))
            smtp.send_message(msg)
        return {"message": "Email sent with signature appended"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health():
    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
