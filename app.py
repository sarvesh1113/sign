import os
import asyncio
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from sqlalchemy import Column, Integer, String, Text, ForeignKey, JSON, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker, relationship
from msal import ConfidentialClientApplication
from pydantic import BaseModel
from typing import List
from datetime import datetime
from email.parser import BytesParser
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from string import Template
from base64 import b64decode
import requests

load_dotenv()

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8000", "https://9934bb037ac2.ngrok-free.app", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database Setup
Base = declarative_base()
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./test.db")
engine = create_async_engine(DATABASE_URL)
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

async def get_db():
    async with AsyncSessionLocal() as session:
        yield session

# Models
class Tenant(Base):
    __tablename__ = "tenants"
    id = Column(Integer, primary_key=True, index=True)
    azure_tenant_id = Column(String, unique=True)
    access_token = Column(Text)
    refresh_token = Column(Text)
    token_expires = Column(DateTime)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    azure_user_id = Column(String, unique=True)
    display_name = Column(String)
    email = Column(String)
    job_title = Column(String)
    department = Column(String)
    groups = Column(JSON)
    tenant_id = Column(Integer, ForeignKey("tenants.id"))
    tenant = relationship("Tenant")

class SignatureTemplate(Base):
    __tablename__ = "signature_templates"
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"))
    name = Column(String)
    html_template = Column(Text)
    rules = Column(JSON)

# MSAL Config
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
AUTHORITY = "https://login.microsoftonline.com/common"
SCOPES = ["https://graph.microsoft.com/User.Read", "https://graph.microsoft.com/GroupMember.Read.All", "https://graph.microsoft.com/Mail.Send"]
REDIRECT_URI = os.getenv("REDIRECT_URI", "http://localhost:8000/auth/callback")  # Set in env for Render

msal_app = ConfidentialClientApplication(CLIENT_ID, authority=AUTHORITY, client_credential=CLIENT_SECRET)

# Helper Functions
async def get_or_create_tenant(db: AsyncSession, azure_tenant_id: str):
    tenant = await db.execute(select(Tenant).filter(Tenant.azure_tenant_id == azure_tenant_id))
    tenant = tenant.scalar()
    if not tenant:
        tenant = Tenant(azure_tenant_id=azure_tenant_id)
        db.add(tenant)
        await db.commit()
        await db.refresh(tenant)
    return tenant

async def refresh_access_token(user: User, db: AsyncSession):
    result = msal_app.acquire_token_by_refresh_token(user.refresh_token, scopes=SCOPES)
    if "error" in result:
        raise HTTPException(status_code=401, detail="Token refresh failed: " + result.get("error_description"))
    user.access_token = result["access_token"]
    user.refresh_token = result.get("refresh_token")
    await db.commit()

async def sync_user_data(user_id: int, db: AsyncSession):
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    headers = {"Authorization": f"Bearer {user.access_token}"}
    try:
        profile_resp = requests.get("https://graph.microsoft.com/v1.0/me?$select=displayName,mail,jobTitle,department", headers=headers)
        profile_resp.raise_for_status()
        profile = profile_resp.json()
        user.display_name = profile.get("displayName")
        user.email = profile.get("mail")
        user.job_title = profile.get("jobTitle")
        user.department = profile.get("department")
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
            await refresh_access_token(user, db)
            headers["Authorization"] = f"Bearer {user.access_token}"
            profile_resp = requests.get("https://graph.microsoft.com/v1.0/me?$select=displayName,mail,jobTitle,department", headers=headers)
            profile = profile_resp.json()
            user.display_name = profile.get("displayName")
            user.email = profile.get("mail")
            user.job_title = profile.get("jobTitle")
            user.department = profile.get("department")
        else:
            raise HTTPException(status_code=500, detail="Graph API error: " + str(e))
    try:
        groups_resp = requests.get("https://graph.microsoft.com/v1.0/me/memberOf", headers=headers)
        groups_resp.raise_for_status()
        groups = groups_resp.json()["value"]
        user.groups = [{"id": g["id"], "displayName": g.get("displayName")} for g in groups if g["@odata.type"] == "#microsoft.graph.group"]
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
            pass  # Already refreshed
        raise HTTPException(status_code=500, detail="Graph API error for groups: " + str(e))
    await db.commit()

async def get_signature_for_user(db: AsyncSession, user_id: int) -> str:
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    templates = await db.execute(select(SignatureTemplate).filter(SignatureTemplate.tenant_id == user.tenant_id))
    templates = templates.scalars().all()
    selected_template = None
    for t in templates:
        rules = t.rules or {}
        match = True
        if "department" in rules and rules["department"] != user.department:
            match = False
        if "group_id" in rules and rules["group_id"] not in [g["id"] for g in user.groups or []]:
            match = False
        if match:
            selected_template = t
            break
    if not selected_template:
        raise HTTPException(400, "No matching signature template found")
    return Template(selected_template.html_template).substitute(
        displayName=user.display_name or "",
        jobTitle=user.job_title or "",
        department=user.department or ""
    )

def inject_signature(email_bytes: bytes, sig_html: str) -> bytes:
    parser = BytesParser()
    msg = parser.parsebytes(email_bytes)
    if msg.is_multipart():
        for part in msg.get_payload():
            if part.get_content_type() == 'text/html':
                part.set_payload(part.get_payload() + "<br><br>" + sig_html)
    else:
        msg.set_payload(msg.get_payload() + "<br><br>" + sig_html)
    return msg.as_bytes()

async def forward_email(access_token: str, from_email: str, to_emails: list, processed_email: bytes):
    parser = BytesParser()
    msg = parser.parsebytes(processed_email)
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    payload = {
        "message": {
            "subject": msg["subject"] or "No Subject",
            "body": {
                "contentType": "HTML",
                "content": processed_email.decode('utf-8', errors='ignore')
            },
            "toRecipients": [{"emailAddress": {"address": t}} for t in to_emails],
            "from": {"emailAddress": {"address": from_email}}  # Optional, Graph may override
        },
        "saveToSentItems": True
    }
    try:
        resp = requests.post("https://graph.microsoft.com/v1.0/me/sendMail", headers=headers, json=payload)
        resp.raise_for_status()
    except requests.exceptions.HTTPError as e:
        raise HTTPException(status_code=e.response.status_code, detail=f"Graph API error: {str(e)}")

# Authentication Endpoints
@app.get("/auth/login")
async def login(request: Request):
    """Initiate OAuth authorization code flow and create/retrieve tenant."""
    auth_url = msal_app.get_authorization_request_url(SCOPES, redirect_uri=REDIRECT_URI)
    return RedirectResponse(auth_url)

@app.get("/auth/callback")
async def auth_callback(request: Request, code: str, db: AsyncSession = Depends(get_db)):
    """Handle OAuth callback, acquire token, create tenant, and sync user data."""
    result = msal_app.acquire_token_by_authorization_code(
        code, scopes=SCOPES, redirect_uri=REDIRECT_URI
    )
    if "error" in result:
        raise HTTPException(status_code=400, detail=result.get("error_description"))

    access_token = result["access_token"]
    refresh_token = result.get("refresh_token")
    id_token_claims = result["id_token_claims"]
    azure_tenant_id = id_token_claims["tid"]
    azure_user_id = id_token_claims.get("oid") or id_token_claims.get("sub")

    # Get or create tenant
    tenant = await get_or_create_tenant(db, azure_tenant_id)

    # Check if user exists
    user = await db.execute(select(User).filter(User.azure_user_id == azure_user_id))
    user = user.scalar()
    if not user:
        user = User(
            tenant_id=tenant.id,
            azure_user_id=azure_user_id,
            access_token=access_token,
            refresh_token=refresh_token
        )
        db.add(user)
    else:
        user.access_token = access_token
        user.refresh_token = refresh_token
    await db.commit()
    await db.refresh(user)

    print(f"User {user.azure_user_id} authenticated in tenant {tenant.azure_tenant_id}")
    print(f"Access Token: {user.access_token}")
    print(f"Refresh Token: {user.refresh_token}")

    # Sync directory data
    await sync_user_data(user.id, db)

    return {"message": "Authenticated successfully", "user_id": str(user.id)}

# Health Checks
@app.get("/")
async def root():
    return {"message": "Exclaimer Replica is running", "status": "healthy"}

@app.get("/health")
async def health():
    return {"status": "ok"}

# Signature Template Management
class TemplateCreate(BaseModel):
    name: str
    html_template: str
    rules: dict

@app.post("/templates")
async def create_template(template: TemplateCreate, user_id: str, db: AsyncSession = Depends(get_db)):
    user = await db.get(User, uuid.UUID(user_id))
    if not user:
        raise HTTPException(404, "User not found")
    db_template = SignatureTemplate(
        tenant_id=user.tenant_id,
        name=template.name,
        html_template=template.html_template,
        rules=template.rules
    )
    db.add(db_template)
    await db.commit()
    await db.refresh(db_template)
    return db_template

@app.get("/templates")
async def list_templates(user_id: str, db: AsyncSession = Depends(get_db)):
    user = await db.get(User, uuid.UUID(user_id))
    if not user:
        raise HTTPException(404, "User not found")
    templates = await db.execute(select(SignatureTemplate).filter(SignatureTemplate.tenant_id == user.tenant_id))
    return templates.scalars().all()

# Email Sending
class EmailSend(BaseModel):
    to: str
    subject: str
    body: str

@app.post("/send_email")
async def send_email(email: EmailSend, user_id: str, db: AsyncSession = Depends(get_db)):
    user = await db.get(User, uuid.UUID(user_id))
    if not user:
        raise HTTPException(404, "User not found")
    sig_html = await get_signature_for_user(db, user.id)
    full_body = f"{email.body}<br><br><div class='signature'>{sig_html}</div>"
    await forward_email(user.access_token, user.email, [email.to], full_body.encode())
    return {"message": "Email sent successfully"}

# Email Proxy for Inbound
class EmailProxyRequest(BaseModel):
    email_data: str  # base64 encoded email bytes
    from_email: str
    to_emails: list[str]

@app.post("/email-proxy")
async def email_proxy(request: EmailProxyRequest, db: AsyncSession = Depends(get_db)):
    email_bytes = b64decode(request.email_data)
    user = await db.execute(select(User).filter(User.email == request.from_email))
    user = user.scalar()
    if not user:
        raise HTTPException(404, "User not found")
    sig_html = await get_signature_for_user(db, user.id)
    processed_email = inject_signature(email_bytes, sig_html)
    await forward_email(user.access_token, request.from_email, request.to_emails, processed_email)
    return {"message": "Email processed and forwarded"}

# SMTP Handling (Disabled on Render)
async def start_smtp():
    if os.getenv("ENV", "local") == "render":
        print("SMTP disabled on Render; use /email-proxy for inbound processing")
        return
    # For local testing (implement if needed)
    # from aiosmtpd.controller import Controller
    # handler = SignatureHandler()  # Define if adding SMTP
    # controller = Controller(handler, hostname="0.0.0.0", port=2525)
    # controller.start()

@app.on_event("startup")
async def startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    if os.getenv("ENV", "local") != "render":
        await start_smtp()

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
