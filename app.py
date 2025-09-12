import os
import uuid
import requests
import json
import time  # For retries
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from sqlalchemy import create_engine, Column, String, Text, DateTime, ForeignKey, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.exc import ProgrammingError, OperationalError
from msal import ConfidentialClientApplication
from pydantic import BaseModel
from datetime import datetime
from dotenv import load_dotenv
from string import Template
import logging
import psycopg
from sqlalchemy.dialects.postgresql import psycopg as psycopg_dialect

# Load environment variables
load_dotenv()

# Logging for Render (visible in dashboard logs)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database setup (inlined)
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise ValueError("DATABASE_URL must be set in environment variables")

engine = create_engine(DATABASE_URL, echo=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Database models (inlined, id as String for simplicity)
class Tenant(Base):
    __tablename__ = "tenants"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String)
    azure_tenant_id = Column(String, unique=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String, ForeignKey("tenants.id"))
    azure_user_id = Column(String, unique=True)
    display_name = Column(String)
    email = Column(String)
    job_title = Column(String)
    department = Column(String)
    groups = Column(JSON)
    access_token = Column(Text)
    refresh_token = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)

class SignatureTemplate(Base):
    __tablename__ = "signature_templates"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String, ForeignKey("tenants.id"))
    name = Column(String)
    html_template = Column(Text)
    rules = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)

class SentEmailLog(Base):
    __tablename__ = "sent_email_logs"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String, ForeignKey("tenants.id"))
    user_id = Column(String, ForeignKey("users.id"))
    to_email = Column(String)
    subject = Column(String)
    body_preview = Column(Text)
    signature_used = Column(String, ForeignKey("signature_templates.id"))
    sent_at = Column(DateTime, default=datetime.utcnow)

# FastAPI app
app = FastAPI()

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Robust table creation on startup with retries
@app.on_event("startup")
async def startup_event():
    logger.info("App starting: Creating tables...")
    max_retries = 5
    for attempt in range(max_retries):
        try:
            Base.metadata.create_all(bind=engine)
            logger.info(f"Tables created successfully on attempt {attempt + 1}.")
            # Verify by querying a simple table
            with SessionLocal() as session:
                result = session.execute("SELECT 1 FROM tenants LIMIT 1").fetchone()
            logger.info("Table verification successful.")
            break
        except (ProgrammingError, OperationalError) as e:
            logger.warning(f"Table creation attempt {attempt + 1} failed: {e}")
            if attempt < max_retries - 1:
                time.sleep(10)  # Wait 10s before retry
            else:
                logger.error("Failed to create tables after all retries. Check DATABASE_URL, permissions, and RDS security group.")
                raise RuntimeError("Database initialization failed")

# MSAL Config
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
if not CLIENT_ID or not CLIENT_SECRET:
    raise ValueError("CLIENT_ID and CLIENT_SECRET must be set")

AUTHORITY = "https://login.microsoftonline.com/common"
SCOPES = ["https://graph.microsoft.com/User.Read", "https://graph.microsoft.com/GroupMember.Read.All", "https://graph.microsoft.com/Mail.Send"]
REDIRECT_URI = "https://sign-gbl9.onrender.com/auth/callback/auth/callback"

msal_app = ConfidentialClientApplication(
    CLIENT_ID, authority=AUTHORITY, client_credential=CLIENT_SECRET
)

# Dependency for DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Helper to get or create tenant
def get_or_create_tenant(db: Session, azure_tenant_id: str):
    tenant = db.query(Tenant).filter(Tenant.azure_tenant_id == azure_tenant_id).first()
    if not tenant:
        tenant = Tenant(azure_tenant_id=azure_tenant_id)
        db.add(tenant)
        db.commit()
        db.refresh(tenant)
        logger.info(f"Created tenant {tenant.id}")
    return tenant

# Authentication Endpoints
@app.get("/auth/login")
def login(request: Request):
    auth_url = msal_app.get_authorization_request_url(SCOPES, redirect_uri=REDIRECT_URI)
    logger.info("OAuth login initiated")
    return RedirectResponse(auth_url)

@app.get("/auth/callback")
def auth_callback(request: Request, code: str, db: Session = Depends(get_db)):
    result = msal_app.acquire_token_by_authorization_code(
        code, scopes=SCOPES, redirect_uri=REDIRECT_URI
    )
    if "error" in result:
        logger.error(f"OAuth error: {result.get('error_description')}")
        raise HTTPException(status_code=400, detail=result.get("error_description"))

    access_token = result["access_token"]
    refresh_token = result.get("refresh_token")
    id_token_claims = result["id_token_claims"]
    azure_tenant_id = id_token_claims["tid"]
    azure_user_id = id_token_claims["oid"]

    tenant = get_or_create_tenant(db, azure_tenant_id)

    user = db.query(User).filter(User.azure_user_id == azure_user_id).first()
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
    db.commit()
    db.refresh(user)

    logger.info(f"User {azure_user_id} authenticated")

    sync_user_data(str(user.id), db)

    return {"message": "Authenticated successfully", "user_id": str(user.id)}

def refresh_access_token(user: User):
    result = msal_app.acquire_token_by_refresh_token(user.refresh_token, scopes=SCOPES)
    if "error" in result:
        logger.error(f"Token refresh failed: {result.get('error_description')}")
        raise HTTPException(status_code=401, detail="Token refresh failed")
    user.access_token = result["access_token"]
    user.refresh_token = result.get("refresh_token")

# Directory Synchronization (Fixed retry to /me)
def sync_user_data(user_id: str, db: Session):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        logger.warning(f"User {user_id} not found for sync")
        raise HTTPException(status_code=404, detail="User not found")

    headers = {"Authorization": f"Bearer {user.access_token}"}

    # GET /me
    try:
        profile_resp = requests.get("https://graph.microsoft.com/v1.0/me?$select=displayName,mail,jobTitle,department", headers=headers)
        profile_resp.raise_for_status()
        profile = profile_resp.json()
        user.display_name = profile.get("displayName")
        user.email = profile.get("mail")
        user.job_title = profile.get("jobTitle")
        user.department = profile.get("department")
        logger.info(f"Synced profile for {user.email}")
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
            refresh_access_token(user)
            headers["Authorization"] = f"Bearer {user.access_token}"
            profile_resp = requests.get("https://graph.microsoft.com/v1.0/me?$select=displayName,mail,jobTitle,department", headers=headers)  # Fixed: /me
            profile_resp.raise_for_status()
            profile = profile_resp.json()
            user.display_name = profile.get("displayName")
            user.email = profile.get("mail")
            user.job_title = profile.get("jobTitle")
            user.department = profile.get("department")
        else:
            logger.error(f"Profile sync error: {e}")
            raise HTTPException(status_code=500, detail=str(e))

    # GET /me/memberOf
    try:
        groups_resp = requests.get("https://graph.microsoft.com/v1.0/me/memberOf", headers=headers)
        groups_resp.raise_for_status()
        groups = groups_resp.json()["value"]
        user.groups = [{"id": g["id"], "displayName": g.get("displayName")} for g in groups if g["@odata.type"] == "#microsoft.graph.group"]
        logger.info(f"Synced {len(user.groups)} groups for {user.email}")
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
            pass
        else:
            logger.error(f"Groups sync error: {e}")
            raise HTTPException(status_code=500, detail=str(e))

    db.commit()

# Signature Template Management
class TemplateCreate(BaseModel):
    name: str
    html_template: str
    rules: dict

@app.post("/templates")
def create_template(template: TemplateCreate, user_id: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(404, "User not found")
    db_template = SignatureTemplate(
        tenant_id=user.tenant_id,
        name=template.name,
        html_template=template.html_template,
        rules=template.rules
    )
    db.add(db_template)
    db.commit()
    db.refresh(db_template)
    logger.info(f"Created template {db_template.id}")
    return db_template

@app.get("/templates")
def list_templates(user_id: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(404, "User not found")
    templates = db.query(SignatureTemplate).filter(SignatureTemplate.tenant_id == user.tenant_id).all()
    logger.info(f"Listed {len(templates)} templates")
    return templates

# Email Sending Flow
class EmailSend(BaseModel):
    to: str
    subject: str
    body: str

@app.post("/send_email")
def send_email(email: EmailSend, user_id: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(404, "User not found")

    templates = db.query(SignatureTemplate).filter(SignatureTemplate.tenant_id == user.tenant_id).all()
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

    sig_html = Template(selected_template.html_template).substitute(
        displayName=user.display_name or '',
        jobTitle=user.job_title or '',
        department=user.department or '',
    )
    full_body = email.body + "<br><br>" + sig_html

    headers = {
        "Authorization": f"Bearer {user.access_token}",
        "Content-Type": "application/json"
    }
    payload = {
        "message": {
            "subject": email.subject,
            "body": {
                "contentType": "HTML",
                "content": full_body
            },
            "toRecipients": [
                {"emailAddress": {"address": email.to}}
            ]
        },
        "saveToSentItems": True
    }
    try:
        logger.info(f"Sending email to {email.to}")
        resp = requests.post("https://graph.microsoft.com/v1.0/me/sendMail", headers=headers, json=payload)
        logger.info(f"Send response: {resp.status_code} - {resp.text}")
        resp.raise_for_status()
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
            refresh_access_token(user)
            db.commit()
            headers["Authorization"] = f"Bearer {user.access_token}"
            resp = requests.post("https://graph.microsoft.com/v1.0/me/sendMail", headers=headers, json=payload)
            logger.info(f"Retry response: {resp.status_code} - {resp.text}")
            resp.raise_for_status()
        else:
            logger.error(f"SendMail error: {e}")
            raise HTTPException(500, str(e))

    log = SentEmailLog(
        tenant_id=user.tenant_id,
        user_id=user.id,
        to_email=email.to,
        subject=email.subject,
        body_preview=full_body[:100],
        signature_used=selected_template.id,
        sent_at=datetime.utcnow()
    )
    db.add(log)
    db.commit()

    logger.info(f"Email sent and logged")
    return {"message": "Email sent successfully"}

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port, reload=False)  # No reload on Render

