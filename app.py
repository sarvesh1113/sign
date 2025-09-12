import os
import uuid
import requests
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from sqlalchemy import create_engine, event, Column, String, Text, DateTime, ForeignKey, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from msal import ConfidentialClientApplication  # For auth code flow
from pydantic import BaseModel
from datetime import datetime
from dotenv import load_dotenv
from string import Template  # For placeholder replacement

# Load environment variables
load_dotenv()

# Database setup
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///app.db")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# For PostgreSQL, ensure UUID extension is enabled
@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    if "postgresql" in DATABASE_URL:
        with dbapi_connection.cursor() as cursor:
            cursor.execute('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"')

# Models
class Tenant(Base):
    __tablename__ = "tenants"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String)
    azure_tenant_id = Column(String, unique=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class User(Base):
    __tablename__ = "users"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id"))
    azure_user_id = Column(String, unique=True)
    display_name = Column(String)
    email = Column(String)
    job_title = Column(String)
    department = Column(String)
    groups = Column(JSON)  # List of {"id": "", "displayName": ""}
    access_token = Column(Text)  # Encrypt in production
    refresh_token = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)

class SignatureTemplate(Base):
    __tablename__ = "signature_templates"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id"))
    name = Column(String)
    html_template = Column(Text)  # e.g., "<p>{{displayName}} - {{jobTitle}}</p>"
    rules = Column(JSON)  # e.g., {"department": "sales"}
    created_at = Column(DateTime, default=datetime.utcnow)

class SentEmailLog(Base):
    __tablename__ = "sent_email_logs"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id"))
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    to_email = Column(String)
    subject = Column(String)
    body_preview = Column(Text)
    signature_used = Column(UUID(as_uuid=True), ForeignKey("signature_templates.id"))
    sent_at = Column(DateTime, default=datetime.utcnow)

# Create tables
def create_tables():
    try:
        # For PostgreSQL, ensure UUID extension is enabled
        if "postgresql" in os.getenv("DATABASE_URL", ""):
            with engine.connect() as conn:
                conn.execute('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"')
                conn.commit()
        Base.metadata.create_all(bind=engine)
        print("Tables created successfully")
    except Exception as e:
        print(f"Error creating tables: {e}")

# FastAPI app
app = FastAPI()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8000", "https://9934bb037ac2.ngrok-free.app", "*"],  # Adjust for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create tables
@app.on_event("startup")
async def startup_event():
    create_tables()

# MSAL Config
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
AUTHORITY = "https://login.microsoftonline.com/common"
SCOPES = ["https://graph.microsoft.com/User.Read", "https://graph.microsoft.com/GroupMember.Read.All", "https://graph.microsoft.com/Mail.Send"]
REDIRECT_URI = "https://sign-gbl9.onrender.com/auth/callback"  # Match app registration

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
    return tenant

# Authentication Endpoints

@app.get("/auth/login")
def login(request: Request):
    """Initiate OAuth authorization code flow. Redirects user to Microsoft login."""
    auth_url = msal_app.get_authorization_request_url(SCOPES, redirect_uri=REDIRECT_URI)
    return RedirectResponse(auth_url)

@app.get("/auth/callback")
def auth_callback(request: Request, code: str, db: Session = Depends(get_db)):
    """Handle OAuth callback, acquire token, sync user data."""
    result = msal_app.acquire_token_by_authorization_code(
        code, scopes=SCOPES, redirect_uri=REDIRECT_URI
    )
    if "error" in result:
        raise HTTPException(status_code=400, detail=result.get("error_description"))

    access_token = result["access_token"]
    refresh_token = result.get("refresh_token")
    id_token_claims = result["id_token_claims"]
    azure_tenant_id = id_token_claims["tid"]
    azure_user_id = id_token_claims["oid"]  # Or 'sub'

    # Get or create tenant
    tenant = get_or_create_tenant(db, azure_tenant_id)

    # Check if user exists
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
    print(f"User {user.azure_user_id} authenticated in tenant {tenant.azure_tenant_id}")
    print(f"Access Token: {user.access_token}")
    print(f"Refresh Token: {user.refresh_token}")
    db.commit()
    db.refresh(user)

    # Sync directory data
    sync_user_data(user.id, db)

    return {"message": "Authenticated successfully", "user_id": str(user.id)}

def refresh_access_token(user: User):
    """Refresh token if expired. Handle errors like consent revoked."""
    result = msal_app.acquire_token_by_refresh_token(user.refresh_token, scopes=SCOPES)
    if "error" in result:
        raise HTTPException(status_code=401, detail="Token refresh failed: " + result.get("error_description"))
    user.access_token = result["access_token"]
    user.refresh_token = result.get("refresh_token")

# Directory Synchronization
def sync_user_data(user_id: uuid.UUID, db: Session):
    """Fetch and update user profile and groups using Graph API."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
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
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
            refresh_access_token(user)
            # Retry once
            headers["Authorization"] = f"Bearer {user.access_token}"
            profile_resp = requests.get("https://graph.microsoft.com/v1.0/users?$select=displayName,mail,jobTitle,department", headers=headers)
            profile = profile_resp.json()
            user.display_name = profile.get("displayName")
            user.email = profile.get("mail")
            user.job_title = profile.get("jobTitle")
            user.department = profile.get("department")
        else:
            raise HTTPException(status_code=500, detail="Graph API error: " + str(e))

    # GET /me/memberOf
    try:
        groups_resp = requests.get("https://graph.microsoft.com/v1.0/me/memberOf", headers=headers)
        groups_resp.raise_for_status()
        groups = groups_resp.json()["value"]
        user.groups = [{"id": g["id"], "displayName": g.get("displayName")} for g in groups if g["@odata.type"] == "#microsoft.graph.group"]
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
            # Already refreshed above, handle as error
            pass
        raise HTTPException(status_code=500, detail="Graph API error for groups: " + str(e))

    db.commit()

# Signature Template Management (CRUD APIs)

class TemplateCreate(BaseModel):
    name: str
    html_template: str
    rules: dict  # e.g., {"department": "sales"}

@app.post("/templates")
def create_template(template: TemplateCreate, user_id: str, db: Session = Depends(get_db)):
    """Create a new signature template. user_id from auth context (simplified)."""
    user = db.query(User).filter(User.id == uuid.UUID(user_id)).first()
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
    return db_template

@app.get("/templates")
def list_templates(user_id: str, db: Session = Depends(get_db)):
    """List templates for the user's tenant."""
    user = db.query(User).filter(User.id == uuid.UUID(user_id)).first()
    if not user:
        raise HTTPException(404, "User not found")
    return db.query(SignatureTemplate).filter(SignatureTemplate.tenant_id == user.tenant_id).all()

# Similar for update/delete: @app.put("/templates/{template_id}"), @app.delete("/templates/{template_id}")
# Enforce tenant_id match for security.

# Email Sending Flow

class EmailSend(BaseModel):
    to: str
    subject: str
    body: str  # HTML body without signature

@app.post("/send_email")
def send_email(email: EmailSend, user_id: str, db: Session = Depends(get_db)):
    """Compose and send email with appended signature using Graph API."""
    user = db.query(User).filter(User.id == uuid.UUID(user_id)).first()
    if not user:
        raise HTTPException(404, "User not found")

    # Find applicable template based on rules
    templates = db.query(SignatureTemplate).filter(SignatureTemplate.tenant_id == user.tenant_id).all()
    selected_template = None
    for t in templates:
        rules = t.rules or {}
        match = True
        if "department" in rules and rules["department"] != user.department:
            match = False
        # Add more rule checks, e.g., for groups
        if "group_id" in rules and rules["group_id"] not in [g["id"] for g in user.groups or []]:
            match = False
        if match:
            selected_template = t
            break
    if not selected_template:
        raise HTTPException(400, "No matching signature template found")

    # Merge signature
    sig_html = Template(selected_template.html_template).substitute(
        displayName=user.display_name,
        jobTitle=user.job_title,
        department=user.department,
        # Add more placeholders
    )
    # full_body = email.body + "<br><br>" + sig_html  # Append signature
    
    full_body = email.body
    # Optional: Embed tracking (e.g., <img src="https://your-tracking-url?event=open&tenant={user.tenant_id}"> in sig_html)

    # Graph API call
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
        resp = requests.post("https://graph.microsoft.com/v1.0/me/sendMail", headers=headers, json=payload)
        resp.raise_for_status()
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
            refresh_access_token(user)
            db.commit()
            headers["Authorization"] = f"Bearer {user.access_token}"
            resp = requests.post("https://graph.microsoft.com/v1.0/me/sendMail", headers=headers, json=payload)
            print(f"Graph API Response: Status={resp.status_code}, Body={resp.text}")
            resp.raise_for_status()
        else:
            raise HTTPException(500, "Graph API sendMail error: " + str(e) + ". Check if consent revoked or permissions missing.")

    # Log
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

    return {"message": "Email sent successfully"}

# Optional Analytics (stub)
# @app.get("/analytics") - Query AnalyticsEvent filtered by tenant_id
# For tracking: Host a /track endpoint that logs GET requests with query params.

# Run: uvicorn main:app --reload

