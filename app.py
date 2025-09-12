import os
import requests
import json
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from msal import ConfidentialClientApplication
from pydantic import BaseModel
from datetime import datetime
from dotenv import load_dotenv
import logging

# Load environment variables
load_dotenv()

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Skip DB for testing - No SQLAlchemy/psycopg imports
# Later: Uncomment and add back DB code

app = FastAPI()

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# MSAL Config
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
if not CLIENT_ID or not CLIENT_SECRET:
    raise ValueError("CLIENT_ID and CLIENT_SECRET must be set")

AUTHORITY = "https://login.microsoftonline.com/common"
SCOPES = ["https://graph.microsoft.com/User.Read", "https://graph.microsoft.com/GroupMember.Read.All", "https://graph.microsoft.com/Mail.Send"]
REDIRECT_URI = "https://sign-gbl9.onrender.com/auth/callback"

msal_app = ConfidentialClientApplication(
    CLIENT_ID, authority=AUTHORITY, client_credential=CLIENT_SECRET
)

# In-memory user storage for testing (no DB)
users = {}  # {user_id: {'access_token': str, 'display_name': str, 'email': str, 'department': str, 'groups': list}}

# Authentication Endpoints
@app.get("/auth/login")
def login(request: Request):
    auth_url = msal_app.get_authorization_request_url(SCOPES, redirect_uri=REDIRECT_URI)
    logger.info("OAuth login initiated")
    return RedirectResponse(auth_url)

@app.get("/auth/callback")
def auth_callback(request: Request, code: str):
    result = msal_app.acquire_token_by_authorization_code(
        code, scopes=SCOPES, redirect_uri=REDIRECT_URI
    )
    if "error" in result:
        logger.error(f"OAuth error: {result.get('error_description')}")
        raise HTTPException(status_code=400, detail=result.get("error_description"))

    access_token = result["access_token"]
    refresh_token = result.get("refresh_token")
    id_token_claims = result["id_token_claims"]
    azure_user_id = id_token_claims["oid"]
    azure_tenant_id = id_token_claims["tid"]
    display_name = id_token_claims.get("name", "Unknown")
    email = id_token_claims.get("preferred_username", "unknown@example.com")

    # Hardcode department and groups for testing (skip sync)
    user_id = str(uuid.uuid4())
    users[user_id] = {
        'access_token': access_token,
        'refresh_token': refresh_token,
        'display_name': display_name,
        'email': email,
        'department': 'Sales',  # Hardcode; later from Graph
        'groups': [{'id': 'test-group', 'displayName': 'Test Group'}]  # Hardcode
    }

    logger.info(f"User {azure_user_id} authenticated with token")
    print(f"Access Token (first 50 chars): {access_token[:50]}...")  # Debug

    # Skip DB sync for testing - Hardcode data above

    return {"message": "Authenticated successfully", "user_id": user_id}

def refresh_access_token(user_data: dict):
    """Refresh token if expired."""
    result = msal_app.acquire_token_by_refresh_token(user_data['refresh_token'], scopes=SCOPES)
    if "error" in result:
        logger.error(f"Token refresh failed: {result.get('error_description')}")
        raise HTTPException(status_code=401, detail="Token refresh failed")
    user_data['access_token'] = result["access_token"]
    user_data['refresh_token'] = result.get("refresh_token")

# Skip sync_user_data - Data hardcoded in auth

# Signature Template Management (Skipped for testing - Hardcode in send_email)
class TemplateCreate(BaseModel):
    name: str
    html_template: str
    rules: dict

@app.post("/templates")
def create_template(template: TemplateCreate, user_id: str):
    # Skip DB - Just log for now
    logger.info(f"Template created (test): {template.name}")
    return {"message": "Template created (DB skipped for testing)", "template_id": str(uuid.uuid4())}

@app.get("/templates")
def list_templates(user_id: str):
    # Skip DB - Return dummy
    return [{"id": "test", "name": "Test Template", "rules": {"department": "Sales"}}]

# Email Sending Flow
class EmailSend(BaseModel):
    to: str
    subject: str
    body: str

@app.post("/send_email")
def send_email(email: EmailSend, user_id: str):
    """Send email with hardcoded signature (DB skipped)."""
    if user_id not in users:
        raise HTTPException(404, "User not found")

    user_data = users[user_id]
    access_token = user_data['access_token']

    # Hardcode signature template for testing (skip DB query)
    sig_html = f"""
    <p>{user_data['display_name']} | {user_data['job_title'] or 'Test Role'} | {user_data['department']}</p>
    <p>Email: {user_data['email']}</p>
    <hr>
    <p>Best regards,<br>Aqeeq Technologies</p>
    """
    full_body = email.body + "<br><br>" + sig_html

    headers = {
        "Authorization": f"Bearer {access_token}",
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
        logger.info(f"Sending email from {user_data['email']} to {email.to}")
        print(f"Payload: {json.dumps(payload, indent=2)}")  # Debug
        resp = requests.post("https://graph.microsoft.com/v1.0/me/sendMail", headers=headers, json=payload)
        print(f"Response: Status {resp.status_code}, Text: {resp.text}")  # Debug
        resp.raise_for_status()
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
            refresh_access_token(user_data)
            headers["Authorization"] = f"Bearer {user_data['access_token']}"
            resp = requests.post("https://graph.microsoft.com/v1.0/me/sendMail", headers=headers, json=payload)
            print(f"Retry Response: Status {resp.status_code}, Text: {resp.text}")
            resp.raise_for_status()
        else:
            logger.error(f"SendMail error: {e}")
            raise HTTPException(500, str(e))

    logger.info("Email sent successfully (no DB log)")
    return {"message": "Email sent successfully"}

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
