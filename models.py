from sqlalchemy import Column, String, Text, DateTime, ForeignKey, JSON
from sqlalchemy.dialects.postgresql import UUID
from database import Base
import uuid
from datetime import datetime

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

# Optional: AnalyticsEvent model similar to above