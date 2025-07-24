import datetime
from sqlalchemy import Column, Integer, String, DateTime, JSON
from ..services.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    hashed_password = Column(String, nullable=False)
    
    # This JSON field will store all other user attributes,
    # making the model flexible for custom fields.
    attributes = Column(JSON)

class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String, index=True) # e.g., "login_success", "login_fail"
    user_id = Column(Integer, index=True, nullable=True)
    ip_address = Column(String)
    user_agent = Column(String)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    details = Column(String, nullable=True)
