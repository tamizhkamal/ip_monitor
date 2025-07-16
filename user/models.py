# models.py
import datetime
from sqlalchemy import JSON, Boolean, Column, DateTime, Integer, String, Date, Time, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.orm import declarative_base

Base = declarative_base()

from sqlalchemy.orm import relationship

class UserMaster(Base):
    __tablename__ = "user_master"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(length=50))
    first_name = Column(String(length=100))
    last_name = Column(String(length=100))
    country_code = Column(String(length=10))
    country = Column(String(length=100))
    email = Column(String(length=255), unique=True, index=True)
    contact_number = Column(String(length=20), unique=True, index=True)
    hashed_password = Column(String)
    access_token = Column(String)
    token_type = Column(String)
    otp = Column(String)
    image = Column(String)
    is_admin = Column(Boolean)
    delete = Column(Boolean)
    otp = Column(String(length=6))
    otp_created_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow)
    created_by = Column(Integer, index=True)
    updated_by = Column(Integer, index=True)
    ip_logs = relationship("UserIPLog", back_populates="user")

class UserIPLog(Base):
    __tablename__ = "user_ip_log"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("user_master.id"))
    ip_address = Column(String)
    location = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    user = relationship("UserMaster", back_populates="ip_logs")

