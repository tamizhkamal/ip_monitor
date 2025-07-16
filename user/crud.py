import asyncio
from dependencies import get_data_hash
from requests import Session
from fastapi import HTTPException
from user.models import UserIPLog, UserMaster
from user.schemas import UserBase, UserCreate, UserOut
from sqlalchemy.orm import joinedload
import random
import datetime
from passlib.context import CryptContext
from user.models import UserMaster


import os
from fastapi import APIRouter, FastAPI, HTTPException
from fastapi.responses import JSONResponse
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig, MessageType
from pydantic import EmailStr, BaseModel
from typing import List

# Environment variables for security (ideally stored in a secure place, not hard-coded)
MAIL_USERNAME = os.getenv("MAIL_USERNAME", "tamizhkamal6590@gmail.com")
MAIL_PASSWORD = os.getenv("MAIL_PASSWORD", "k.sakthi")
MAIL_FROM = os.getenv("MAIL_FROM", "tamizhkamal6590@gmail.com")
MAIL_SERVER = os.getenv("MAIL_SERVER", "smtp.gmail.com")
MAIL_PORT = int(os.getenv("MAIL_PORT", 587))

conf = ConnectionConfig(
    MAIL_USERNAME="tamizhkamal6590@gmail.com",  # Your Gmail address
    MAIL_PASSWORD="hudg vicz eesn fqlu",  # Your App Password
    MAIL_FROM="tamizhkamal6590@gmail.com",
    MAIL_PORT=587,
    MAIL_SERVER="smtp.gmail.com",
    MAIL_FROM_NAME="kamal",
    MAIL_STARTTLS=True,
    MAIL_SSL_TLS=False,
    USE_CREDENTIALS=True,
    VALIDATE_CERTS=True,
)


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def generate_otp():
    return str(random.randint(100000, 999999))

def otp_expiry_time():
    return datetime.datetime.utcnow() + datetime.timedelta(minutes=5)

def get_data_hash(password: str):
    return pwd_context.hash(password)

async def create_user_data(db: Session, request, userdata: UserBase):
    # ✅ Check if email already exists
    existing_user = db.query(UserMaster).filter(UserMaster.email == userdata.email).first()
    print("Existing User: 11111111111111111111111111111", existing_user)
    if existing_user:
        return {"status": "failed", "message": "Email already exists"}

    # ✅ Confirm password match
    if userdata.password != userdata.confirm_password:
        return {"status": "failed", "message": "Passwords do not match"}

    # ✅ Hash password
    hashed_pwd = get_data_hash(userdata.password)

    # ✅ Create user
    user_obj = UserMaster(
        username=userdata.username,
        first_name=userdata.first_name,
        last_name=userdata.last_name,
        country_code=userdata.country_code,
        country=userdata.country,
        email=userdata.email,
        contact_number=userdata.contact_number,
        hashed_password=hashed_pwd,
        is_admin=False,
        delete=False,
        created_by=1,
        updated_by=1
    )

    db.add(user_obj)
    db.commit()
    db.refresh(user_obj)

    # ✅ Get IP address
    ip = request.headers.get('X-Forwarded-For')
    if ip:
        ip = ip.split(',')[0]
    else:
        ip = request.client.host

    print("User IP Address:", ip)

    # ✅ Store in UserIPLog
    user_ip_log = UserIPLog(
        user_id=user_obj.id,
        ip_address=ip,
        location=None  # 🔄 Optional: You can add location later
    )
    db.add(user_ip_log)
    db.commit()

    # ✅ Send welcome mail
    await send_registration_email(userdata.email, ip)
    return {"status": "success", "user_id": user_obj.id}

async def send_registration_email(to_email: str, ip: str):
    html = f"""
    <h1>Welcome to User 🎉</h1>
    <p>Your sign-up was successful. Thank you for registering!</p>
    <p>Your Sign-Up IP address is: {ip}</p>
    """

    message = MessageSchema(
        subject="🎉 Welcome to User",
        recipients=[to_email],
        body=html,
        subtype=MessageType.html,
    )

    fm = FastMail(conf)
    await fm.send_message(message)

async def send_otp_email(email: str, otp: str):
    html = f"""
    <h2>🛡️ Your OTP Code</h2>
    <p>Use this OTP to verify your login: <strong>{otp}</strong></p>
    <p>This code will expire in 5 minutes.</p>
    """
    message = MessageSchema(
        subject="🛡️ Your OTP Code",
        recipients=[email],
        body=html,
        subtype=MessageType.html,
    )
    fm = FastMail(conf)
    await fm.send_message(message)


def delete_user_data(id: int,db: Session):
    user_details = db.query(UserMaster).filter(UserMaster.id == id).first()
    user_details.delete = True
    db.commit()
    return {"message":'User Deleted succesfully'}
