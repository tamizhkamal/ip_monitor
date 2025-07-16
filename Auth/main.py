from starlette.responses import JSONResponse
from Auth.crud import *
from dependencies import ACCESS_TOKEN_EXPIRE_MINUTES
from user import schemas as Userschema
from fastapi import Depends,APIRouter,HTTPException,status
from Auth.schemas import OTPVerifySchema, Token,ResetPassword, Users
from database import get_db
import datetime
from sqlalchemy.orm import Session
import random
# from app.Users import crud
# from datetime import datetime, timedelta
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
# from google.auth.transport import requests
# from google.oauth2 import id_token
from fastapi import HTTPException
from user import *
from user.crud import create_user_data, send_otp_email
from user.models import UserIPLog, UserMaster
from fastapi import Request
from .ip_utils import get_ip_location
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# router = APIRouter(tags=['Auth'])
router = APIRouter(
# router = APIRouter(tags=['Auth'])
    prefix="/Auth",
)

def generate_otp():
    return "".join([str(random.randint(0, 9)) for i in range(6)])

def failure_message(message):
    return JSONResponse({"status": "failed", "message": message},
                        status_code=401)

# import requests

# def get_location_from_ip(ip):
#     response = requests.get(f"https://ipinfo.io/{ip}/json")
#     data = response.json()
#     return data.get("city"), data.get("region"), data.get("country")




@router.post("/login", response_model=Token, tags=["Authentication"])
async def login(request: Request):
    ip = request.headers.get('X-Forwarded-For')
    if ip:
        ip = ip.split(',')[0]
    else:
        ip = request.client.host

    print("User IP Address:", ip)

    # Dummy token response for testing
    return {
        "access_token": "test123token",
        "token_type": "bearer",
        "user_id": "U001",
        "user_name": f"Login from {ip}"
    }


@router.post("/token", tags=["Authentication"])
async def login_for_access_token(
    request: Request,
    from_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    print(from_data, "<--------------------------- from_data")

    user = authendicate_user(db, from_data.username, from_data.password)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # ✅ Step 1: Get client IP
    client_ip = request.client.host
    print(f"🔍 Login attempt from IP: {client_ip}")

    # ✅ Step 2: Fetch known IPs
    previous_ips = db.query(UserIPLog).filter(UserIPLog.user_id == user.id).all()
    known_ips = [ip.ip_address for ip in previous_ips]

    is_new_ip = client_ip not in known_ips

    # ✅ Step 3: Log IP if new
    if is_new_ip:
        print("🚨 New IP detected:", client_ip)

        # Save IP log
        location = get_ip_location(client_ip)  # Optional location
        new_log = UserIPLog(user_id=user.id, ip_address=client_ip, location=location)
        db.add(new_log)

        # ❗ Threshold check (optional)
        if len(set(known_ips)) >= 5:
            return JSONResponse({
                "status": "failed",
                "message": "Too many IP address changes. Account temporarily locked."
            }, status_code=403)

        # ✅ Step 4: Generate and email OTP
        otp = generate_otp()
        user.otp = otp
        user.otp_created_at = datetime.datetime.utcnow()
        db.commit()

        await send_otp_email(user.email, otp)

        return {
            "status": "2fa_required",
            "message": "OTP sent to your email",
            "username": user.username
        }

    # ✅ Step 5: If known IP → create access token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username},
        expires_delta=access_token_expires
    )

    db.query(UserMaster).filter(UserMaster.username == from_data.username).update(
        {
            UserMaster.access_token: access_token,
            UserMaster.token_type: "bearer",
            UserMaster.updated_at: datetime.datetime.now()
        }
    )
    db.commit()

    user_ = db.query(UserMaster).filter(UserMaster.id == user.id).first()

    return Token(
        access_token=access_token,
        token_type="bearer",
        user_id=user_.username,
        user_name=str(user_.id),
    )


@router.post("/verify-otp", tags=["Authentication"])
def verify_otp(data: OTPVerifySchema, db: Session = Depends(get_db)):
    user = db.query(UserMaster).filter(UserMaster.username == data.username).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    now = datetime.datetime.utcnow()

    if not user.otp or user.otp != data.otp:
        return {"status": "failed", "message": "Invalid OTP"}

    if (now - user.otp_created_at).total_seconds() > 300:
        return {"status": "failed", "message": "OTP expired"}

    # ✅ OTP valid → generate token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username},
        expires_delta=access_token_expires
    )

    # Clear OTP after successful verification
    user.access_token = access_token
    user.token_type = "bearer"
    user.updated_at = datetime.datetime.utcnow()
    user.otp = None
    db.commit()

    return Token(
        access_token=access_token,
        token_type="bearer",
        user_id=user.username,
        user_name=str(user.id),
    )



@router.post("/reset_password", tags=["Authentication"])
async def reset_password(request: ResetPassword,user = Depends(get_current_active_user), db: Session = Depends(get_db)):
    if request.password != request.confirm_password:
        return failure_message("Passwords do not match")
    if user is None:
        return failure_message("User authentication failed")
    db.query(UserMaster).filter(UserMaster.username == user.username).update({
        UserMaster.hashed_password: get_data_hash(request.password)
    })
    try:
        db.commit()
    except:
        db.rollback()
    return {"status": "success", "message": "Password changed successfully"}