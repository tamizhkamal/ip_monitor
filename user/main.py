
from fastapi import APIRouter, Depends, File
# from sqlalchemy import func
from sqlalchemy.orm import Session
# from Auth.crud import get_current_active_user
from database import get_db
from user.crud import create_user_data, delete_user_data, send_registration_email
from user.models import UserMaster
from user.schemas import  UserBase, UserCreate, UserOut, UserResponse
from datetime import datetime
from datetime import datetime
import base64
from concurrent.futures import ThreadPoolExecutor
from user import schemas as Userschema
from fastapi import Request


router = APIRouter(tags=['User'])  

@router.post("/AddUser", tags=["User"])
async def AddUser(userdata: Userschema.UserBase,request: Request, db: Session = Depends(get_db)):
    final_dict = await create_user_data(db,request, userdata)
    print("result", final_dict)
    return final_dict

@router.post("/test_mail", tags=["User"])
async def test_mail(userdata: Userschema.TestEmailSchema, db: Session = Depends(get_db)):
    await send_registration_email(userdata.email)
    return {"status": "success", "message": "Email sent successfully"}


@router.get("/all_user_data", response_model=UserResponse, tags=['User'])
async def all_user_data(db: Session = Depends(get_db)):
    users = db.query(UserMaster).all()

    user_data = [
        UserOut(
            username=user.username,
            first_name=user.first_name,
            last_name=user.last_name,
            country_code=user.country_code,
            country=user.country,
            email=user.email,
            contact_number=user.contact_number,
            is_admin=user.is_admin,
        )
        for user in users
    ]

    return UserResponse(data=user_data)

