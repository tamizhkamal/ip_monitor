from typing import List, Optional
from fastapi import UploadFile
from pydantic import BaseModel, ConfigDict, EmailStr, Field

class UserCreate(BaseModel):
    username: str
    first_name: str
    last_name: str
    country_code: str
    country: str
    email: EmailStr
    contact_number: str
    password: str
    confirm_password: str
    agree_terms: bool = Field(..., description="Must be accepted")

    model_config = ConfigDict(from_attributes=True)

class UserBase(UserCreate):
    hashed_password: Optional[str] = None  # Optional for now (to be hashed in backend)
    
class UserResponse(BaseModel):
    data: List[UserBase]


class UserOut(BaseModel):
    username: str
    first_name: str
    last_name: str
    country_code: str
    country: str
    email: EmailStr
    contact_number: str
    is_admin: Optional[bool] = None

    class Config:
        orm_mode = True


class UserResponse(BaseModel):
    data: List[UserOut]

class TestEmailSchema(BaseModel):
    email: List[EmailStr]