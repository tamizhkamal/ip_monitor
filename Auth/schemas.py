
from typing import Optional
from pydantic_models import BaseModel

class Token(BaseModel):
    access_token: str
    token_type: str
    user_id: str
    user_name: str


class TokenData(BaseModel):
    username: Optional[str] = None
    contact: Optional[str] = None
    email: Optional[str] = None


class UserInDB(BaseModel):
    hashed_password: str

class ResetPassword(BaseModel):
    password: str
    confirm_password: str
    
class Users(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None
    
class User(BaseModel):
    email: str
    name: str
    picture: str
    given_name: str
    family_name: str

class OTPVerifySchema(BaseModel):
    username: str
    otp: str