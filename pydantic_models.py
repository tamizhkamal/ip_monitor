from pydantic import BaseModel
from datetime import datetime

class UserMasterPydantic(BaseModel):
    id: int
    username: str
    email: str
    contact_number: str
    hashed_password: str
    access_token: str
    token_type: str
    otp: str
    image: str
    is_admin: bool
    delete: bool
    created_at: datetime
    updated_at: datetime
    created_by: int
    updated_by: int