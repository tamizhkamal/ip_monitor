from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, DateTime
from sqlalchemy import Boolean, Column, Integer, String,DateTime
import datetime
from database import *
# from ..database import *


class UserToken(Base):
    __tablename__ = "user_token"
    token_id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True)
    email = Column(String, unique=True)
    access_token = Column(String, unique=True)
    token_type = Column(String)
    hashed_password = Column(String)
    otp = Column(String)
    created_at = Column(DateTime,default=datetime.datetime.utcnow)
    updated_at = Column(DateTime,default=datetime.datetime.utcnow)
    created_by = Column(Integer)
    updated_by = Column(Integer)