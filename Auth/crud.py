import secrets
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm,HTTPBearer
from pydantic_models import BaseModel
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from Auth.schemas import UserInDB, TokenData
import user.models as UserModel
from dependencies import SECRET_KEY, ALGORITHM, oauth_2_scheme, pwd_context, get_data_hash, verify_hashdata
from sqlalchemy.orm import Session
# from user import schemas as Userschema
from database import SessionLocal, get_db



def get_user1(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)
    
    
def get_user(db: Session, username: str=None,mobile_no: str=None):
    if username is not None:
        user_exist = db.query(UserModel.UserMaster).filter(UserModel.UserMaster.username == username).first()
        return user_exist
    elif mobile_no is not None:
        user_exist = db.query(UserModel.UserMaster).filter(UserModel.UserMaster.contact_number == mobile_no).first()
        return user_exist
    else:
        return None

def authendicate_user(db, username:str, password: str):
    user = get_user(db, username)
    print("user", user)
    if not user:
        return False
    if not verify_hashdata(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)

    to_encode.update({'exp':expire})
    encoded_jwt_token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    print("Access Token:", encoded_jwt_token)
    return encoded_jwt_token


async def get_current_user(token: str = Depends(oauth_2_scheme),db:Session=Depends(get_db)):
    credential_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                         detail="Could not validate credentials", headers={"WWW-Authenticate":"Bearer"})
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        print("Full payload", payload)
        username: str = payload.get("sub")
        if username is None:
            raise credential_exception
        token_data = TokenData(username = username)
        print("Data", token_data)

    except JWTError:
        raise credential_exception

    user = get_user(db, username=token_data.username)
    if user is None:
        raise credential_exception
    print("user1", user)
    return user

async def get_current_active_user(current_user: UserModel.UserMaster = Depends(get_current_user)):
    # if not current_user.is_active:
    #     raise HTTPException(status_code=400, detail="Inactive user")

    return current_user

# class SessionManager:
#     def __init__(self):
#         self.active_sessions = set()

#     def is_user_logged_in(self, session_id: str) -> bool:
#         return session_id in self.active_sessions

#     def logout_user(self, session_id: str):
#         self.active_sessions.discard(session_id)

# # router = APIRouter()

# # Instantiate the SessionManager
# session_manager = SessionManager()

# def is_user_logged_in(session_id: str = Depends()):
#     if not session_manager.is_user_logged_in(session_id):
#         raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not logged in")
#     return session_id


# async def validate_user(token: str = Depends(HTTPBearer()), db: Session = Depends(get_db)):
#     credential_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
#                                          detail="Could not validate credentials", headers={"WWW-Authenticate": "Bearer"})
#     try:
#         payload = jwt.decode(token.credentials, SECRET_KEY, algorithms=[ALGORITHM])
#         username: str = payload.get("sub")
#         if username is None:
#             raise credential_exception
#         token_data = TokenData(username=username)

#     except JWTError:
#         raise credential_exception

#     user = get_user(db, username=token_data.username)
#     if user is None:
#         raise credential_exception

#     return user