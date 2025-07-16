from datetime import datetime, timedelta
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
# from jose import JWTError, jwt
from passlib.context import CryptContext

import secrets

# Generate a random 32-byte (256-bit) secret key
SECRET_KEY = secrets.token_hex(32)
print(SECRET_KEY)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
# SECRET_KEY = "bc27223f96abdf0d562f4f5cb92c20c4795c80e383bfca9191c9efaa23973c22"
ALGORITHM = "HS256"                                               
ACCESS_TOKEN_EXPIRE_MINUTES = 120

oauth_2_scheme = OAuth2PasswordBearer(tokenUrl="/Auth/token")

def verify_hashdata(plain_data, hashed_data):
    confirm = pwd_context.verify(plain_data, hashed_data)
    if confirm:
        print("Password verified successfully!")
    else:
        print("Password verification failed!")
    return confirm



def get_data_hash(data):
    hashed_data = pwd_context.hash(data)
    return hashed_data
