from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
# from sqlalchemy.ext.declarative import declarative_base

from sqlalchemy.orm import declarative_base



PROJECT_NAME:str = "ip_moniter"
PROJECT_VERSION: str = "1.0.0"
POSTGRES_USER = "postgres"
POSTGRES_PASSWORD = "1234"
POSTGRES_SERVER = "localhost"
POSTGRES_PORT = 5432
POSTGRES_DB = "ip_monitor_db"
   
DATABASE_URL = f"postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_SERVER}:{POSTGRES_PORT}/{POSTGRES_DB}"


engine = create_engine(DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()