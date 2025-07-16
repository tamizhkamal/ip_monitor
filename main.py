from fastapi import APIRouter, FastAPI
from starlette.middleware.cors import CORSMiddleware
from database import get_db,engine
from user import models as user_models
from user.main import router as user_router
import uvicorn
from Auth.main import router as auth_router
import stripe

app = FastAPI()

origins = ['*']

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


user_models.Base.metadata.create_all(engine)

app.include_router(auth_router)
app.include_router(user_router)



if __name__=="__main__":
    uvicorn.run(app)