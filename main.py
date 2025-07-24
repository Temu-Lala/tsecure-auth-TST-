from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from tsecure_auth.core.config import init_auth
from tsecure_auth.routes.auth import create_auth_router

# Configure T-SecureAuth with custom fields
init_auth({})

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Or specify your frontend's URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(create_auth_router(), prefix="/auth", tags=["Authentication"])

@app.get("/")
def root():
    return {"message": "Welcome to the T-SecureAuth demo app!"}
