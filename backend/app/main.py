from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .database import engine, Base
from .routers import auth, users, scans, assets, zap
from .celery_app import celery_app

import subprocess

app = FastAPI(
    title="Vulnora API",
    description="Vulnora – Built by Cybersecurity Researcher"
)

@app.on_event("startup")
async def startup_event():
    try:
        subprocess.run(["nuclei", "-update-templates"], timeout=60, capture_output=True)
        print("Nuclei templates updated successfully")
    except:
        pass

Base.metadata.create_all(bind=engine)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8501"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)

app.include_router(auth.router)
app.include_router(users.router)
app.include_router(scans.router)
app.include_router(assets.router)
app.include_router(zap.router)

@app.get("/")
def root():
    return {"message": "Vulnora Backend – Built by Cybersecurity Researcher"}
