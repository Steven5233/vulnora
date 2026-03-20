from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .database import engine, Base
from .routers import auth, users, scans, assets

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Vulnora API",
    description="Vulnora – Built by Cybersecurity Researcher"
)

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

@app.get("/")
def root():
    return {"message": "Vulnora Backend – Built by Cybersecurity Researcher"}
