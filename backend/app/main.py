import uvicorn
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from .database import engine, Base
from .celery_app import run_logic_scan
from .routers import assets, scans, auth, zap   # ← added zap

@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield

app = FastAPI(title="Vulnora", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/auth", tags=["auth"])
app.include_router(assets.router, prefix="/assets", tags=["assets"])
app.include_router(scans.router, prefix="/scans", tags=["scans"])
app.include_router(zap.router)   

@app.post("/scan/logic", status_code=status.HTTP_202_ACCEPTED)
async def trigger_logic_scan(request: dict):
    if not request.get("asset_id"):
        raise HTTPException(status_code=400, detail="asset_id is required")
    task = run_logic_scan.delay(
        asset_id=request["asset_id"],
        selected_checks=request.get("selected_checks")
    )
    return {
        "task_id": task.id,
        "message": "Advanced IDORForge Pro v2 logic scan started"
    }

@app.get("/")
async def root():
    return {"message": "Vulnora API is running"}

@app.get("/health")
async def health():
    return {"status": "healthy"}

if __name__ == "__main__":
    uvicorn.run("backend.app.main:app", host="0.0.0.0", port=8000, reload=True)
