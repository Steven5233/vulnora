from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from .. import schemas, crud, dependencies
from ..database import get_db

router = APIRouter(prefix="/assets", tags=["assets"])

@router.post("/", response_model=schemas.AssetOut)
def create_asset(
    asset: schemas.AssetCreate,
    current_user = Depends(dependencies.get_current_active_user),
    db: Session = Depends(get_db)
):
    if crud.get_asset_by_target(db, asset.target, current_user.id):
        raise HTTPException(status_code=400, detail="Asset already exists for this user")
    return crud.create_asset(db, asset, current_user.id)

@router.get("/", response_model=List[schemas.AssetOut])
def read_assets(
    current_user = Depends(dependencies.get_current_active_user),
    db: Session = Depends(get_db)
):
    return crud.get_assets_by_user(db, current_user.id)

@router.delete("/{asset_id}", status_code=204)
def delete_asset(
    asset_id: int,
    current_user = Depends(dependencies.get_current_active_user),
    db: Session = Depends(get_db)
):
    if not crud.delete_asset(db, asset_id, current_user.id):
        raise HTTPException(status_code=404, detail="Asset not found or not owned by you")
