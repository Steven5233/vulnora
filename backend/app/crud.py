from sqlalchemy.orm import Session
from . import models, schemas
from .auth import get_password_hash, verify_password

def get_user_by_username(db: Session, username: str):
    return db.query(models.User).filter(models.User.username == username).first()

def get_user_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()

def create_user(db: Session, user: schemas.UserCreate):
    hashed_password = get_password_hash(user.password)
    db_user = models.User(
        username=user.username,
        email=user.email,
        hashed_password=hashed_password
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def authenticate_user(db: Session, username: str, password: str):
    user = get_user_by_username(db, username)
    if not user or not verify_password(password, user.hashed_password):
        return False
    return user

# ─── Asset CRUD ────────────────────────────────────────────────

def create_asset(db: Session, asset: schemas.AssetCreate, user_id: int):
    db_asset = models.Asset(user_id=user_id, target=asset.target)
    db.add(db_asset)
    db.commit()
    db.refresh(db_asset)
    return db_asset

def get_assets_by_user(db: Session, user_id: int):
    return db.query(models.Asset).filter(models.Asset.user_id == user_id).all()

def get_asset_by_target(db: Session, target: str, user_id: int):
    return db.query(models.Asset).filter(
        models.Asset.target == target,
        models.Asset.user_id == user_id
    ).first()

def delete_asset(db: Session, asset_id: int, user_id: int):
    asset = db.query(models.Asset).filter(
        models.Asset.id == asset_id,
        models.Asset.user_id == user_id
    ).first()
    if asset:
        db.delete(asset)
        db.commit()
        return True
    return False
