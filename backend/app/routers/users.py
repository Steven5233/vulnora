from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from .. import schemas, dependencies
from ..database import get_db

router = APIRouter(prefix="/users", tags=["users"])

@router.get("/me", response_model=schemas.UserOut)
def read_users_me(current_user: schemas.UserOut = Depends(dependencies.get_current_active_user)):
    return current_user
