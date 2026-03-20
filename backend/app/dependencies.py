from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session
from .database import get_db
from . import schemas, crud
import os
from dotenv import load_dotenv
from collections import defaultdict
import time

load_dotenv()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token")

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, os.getenv("SECRET_KEY"), algorithms=[os.getenv("ALGORITHM")])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = crud.get_user_by_username(db, username=username)
    if user is None:
        raise credentials_exception
    return user

def get_current_active_user(current_user: schemas.UserOut = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

def get_current_admin_user(current_user: schemas.UserOut = Depends(get_current_active_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return current_user

# Simple in-memory rate limiter: max 3 scans / 60 seconds per user
_user_scan_times = defaultdict(list)

def rate_limit_scans(current_user: schemas.UserOut = Depends(get_current_active_user)):
    now = time.time()
    user_id = current_user.id
    _user_scan_times[user_id] = [t for t in _user_scan_times[user_id] if now - t < 60]
    if len(_user_scan_times[user_id]) >= 3:
        raise HTTPException(status_code=429, detail="Rate limit exceeded: max 3 scans per minute")
    _user_scan_times[user_id].append(now)
    return current_user
