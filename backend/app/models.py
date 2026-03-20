from sqlalchemy import Column, Integer, String, Boolean, DateTime, Float, JSON, ForeignKey
from sqlalchemy.sql import func
from .database import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="user")  # "user" or "admin"
    disabled = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class Asset(Base):
    __tablename__ = "assets"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    target = Column(String(255), nullable=False, index=True)
    verified = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class Scan(Base):
    __tablename__ = "scans"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    target = Column(String(255), nullable=False, index=True)
    time = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    risk_score = Column(Float, nullable=True)
    modules_used = Column(JSON, nullable=True, default=list)
    result_data = Column(JSON, nullable=True, default=dict)
    status = Column(String, default="completed")  # pending, running, completed, failed
