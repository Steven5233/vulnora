# backend/app/schemas.py
from pydantic import BaseModel, EmailStr
from typing import List, Optional, Dict
from datetime import datetime

class UserBase(BaseModel):
    username: str
    email: EmailStr

class UserCreate(UserBase):
    password: str

class UserOut(UserBase):
    id: int
    role: str
    disabled: bool
    created_at: datetime

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

class AssetBase(BaseModel):
    target: str

class AssetCreate(AssetBase):
    pass

class AssetOut(AssetBase):
    id: int
    user_id: int
    verified: bool
    created_at: datetime

    class Config:
        from_attributes = True

# Available logic flaw checks (updated with all new ones)
LOGIC_CHECK_OPTIONS = [
    "client_side_trust",
    "idor",
    "bfla",
    "workflow_bypass",
    "race_condition",
    "price_manipulation",
    "multi_account_manipulation",
    "mass_assignment",
    "http_parameter_pollution",
    "forced_state_transition",
    "coupon_stacking",
    "balance_manipulation"
]

class ScanCreate(BaseModel):
    target: str
    modules: List[str] = [
        "subdomains", "ports", "nuclei", "headers", "tech", 
        "dirs", "screenshot", "logic_flaws"
    ]
    selected_logic_checks: Optional[List[str]] = None

class ScanOut(BaseModel):
    id: int
    user_id: int
    target: str
    time: datetime
    risk_score: Optional[float] = None
    modules_used: List[str]
    result_data: Dict
    status: str
