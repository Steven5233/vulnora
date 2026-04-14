# backend/app/routers/zap.py
import httpx
import json
from typing import Dict, Any, Optional
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session

from .. import dependencies
from ..database import SessionLocal

router = APIRouter(prefix="/zap", tags=["zap"])

ZAP_BASE = "http://zap:8080"
PROXY_PORT = 8090

async def call_zap(endpoint: str, method: str = "GET", params: Optional[Dict] = None, json_data: Optional[Dict] = None):
    url = f"{ZAP_BASE}{endpoint}"
    async with httpx.AsyncClient(timeout=30) as client:
        if method.upper() == "POST":
            resp = await client.post(url, params=params, json=json_data)
        else:
            resp = await client.get(url, params=params)
        if resp.status_code != 200:
            raise HTTPException(status_code=500, detail=f"ZAP API error: {resp.text}")
        return resp.json()

@router.get("/status")
async def zap_status():
    """Check if ZAP is running and proxy is ready"""
    try:
        data = await call_zap("/JSON/core/view/version/")
        return {
            "status": "running",
            "version": data.get("version"),
            "proxy_url": f"http://localhost:{PROXY_PORT}",
            "api_url": "http://localhost:8080"
        }
    except Exception as e:
        raise HTTPException(status_code=503, detail=str(e))

@router.post("/context/create")
async def create_context(context_name: str = "Vulnora_Default"):
    """Create a new ZAP context for isolation"""
    await call_zap("/JSON/context/action/newContext/", params={"contextName": context_name})
    return {"status": "success", "context": context_name}

@router.get("/sites")
async def get_sites():
    """Get discovered sites (Sites Tree)"""
    data = await call_zap("/JSON/core/view/sites/")
    return data.get("sites", [])

@router.get("/history")
async def get_history(baseurl: Optional[str] = None, start: int = 0, count: int = 100):
    """Get HTTP history (Proxy tab equivalent)"""
    params = {"start": start, "count": count}
    if baseurl:
        params["baseurl"] = baseurl
    data = await call_zap("/JSON/core/view/history/", params=params)
    return data.get("history", [])

@router.post("/repeater/send")
async def send_repeater_request(request_data: Dict[str, Any]):
    """
    Repeater: Send custom/modified request
    Expected body:
    {
      "request": "GET /api/test HTTP/1.1\r\nHost: example.com\r\n...",
      "followRedirects": true
    }
    """
    try:
        result = await call_zap(
            "/JSON/core/action/sendRequest/",
            params={"request": request_data.get("request"), "followRedirects": str(request_data.get("followRedirects", True)).lower()}
        )
        return {"status": "sent", "response": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/cookie/set")
async def set_cookie(name: str, value: str, domain: str):
    """Set cookie for authenticated sessions"""
    await call_zap("/JSON/core/action/addSessionCookie/", params={"name": name, "value": value, "domain": domain})
    return {"status": "cookie set"}

@router.post("/jwt/set")
async def set_jwt(jwt_token: str):
    """Add JWT to session (via replacer or header)"""
    # Simple way: use replacer rule for Authorization header
    await call_zap("/JSON/replacer/action/addRule/", params={
        "description": "JWT Auth",
        "enabled": "true",
        "matchType": "REQ_HEADER",
        "matchString": "Authorization",
        "replacement": f"Bearer {jwt_token}"
    })
    return {"status": "JWT rule added"}

@router.get("/breakpoints")
async def get_breakpoints():
    data = await call_zap("/JSON/break/view/httpMessage/")
    return data

@router.post("/break/set")
async def set_breakpoint(state: str = "on", scope: str = "http-all"):
    """Turn breakpoint on/off"""
    await call_zap("/JSON/break/action/break/", params={"type": scope, "state": state})
    return {"status": f"Breakpoint set to {state}"}
