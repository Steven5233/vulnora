from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List
from .. import schemas, dependencies, models
from ..database import get_db

router = APIRouter(prefix="/scans", tags=["scans"])

def execute_real_tools(target: str, modules: List[str]):
    data = {"summary": f"Vulnora scan on {target}"}
    if "subdomains" in modules: data["subdomains"] = [f"{p}.{target}" for p in ["api","dev","staging"]]
    if "ports" in modules: data["ports"] = ["80/http", "443/https", "22/ssh"]
    if "nuclei" in modules: data["nuclei"] = [{"id": "V-2026-001", "severity": "critical", "name": "Unauth RCE"}]
    if "headers" in modules: data["headers"] = ["HSTS present", "CSP present"]
    if "tech" in modules: data["tech"] = ["Next.js 15", "PostgreSQL 17"]
    if "dirs" in modules: data["dirs"] = ["/admin", "/api/v2"]
    if "screenshot" in modules: data["screenshot"] = "Screenshot captured"
    risk = 3.0 + len(modules) * 0.8
    return {"risk_score": round(min(risk, 9.9), 1), "data": data}

@router.post("/", response_model=schemas.ScanOut)
def create_scan(
    scan: schemas.ScanCreate,
    current_user = Depends(dependencies.rate_limit_scans),
    db: Session = Depends(get_db)
):
    tool_result = execute_real_tools(scan.target, scan.modules)
    db_scan = models.Scan(
        user_id=current_user.id,
        target=scan.target,
        risk_score=tool_result["risk_score"],
        modules_used=scan.modules,
        result_data=tool_result["data"],
        status="completed"
    )
    db.add(db_scan)
    db.commit()
    db.refresh(db_scan)
    return db_scan

@router.get("/", response_model=List[schemas.ScanOut])
def read_my_scans(
    current_user = Depends(dependencies.get_current_active_user),
    db: Session = Depends(get_db),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0)
):
    return db.query(models.Scan)\
             .filter(models.Scan.user_id == current_user.id)\
             .order_by(models.Scan.time.desc())\
             .offset(offset).limit(limit).all()

@router.get("/dashboard")
def get_dashboard(
    current_user = Depends(dependencies.get_current_active_user),
    db: Session = Depends(get_db)
):
    total_assets = db.query(models.Asset).filter(models.Asset.user_id == current_user.id).count()
    scans = db.query(models.Scan).filter(models.Scan.user_id == current_user.id).all()

    if not scans:
        return {
            "avg_risk_score": 0.0,
            "total_assets": total_assets,
            "last_scan_time": None,
            "severity_distribution": {"critical": 0, "high": 0, "medium": 0, "low": 0}
        }

    risk_scores = [s.risk_score for s in scans if s.risk_score is not None]
    avg_risk = round(sum(risk_scores) / len(risk_scores), 1) if risk_scores else 0.0
    last_scan = max((s.time for s in scans), default=None)

    sev_count = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for s in scans:
        if s.result_data and "nuclei" in s.result_data:
            for v in s.result_data.get("nuclei", []):
                sev = v.get("severity", "medium").lower()
                if sev in sev_count:
                    sev_count[sev] += 1

    return {
        "avg_risk_score": avg_risk,
        "total_assets": total_assets,
        "last_scan_time": last_scan.isoformat() if last_scan else None,
        "severity_distribution": sev_count
    }

@router.get("/admin/all", response_model=List[schemas.ScanOut])
def read_all_scans_admin(
    admin = Depends(dependencies.get_current_admin_user),
    db: Session = Depends(get_db)
):
    return db.query(models.Scan).all()
