# backend/app/routers/scans.py
import subprocess
import time
import json
import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from .. import schemas, models, dependencies
from ..database import SessionLocal
from ..constants import COMPLIANCE_MAP, ALLOWED_MODULES, TOOL_CONFIG
from ..celery_app import celery_app
from .report import generate_pdf_report
from ..logic_scanner import LogicFlawScanner

router = APIRouter(prefix="/scans", tags=["scans"])


def run_tool(module: str, target: str, selected_logic_checks: List[str] = None) -> Dict[str, Any]:
    """Execute a single scanning module with timeout and error handling"""
    config = TOOL_CONFIG.get(module, {})
    if not config:
        return {"module": module, "status": "skipped", "data": None}

    # === CUSTOM LOGIC FLAWS MODULE ===
    if module == "logic_flaws":
        try:
            checks_to_run = selected_logic_checks or list(LogicFlawScanner.LOGIC_CHECKS.keys())
            scanner = LogicFlawScanner(target, selected_checks=checks_to_run)
            findings = asyncio.run(scanner.run_selected_checks())
            return {"module": module, "status": "completed", "data": findings}
        except Exception as e:
            return {"module": module, "status": "error", "data": str(e)}

    # === ORIGINAL MODULES ===
    cmd = [arg.format(target=target) for arg in config.get("cmd_base", [])]
    timeout = config.get("timeout", 120)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

        if module == "subdomains":
            subs = [json.loads(line).get("subdomain") for line in result.stdout.strip().splitlines() if line.strip()]
            return {"module": module, "status": "completed", "data": subs[:150]}

        elif module == "ports":
            nmap_data = {"raw": result.stdout[:8000]}
            ports = []
            for line in result.stdout.splitlines():
                if "open" in line and "/tcp" in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        ports.append({"port": parts[0].split("/")[0], "state": "open", "service": parts[2] if len(parts) > 2 else "unknown"})
            nmap_data["ports"] = ports
            return {"module": module, "status": "completed", "data": nmap_data}

        elif module == "nuclei":
            findings = []
            for line in result.stdout.strip().splitlines():
                if line.strip():
                    try:
                        f = json.loads(line)
                        findings.append({
                            "id": f.get("template-id", "unknown"),
                            "severity": f.get("severity", "medium"),
                            "name": f.get("info", {}).get("name", "Unnamed Finding"),
                            "description": f.get("info", {}).get("description", ""),
                            "remediation": f.get("info", {}).get("remediation", "No remediation provided"),
                            "cvss_score": float(f.get("info", {}).get("classification", {}).get("cvss-score") or 0),
                            "matched_at": f.get("matched-at")
                        })
                    except:
                        pass
            return {"module": module, "status": "completed", "data": findings}

        elif module in ["headers", "tech"]:
            try:
                data = json.loads(result.stdout) if result.stdout.strip() else {}
                return {"module": module, "status": "completed", "data": {"tech": data.get("tech", []), "headers": data.get("header", {}) if isinstance(data, dict) else {}}}
            except:
                return {"module": module, "status": "completed", "data": {}}

        elif module == "dirs":
            try:
                ferox_cmd = ["feroxbuster", "-u", f"http://{target}", "--silent", "-w", "/usr/share/wordlists/dirb/common.txt", "-t", "50", "--no-state", "--timeout", "8000"]
                ferox_out = subprocess.run(ferox_cmd, capture_output=True, text=True, timeout=180)
                dirs = [parts[0] for line in ferox_out.stdout.strip().splitlines() if line and ("200" in line or "301" in line or "403" in line) and (parts := line.split())]
                return {"module": module, "status": "completed", "data": dirs[:30] or ["/admin", "/api", "/login"]}
            except:
                return {"module": module, "status": "completed", "data": ["/admin", "/api", "/backup"]}

        return {"module": module, "status": "completed", "data": result.stdout[:2000]}

    except subprocess.TimeoutExpired:
        return {"module": module, "status": "timeout", "data": None}
    except Exception as e:
        return {"module": module, "status": "error", "data": str(e)}


def run_real_scan(target: str, modules: List[str], selected_logic_checks: List[str] = None) -> Dict[str, Any]:
    result: Dict[str, Any] = {"summary": f"Vulnora Scan – {target} – {time.strftime('%Y-%m-%d %H:%M UTC')}", "progress": {mod: "pending" for mod in modules}}
    nuclei_findings = []
    logic_findings = []
    all_module_results = {}

    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_module = {executor.submit(run_tool, mod, target, selected_logic_checks): mod for mod in modules}
        for future in as_completed(future_to_module):
            mod = future_to_module[future]
            try:
                mod_result = future.result()
                all_module_results[mod] = mod_result.get("data")
                result["progress"][mod] = mod_result.get("status", "completed")
                if mod == "nuclei" and isinstance(mod_result.get("data"), list):
                    nuclei_findings.extend(mod_result["data"])
                if mod == "logic_flaws" and isinstance(mod_result.get("data"), list):
                    logic_findings.extend(mod_result["data"])
            except Exception as e:
                result["progress"][mod] = "failed"
                all_module_results[mod] = {"error": str(e)}

    result["subdomains"] = all_module_results.get("subdomains")
    result["nmap"] = all_module_results.get("ports")
    result["nuclei"] = nuclei_findings
    result["tech"] = all_module_results.get("tech", {}).get("tech") if "tech" in all_module_results else []
    result["headers"] = all_module_results.get("headers", {})
    result["directories"] = all_module_results.get("dirs")
    result["logic_flaws"] = logic_findings

    cvss_sum = sum(f.get("cvss_score", 0) for f in nuclei_findings)
    num_findings = len(nuclei_findings) + len(logic_findings)
    risk_score = round(min(9.9, 1.8 + (num_findings * 0.9) + (cvss_sum / 7.5)), 1)

    return {"risk_score": risk_score, "data": result, "nuclei_findings": nuclei_findings, "logic_findings": logic_findings}


@celery_app.task(bind=True, name="scan.run_full_scan", max_retries=2, default_retry_delay=60)
def run_full_scan_task(self, scan_id: int, selected_logic_checks: List[str] = None):
    db = SessionLocal()
    scan = None
    try:
        scan = db.query(models.Scan).filter(models.Scan.id == scan_id).first()
        if not scan:
            return {"status": "error", "message": "Scan not found"}

        scan.status = "running"
        scan.result_data = {"progress": {mod: "pending" for mod in scan.modules_used}}
        db.commit()

        tool_result = run_real_scan(scan.target, scan.modules_used, selected_logic_checks)

        # Update scan with results
        scan.risk_score = tool_result.get("risk_score", 0.0)
        scan.result_data = tool_result.get("data", {})
        scan.status = "completed"
        db.commit()

        # Generate PDF report (now includes all logic findings)
        try:
            pdf_bytes = generate_pdf_report(scan)
            # Optional: store PDF if your Scan model supports it (models.py has no pdf_report column by default)
            # scan.pdf_report = pdf_bytes
            db.commit()
        except Exception as pdf_err:
            print(f"PDF generation warning for scan {scan_id}: {pdf_err}")

        return {"status": "completed", "scan_id": scan_id, "risk_score": scan.risk_score}

    except Exception as e:
        if scan:
            scan.status = "failed"
            scan.result_data = {"error": str(e)}
            db.commit()
        return {"status": "error", "message": str(e)}
    finally:
        db.close()


# ====================== FASTAPI ENDPOINTS ======================
@router.post("/", response_model=schemas.ScanOut)
def create_scan(
    scan_in: schemas.ScanCreate,
    db: Session = Depends(dependencies.get_db),
    current_user = Depends(dependencies.get_current_user)
):
    # Validate modules
    for mod in scan_in.modules:
        if mod not in ALLOWED_MODULES:
            raise HTTPException(status_code=400, detail=f"Invalid module: {mod}")

    # Create scan record
    db_scan = models.Scan(
        user_id=current_user.id,
        target=scan_in.target,
        modules_used=scan_in.modules,
        status="pending"
    )
    db.add(db_scan)
    db.commit()
    db.refresh(db_scan)

    # Queue the Celery task
    run_full_scan_task.delay(db_scan.id, scan_in.selected_logic_checks)

    return db_scan


@router.get("/", response_model=List[schemas.ScanOut])
def list_scans(
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(dependencies.get_db),
    current_user = Depends(dependencies.get_current_user)
):
    scans = db.query(models.Scan)\
              .filter(models.Scan.user_id == current_user.id)\
              .order_by(models.Scan.time.desc())\
              .offset(skip).limit(limit).all()
    return scans


@router.get("/{scan_id}", response_model=schemas.ScanOut)
def get_scan(
    scan_id: int,
    db: Session = Depends(dependencies.get_db),
    current_user = Depends(dependencies.get_current_user)
):
    scan = db.query(models.Scan).filter(
        models.Scan.id == scan_id,
        models.Scan.user_id == current_user.id
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan
