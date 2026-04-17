import asyncio
import json
import os
from typing import List, Optional

from celery import Celery

from .database import SessionLocal
from .crud import get_asset_by_id, save_scan_findings
from .logic_scanner import LogicFlawScanner

redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")

celery = Celery(
    "vulnora",
    broker=redis_url,
    backend=redis_url,
)

celery.conf.update(
    task_track_started=True,
    task_time_limit=900,
    task_soft_time_limit=720,
    worker_prefetch_multiplier=1,
)

@celery.task(name="run_logic_scan", bind=True, max_retries=2)
def run_logic_scan(self, asset_id: int, selected_checks: Optional[List[str]] = None):
    db = SessionLocal()
    scanner = None

    try:
        asset = get_asset_by_id(db, asset_id)
        if not asset or not asset.target_url:
            return {"status": "failed", "error": "Asset not found or target_url is missing"}

        auth_cookies = {}
        if hasattr(asset, "auth_cookies") and asset.auth_cookies:
            try:
                auth_cookies = json.loads(asset.auth_cookies)
            except (json.JSONDecodeError, TypeError):
                auth_cookies = {}

        auth_jwt = getattr(asset, "auth_jwt", None)

        scanner = LogicFlawScanner(
            target=asset.target_url,
            selected_checks=selected_checks,
            auth_cookies=auth_cookies,
            auth_jwt=auth_jwt,
            aggression="medium"
        )

        findings = asyncio.run(scanner.run_all())

        save_scan_findings(db, asset_id, scan_type="logic", findings=findings)

        return {
            "status": "completed",
            "asset_id": asset_id,
            "findings_count": len(findings),
            "message": "Advanced IDORForge Pro v2 scan finished successfully"
        }

    except Exception as e:
        if not str(e).startswith("Asset"):
            self.retry(countdown=60, exc=e)

        return {
            "status": "failed",
            "asset_id": asset_id,
            "error": str(e)
        }

    finally:
        db.close()
        if scanner:
            try:
                asyncio.run(scanner.close())
            except Exception:
                pass
