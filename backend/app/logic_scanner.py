# backend/app/logic_scanner.py
import httpx
import asyncio
from typing import Dict, List, Any, Optional
import time

LOGIC_CHECKS = {
    "client_side_trust": {
        "name": "Excessive Trust in Client-Side Controls (Price/Quantity Manipulation)",
        "severity": "high",
        "description": "Checks if price, quantity, or totals can be tampered client-side."
    },
    "idor": {
        "name": "IDOR / Broken Object Level Authorization (BOLA)",
        "severity": "high",
        "description": "Tests sequential ID access without ownership checks."
    },
    "bfla": {
        "name": "Broken Function Level Authorization (Privilege Escalation)",
        "severity": "critical",
        "description": "Checks if admin or high-privilege functions are accessible."
    },
    "workflow_bypass": {
        "name": "Workflow / State Machine Bypass",
        "severity": "high",
        "description": "Tests skipping steps in multi-step processes."
    },
    "race_condition": {
        "name": "Race Conditions (Concurrent Requests)",
        "severity": "high",
        "description": "Tests limit bypass via simultaneous requests (e.g., coupon redemption)."
    },
    "price_manipulation": {
        "name": "Price / Discount / Refund Abuse",
        "severity": "high",
        "description": "Tests negative values, zero, invalid coupons, refund logic."
    }
}

class LogicFlawScanner:
    def __init__(self, target: str, selected_checks: Optional[List[str]] = None):
        self.target = target.rstrip("/")
        self.client = httpx.AsyncClient(timeout=12, follow_redirects=True)
        self.findings = []
        self.selected_checks = selected_checks or list(LOGIC_CHECKS.keys())  # default = all

    async def _request(self, method: str, url: str, json_data=None, params=None):
        try:
            resp = await self.client.request(method, url, json=json_data, params=params)
            return resp
        except:
            return None

    def _add_finding(self, check_key: str, poc: Dict):
        check = LOGIC_CHECKS[check_key]
        self.findings.append({
            "flaw_type": check_key,
            "name": check["name"],
            "severity": check["severity"],
            "description": check["description"],
            "poc": poc,
            "timestamp": time.time()
        })

    # Individual check methods
    async def check_client_side_trust(self):
        payloads = [
            {"price": 0.01, "quantity": 9999},
            {"total": 1.0},
            {"amount": -50}
        ]
        for payload in payloads:
            for path in ["/checkout", "/api/order", "/cart/update"]:
                resp = await self._request("POST", f"{self.target}{path}", json_data=payload)
                if resp and resp.status_code in (200, 201, 202):
                    self._add_finding("client_side_trust", {"url": str(resp.url), "payload": payload, "status": resp.status_code})

    async def check_idor(self):
        for i in range(1, 30):
            for base in ["/user/", "/order/", "/profile/", "/api/resource/"]:
                url = f"{self.target}{base}{i}"
                resp = await self._request("GET", url)
                if resp and resp.status_code == 200 and len(resp.text) > 50:  # rough success check
                    self._add_finding("idor", {"url": url, "id": i})

    async def check_bfla(self):
        for path in ["/admin", "/api/admin", "/dashboard/admin", "/api/v1/admin"]:
            resp = await self._request("GET", f"{self.target}{path}")
            if resp and resp.status_code in (200, 301, 302):
                self._add_finding("bfla", {"url": str(resp.url), "status": resp.status_code})

    async def check_workflow_bypass(self):
        # Simple multi-step simulation
        steps = [
            (f"{self.target}/api/cart/add", {"item_id": 1}),
            (f"{self.target}/api/checkout/complete", {"payment_method": "free"})
        ]
        for url, payload in steps:
            resp = await self._request("POST", url, json_data=payload)
            if resp and resp.status_code in (200, 201):
                self._add_finding("workflow_bypass", {"url": url, "payload": payload})

    async def check_race_condition(self):
        async def race():
            tasks = [self._request("POST", f"{self.target}/api/redeem", json_data={"code": "TEST123"}) for _ in range(4)]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            success_count = sum(1 for r in results if r and getattr(r, "status_code", 0) in (200, 201))
            if success_count > 1:
                self._add_finding("race_condition", {"attempts": 4, "successes": success_count})
        await race()

    async def check_price_manipulation(self):
        payloads = [
            {"price": -100, "coupon": "INVALID"},
            {"quantity": 0},
            {"refund_amount": 9999},
            {"discount": 1000}
        ]
        for payload in payloads:
            for path in ["/api/order", "/checkout", "/api/payment"]:
                resp = await self._request("POST", f"{self.target}{path}", json_data=payload)
                if resp and resp.status_code in (200, 201):
                    self._add_finding("price_manipulation", {"url": str(resp.url), "payload": payload})

    async def run_selected_checks(self) -> List[Dict]:
        tasks = []
        if "client_side_trust" in self.selected_checks:
            tasks.append(self.check_client_side_trust())
        if "idor" in self.selected_checks:
            tasks.append(self.check_idor())
        if "bfla" in self.selected_checks:
            tasks.append(self.check_bfla())
        if "workflow_bypass" in self.selected_checks:
            tasks.append(self.check_workflow_bypass())
        if "race_condition" in self.selected_checks:
            tasks.append(self.check_race_condition())
        if "price_manipulation" in self.selected_checks:
            tasks.append(self.check_price_manipulation())

        if tasks:
            await asyncio.gather(*tasks)
        return self.findings
