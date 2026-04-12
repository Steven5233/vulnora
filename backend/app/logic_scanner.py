# backend/app/logic_scanner.py
import httpx
import asyncio
from typing import Dict, List, Any
import time
import json
from concurrent.futures import ThreadPoolExecutor

class LogicFlawScanner:
    def __init__(self, target: str):
        self.target = target.rstrip("/")
        self.client = httpx.AsyncClient(timeout=10, follow_redirects=True)
        self.findings = []
        self.endpoints = []  # populated from feroxbuster or nuclei results if available

    async def _request(self, method: str, url: str, data=None, params=None, headers=None):
        try:
            resp = await self.client.request(method, url, json=data, params=params, headers=headers)
            return resp
        except Exception:
            return None

    def _add_finding(self, flaw_type: str, severity: str, description: str, poc: Dict):
        self.findings.append({
            "flaw_type": flaw_type,
            "severity": severity,
            "description": description,
            "poc": poc,
            "timestamp": time.time()
        })

    # 1. Excessive Trust in Client-Side Controls
    async def check_client_side_trust(self):
        urls = [f"{self.target}/checkout", f"{self.target}/cart", f"{self.target}/api/order"]
        for url in urls:
            resp = await self._request("POST", url, json={"price": 0.01, "quantity": 9999})
            if resp and resp.status_code in (200, 201):
                self._add_finding("client_side_trust", "high", "Price/quantity tampered successfully", {"url": str(resp.url), "payload": {"price": 0.01}})

    # 2. IDOR / BOLA
    async def check_idor(self):
        for i in range(1, 50):
            for endpoint in ["/user/", "/order/", "/profile/", "/api/v1/resource/"]:
                url = f"{self.target}{endpoint}{i}"
                resp = await self._request("GET", url)
                if resp and resp.status_code == 200 and "unauthorized" not in resp.text.lower():
                    self._add_finding("idor", "high", f"IDOR possible on {endpoint}{i}", {"url": url})

    # 3. BFLA / Privilege Escalation
    async def check_bfla(self):
        urls = [f"{self.target}/admin", f"{self.target}/api/admin", f"{self.target}/dashboard"]
        for url in urls:
            resp = await self._request("GET", url)
            if resp and resp.status_code == 200:
                self._add_finding("bfla", "critical", "Admin function accessible without auth", {"url": url})

    # 4. Workflow / State Machine Bypass
    async def check_workflow_bypass(self):
        # Example: skip steps in checkout
        steps = [
            (f"{self.target}/api/cart/add", {"item": "test"}),
            (f"{self.target}/api/checkout", {"payment": "free"}),
        ]
        for url, payload in steps:
            resp = await self._request("POST", url, json=payload)
            if resp and resp.status_code in (200, 201):
                self._add_finding("workflow_bypass", "high", "Workflow step skipped", {"url": url, "payload": payload})

    # 5-18. All other common flaws (price, discount, race, refund, etc.) – batched
    async def check_all_remaining(self):
        # Race condition example (concurrent requests)
        async def race_test():
            tasks = [self._request("POST", f"{self.target}/api/redeem", json={"code": "TESTCOUPON"}) for _ in range(5)]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            if any(r and getattr(r, "status_code", 0) == 200 for r in results):
                self._add_finding("race_condition", "high", "Race condition on coupon redemption", {"requests": 5})
        await race_test()

        # Price / discount / refund abuse patterns
        test_payloads = [
            {"price": -100, "coupon": "INVALID"},
            {"quantity": 0},
            {"refund": True, "reason": "test"},
        ]
        for payload in test_payloads:
            resp = await self._request("POST", f"{self.target}/api/order", json=payload)
            if resp and resp.status_code in (200, 201):
                self._add_finding("price_manipulation", "high", "Business logic tampered", {"payload": payload})

    async def run_all_checks(self) -> List[Dict]:
        await asyncio.gather(
            self.check_client_side_trust(),
            self.check_idor(),
            self.check_bfla(),
            self.check_workflow_bypass(),
            self.check_all_remaining(),
        )
        return self.findings
