# backend/app/logic_scanner.py
import httpx
import asyncio
from typing import Dict, List, Any, Optional
import time
import random
import string

class LogicFlawScanner:
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
            "description": "Tests limit bypass via simultaneous requests."
        },
        "price_manipulation": {
            "name": "Price / Discount / Refund Abuse",
            "severity": "high",
            "description": "Tests negative values, zero, invalid coupons, refund logic."
        },
        # === NEW CHECK ===
        "multi_account_manipulation": {
            "name": "Multi-Account Broken Authorization (Cross-User IDOR/BOLA via Cookie/Session)",
            "severity": "critical",
            "description": "Creates 3 accounts (A, B, C). Uses Account A session/cookie to manipulate/view/delete data of Account B/C by combining A’s auth with B/C user IDs."
        }
    }

    def __init__(self, target: str, selected_checks: Optional[List[str]] = None):
        self.target = target.rstrip("/")
        self.client = httpx.AsyncClient(timeout=15, follow_redirects=True)
        self.findings = []
        self.selected_checks = selected_checks or list(self.LOGIC_CHECKS.keys())
        self.accounts = {}  # Will store {"A": {"id": , "cookie": , "session": }, ...}

    async def _request(self, method: str, url: str, json_data=None, cookies=None, headers=None):
        try:
            resp = await self.client.request(
                method, url, json=json_data, cookies=cookies, headers=headers
            )
            return resp
        except Exception:
            return None

    def _add_finding(self, check_key: str, poc: Dict):
        check = self.LOGIC_CHECKS[check_key]
        self.findings.append({
            "flaw_type": check_key,
            "name": check["name"],
            "severity": check["severity"],
            "description": check["description"],
            "poc": poc,
            "timestamp": time.time()
        })

    # ====================== EXISTING CHECKS (unchanged) ======================
    async def check_client_side_trust(self): ...  # (keep original)
    async def check_idor(self): ...               # (keep original)
    async def check_bfla(self): ...               # (keep original)
    async def check_workflow_bypass(self): ...    # (keep original)
    async def check_race_condition(self): ...     # (keep original)
    async def check_price_manipulation(self): ... # (keep original)

    # ====================== NEW MULTI-ACCOUNT CHECK ======================
    async def register_account(self, username: str, email: str, password: str):
        payload = {"username": username, "email": email, "password": password}
        for path in ["/register", "/api/register", "/signup", "/api/auth/register"]:
            resp = await self._request("POST", f"{self.target}{path}", json_data=payload)
            if resp and resp.status_code in (200, 201):
                return resp
        return None

    async def login_account(self, username: str, password: str):
        payload = {"username": username, "password": password}
        for path in ["/login", "/api/login", "/auth/login", "/api/auth/login"]:
            resp = await self._request("POST", f"{self.target}{path}", json_data=payload)
            if resp and resp.status_code in (200, 201, 302):
                return resp.cookies, resp.headers.get("set-cookie"), resp.json() if resp.content else {}
        return None, None, {}

    async def get_user_id(self, cookies):
        """Try to fetch current user profile to extract own user ID"""
        for path in ["/api/me", "/api/user/profile", "/profile", "/api/profile"]:
            resp = await self._request("GET", f"{self.target}{path}", cookies=cookies)
            if resp and resp.status_code == 200:
                try:
                    data = resp.json()
                    return data.get("id") or data.get("user_id") or data.get("_id")
                except:
                    pass
        return None

    async def check_multi_account_manipulation(self):
        try:
            # Step 1: Create 3 accounts
            base = "vulnora_test_" + ''.join(random.choices(string.ascii_lowercase, k=6))
            accounts = ["A", "B", "C"]
            for acc in accounts:
                username = f"{base}_{acc}"
                email = f"{username}@example.com"
                password = "Pass123!"
                await self.register_account(username, email, password)

            # Step 2: Login to all 3 and capture cookies + user IDs
            for acc in accounts:
                username = f"{base}_{acc}"
                cookies, set_cookie, login_data = await self.login_account(username, "Pass123!")
                user_id = await self.get_user_id(cookies) or f"unknown_{acc}"

                self.accounts[acc] = {
                    "username": username,
                    "cookies": dict(cookies) if cookies else {},
                    "set_cookie": set_cookie,
                    "user_id": user_id
                }

            if not self.accounts.get("A") or not self.accounts.get("B"):
                return  # Not enough accounts created

            # Step 3: Use Account A session to attack B and C
            a_cookies = self.accounts["A"]["cookies"]
            b_id = self.accounts["B"]["user_id"]
            c_id = self.accounts["C"]["user_id"]

            test_paths = [
                f"/api/user/{b_id}", f"/api/profile/{b_id}", f"/api/users/{b_id}",
                f"/api/order/{b_id}", f"/api/resource/{b_id}",
                f"/api/admin/user/{b_id}/delete", f"/api/user/{b_id}/update"
            ]

            for path in test_paths:
                # GET (view other user's data)
                resp = await self._request("GET", f"{self.target}{path}", cookies=a_cookies)
                if resp and resp.status_code in (200, 201, 403, 404) and len(resp.text) > 30:
                    self._add_finding("multi_account_manipulation", {
                        "action": "View",
                        "attacker_account": "A",
                        "victim_account": "B",
                        "victim_id": b_id,
                        "url": str(resp.url),
                        "status_code": resp.status_code,
                        "response_snippet": resp.text[:200]
                    })

                # POST/PATCH (modify)
                update_payload = {"email": "hacked@example.com", "role": "admin"}
                resp = await self._request("PATCH", f"{self.target}{path}", json_data=update_payload, cookies=a_cookies)
                if resp and resp.status_code in (200, 204, 201):
                    self._add_finding("multi_account_manipulation", {
                        "action": "Modify",
                        "attacker_account": "A",
                        "victim_account": "B",
                        "victim_id": b_id,
                        "url": str(resp.url),
                        "payload": update_payload,
                        "status_code": resp.status_code
                    })

                # DELETE (delete other user's data)
                resp = await self._request("DELETE", f"{self.target}{path}", cookies=a_cookies)
                if resp and resp.status_code in (200, 204):
                    self._add_finding("multi_account_manipulation", {
                        "action": "Delete",
                        "attacker_account": "A",
                        "victim_account": "B",
                        "victim_id": b_id,
                        "url": str(resp.url),
                        "status_code": resp.status_code
                    })

            # Optional: Test with Account A ID + Account B cookie (extra variant)
            # ... (can be added if needed)

        except Exception as e:
            # Silent fail – don't break the whole scan
            pass

    # ====================== RUNNER ======================
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
        if "multi_account_manipulation" in self.selected_checks:
            tasks.append(self.check_multi_account_manipulation())

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        await self.client.aclose()  # Clean up
        return self.findings
