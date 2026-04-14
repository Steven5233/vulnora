# backend/app/logic_scanner.py
import httpx
import asyncio
from typing import Dict, List, Any, Optional
import time
import random
import string

class LogicFlawScanner:
    LOGIC_CHECKS = {
        "client_side_trust": {"name": "Excessive Trust in Client-Side Controls (Price/Quantity Manipulation)", "severity": "high", "description": "Checks if price, quantity, or totals can be tampered client-side."},
        "idor": {"name": "IDOR / Broken Object Level Authorization (BOLA)", "severity": "high", "description": "Tests sequential ID access without ownership checks."},
        "bfla": {"name": "Broken Function Level Authorization (Privilege Escalation)", "severity": "critical", "description": "Checks if admin or high-privilege functions are accessible."},
        "workflow_bypass": {"name": "Workflow / State Machine Bypass", "severity": "high", "description": "Tests skipping steps in multi-step processes."},
        "race_condition": {"name": "Race Conditions (Concurrent Requests)", "severity": "high", "description": "Tests limit bypass via simultaneous requests."},
        "price_manipulation": {"name": "Price / Discount / Refund Abuse", "severity": "high", "description": "Tests negative values, zero, invalid coupons, refund logic."},
        "multi_account_manipulation": {"name": "Multi-Account Broken Authorization (Cross-User IDOR/BOLA via Cookie/Session)", "severity": "critical", "description": "Creates 3 accounts (A, B, C). Uses Account A session/cookie to manipulate/view/delete data of Account B/C."},
        "mass_assignment": {"name": "Mass Assignment / Object Injection", "severity": "high", "description": "Tests injection of privileged fields (role, balance, is_admin, etc.)."},
        "http_parameter_pollution": {"name": "HTTP Parameter Pollution (HPP)", "severity": "medium", "description": "Uses duplicate or malformed parameters to bypass validation."},
        "forced_state_transition": {"name": "Forced State Transition", "severity": "high", "description": "Forces business state changes without proper payment/flow."},
        "coupon_stacking": {"name": "Coupon / Discount Stacking Abuse", "severity": "medium", "description": "Tests applying multiple or repeated discounts illegally."},
        "balance_manipulation": {"name": "Balance Manipulation / Refund Loop", "severity": "high", "description": "Creates negative balances or exploits refund logic."}
    }

    def __init__(self, target: str, selected_checks: Optional[List[str]] = None,
                 auth_cookies: Optional[Dict[str, str]] = None, auth_jwt: Optional[str] = None):
        self.target = target.rstrip("/")
        self.client = httpx.AsyncClient(timeout=15, follow_redirects=True)
        self.findings: List[Dict] = []
        self.selected_checks = selected_checks or list(self.LOGIC_CHECKS.keys())
        self.accounts = {}

        # === AUTHENTICATED SCANNING SUPPORT ===
        self.auth_cookies = auth_cookies or {}
        self.auth_jwt = auth_jwt
        self.base_headers = {"User-Agent": "Vulnora-LogicScanner/1.0"}
        if self.auth_jwt:
            self.base_headers["Authorization"] = f"Bearer {self.auth_jwt}"

    async def _request(self, method: str, url: str, json_data=None, cookies=None, headers=None):
        effective_cookies = {**self.auth_cookies, **(cookies or {})}
        effective_headers = {**self.base_headers, **(headers or {})}
        try:
            resp = await self.client.request(
                method, url, json=json_data, cookies=effective_cookies, headers=effective_headers
            )
            return resp
        except Exception:
            return None

    def _add_finding(self, check_key: str, poc: Dict[str, Any]):
        check = self.LOGIC_CHECKS[check_key]
        self.findings.append({
            "flaw_type": check_key,
            "name": check["name"],
            "severity": check["severity"],
            "description": check["description"],
            "poc": poc,
            "timestamp": time.time()
        })

    # ====================== ALL ORIGINAL CHECKS (100% preserved) ======================
    async def check_client_side_trust(self):
        payloads = [{"price": 0.01, "quantity": 9999}, {"total": 1.0}, {"amount": -50}]
        paths = ["/checkout", "/api/order", "/cart/update", "/api/cart"]
        for payload in payloads:
            for path in paths:
                resp = await self._request("POST", f"{self.target}{path}", json_data=payload)
                if resp and resp.status_code in (200, 201, 202):
                    self._add_finding("client_side_trust", {"url": str(resp.url), "payload": payload})

    async def check_idor(self):
        for i in range(1, 30):
            for base in ["/user/", "/order/", "/profile/", "/api/resource/", "/api/user/"]:
                url = f"{self.target}{base}{i}"
                resp = await self._request("GET", url)
                if resp and resp.status_code == 200 and len(resp.text) > 50:
                    self._add_finding("idor", {"url": url, "id": i})

    async def check_bfla(self):
        paths = ["/admin", "/api/admin", "/dashboard/admin", "/api/v1/admin", "/api/admin/users"]
        for path in paths:
            resp = await self._request("GET", f"{self.target}{path}")
            if resp and resp.status_code in (200, 301, 302):
                self._add_finding("bfla", {"url": str(resp.url)})

    async def check_workflow_bypass(self):
        payloads = [{"step": "complete"}, {"status": "paid"}]
        paths = ["/api/checkout/complete", "/api/order/confirm"]
        for payload in payloads:
            for path in paths:
                resp = await self._request("POST", f"{self.target}{path}", json_data=payload)
                if resp and resp.status_code in (200, 201):
                    self._add_finding("workflow_bypass", {"url": str(resp.url), "payload": payload})

    async def check_race_condition(self):
        async def race():
            tasks = [self._request("POST", f"{self.target}/api/redeem", json_data={"code": "TEST123"}) for _ in range(5)]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            success_count = sum(1 for r in results if isinstance(r, httpx.Response) and r.status_code in (200, 201))
            if success_count > 2:
                self._add_finding("race_condition", {"attempts": 5, "successes": success_count})
        await race()

    async def check_price_manipulation(self):
        payloads = [{"price": -100}, {"coupon": "INVALID"}, {"refund_amount": 9999}, {"discount": 1000}]
        paths = ["/api/order", "/checkout", "/api/payment"]
        for payload in payloads:
            for path in paths:
                resp = await self._request("POST", f"{self.target}{path}", json_data=payload)
                if resp and resp.status_code in (200, 201):
                    self._add_finding("price_manipulation", {"url": str(resp.url), "payload": payload})

    # ====================== MULTI-ACCOUNT CHECK (original + auth support) ======================
    async def register_account(self, username: str, email: str, password: str):
        payload = {"username": username, "email": email, "password": password}
        paths = ["/register", "/api/register", "/signup", "/api/auth/register"]
        for path in paths:
            resp = await self._request("POST", f"{self.target}{path}", json_data=payload)
            if resp and resp.status_code in (200, 201):
                return resp
        return None

    async def login_account(self, username: str, password: str):
        payload = {"username": username, "password": password}
        paths = ["/login", "/api/login", "/auth/login", "/api/auth/login"]
        for path in paths:
            resp = await self._request("POST", f"{self.target}{path}", json_data=payload)
            if resp and resp.status_code in (200, 201, 302):
                return resp.cookies, resp.headers.get("set-cookie"), resp.json() if resp.content else {}
        return None, None, {}

    async def get_user_id(self, cookies):
        paths = ["/api/me", "/api/user", "/profile"]
        for path in paths:
            resp = await self._request("GET", f"{self.target}{path}", cookies=cookies)
            if resp and resp.status_code == 200:
                try:
                    data = resp.json()
                    return data.get("id") or data.get("user_id")
                except:
                    pass
        return None

    async def check_multi_account_manipulation(self):
        # Create 3 test accounts
        accounts = []
        for i in range(3):
            username = f"testuser_{i}_{int(time.time())}"
            email = f"{username}@vulnora.test"
            resp = await self.register_account(username, email, "Pass123!")
            if resp:
                cookies, _, _ = await self.login_account(username, "Pass123!")
                if cookies:
                    accounts.append((username, cookies))
        if len(accounts) < 3:
            return
        # Account A manipulates Account B's data
        a_cookies = accounts[0][1]
        b_user_id = await self.get_user_id(accounts[1][1])
        if b_user_id:
            resp = await self._request("DELETE", f"{self.target}/api/user/{b_user_id}", cookies=a_cookies)
            if resp and resp.status_code in (200, 204):
                self._add_finding("multi_account_manipulation", {"attacker": accounts[0][0], "victim_id": b_user_id})

    async def check_mass_assignment(self):
        payload = {"role": "admin", "is_admin": True, "balance": 999999}
        resp = await self._request("POST", f"{self.target}/api/user", json_data=payload)
        if resp and resp.status_code in (200, 201):
            self._add_finding("mass_assignment", {"payload": payload})

    async def check_http_parameter_pollution(self):
        # Example HPP
        resp = await self._request("GET", f"{self.target}/api/search?q=test&q=admin")
        if resp and resp.status_code == 200:
            self._add_finding("http_parameter_pollution", {"url": str(resp.url)})

    async def check_forced_state_transition(self):
        resp = await self._request("POST", f"{self.target}/api/order/complete", json_data={"status": "paid"})
        if resp and resp.status_code in (200, 201):
            self._add_finding("forced_state_transition", {"url": str(resp.url)})

    async def check_coupon_stacking(self):
        resp = await self._request("POST", f"{self.target}/api/coupon/apply", json_data={"code": "SUMMER20", "code": "DISCOUNT50"})
        if resp and resp.status_code in (200, 201):
            self._add_finding("coupon_stacking", {"url": str(resp.url)})

    async def check_balance_manipulation(self):
        payloads = [{"balance": -9999}, {"refund": 999999}]
        for payload in payloads:
            resp = await self._request("POST", f"{self.target}/api/payment", json_data=payload)
            if resp and resp.status_code in (200, 201):
                self._add_finding("balance_manipulation", {"url": str(resp.url), "payload": payload})

    async def run_selected_checks(self) -> List[Dict]:
        mapping = {
            "client_side_trust": self.check_client_side_trust(),
            "idor": self.check_idor(),
            "bfla": self.check_bfla(),
            "workflow_bypass": self.check_workflow_bypass(),
            "race_condition": self.check_race_condition(),
            "price_manipulation": self.check_price_manipulation(),
            "multi_account_manipulation": self.check_multi_account_manipulation(),
            "mass_assignment": self.check_mass_assignment(),
            "http_parameter_pollution": self.check_http_parameter_pollution(),
            "forced_state_transition": self.check_forced_state_transition(),
            "coupon_stacking": self.check_coupon_stacking(),
            "balance_manipulation": self.check_balance_manipulation()
        }
        tasks = [mapping[check] for check in self.selected_checks if check in mapping]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        return self.findings
