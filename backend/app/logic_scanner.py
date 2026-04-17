import httpx
import asyncio
from typing import Dict, List, Any, Optional
import time
import random
import re
from urllib.parse import urljoin

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
        self.discovered = {"paths": [], "ids": []}

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

    async def _discover_endpoints(self):
        discovered = {"paths": set(), "ids": []}
        start_urls = [
            self.target, f"{self.target}/", f"{self.target}/api", f"{self.target}/dashboard",
            f"{self.target}/user", f"{self.target}/order", f"{self.target}/profile"
        ]
        for url in start_urls:
            resp = await self._request("GET", url)
            if not resp:
                continue
            links = re.findall(r'href=["\'](.*?)["\']', resp.text) + re.findall(r'src=["\'](.*?)["\']', resp.text)
            for link in links:
                if link.startswith(('/', 'http')):
                    full = urljoin(self.target, link) if not link.startswith('http') else link
                    if full.startswith(self.target):
                        discovered["paths"].add(full.replace(self.target, ''))
            try:
                if 'application/json' in resp.headers.get('content-type', ''):
                    data = resp.json()
                    self._extract_ids(data, discovered["ids"])
            except:
                pass
        self.discovered["paths"] = list(discovered["paths"])[:30]
        self.discovered["ids"] = list(set(discovered["ids"]))[:15]

    def _extract_ids(self, data, ids_list):
        if isinstance(data, dict):
            for k, v in data.items():
                if isinstance(v, (int, str)) and str(v).isdigit() and int(v) > 0:
                    ids_list.append(str(v))
                elif isinstance(v, (list, dict)):
                    self._extract_ids(v, ids_list)
        elif isinstance(data, list):
            for item in data:
                self._extract_ids(item, ids_list)

    def _is_vulnerable(self, resp, check_key: str) -> bool:
        if not resp or resp.status_code not in (200, 201, 202, 204):
            return False
        text_lower = resp.text.lower()
        if any(err in text_lower for err in ["error", "forbidden", "unauthorized", "access denied", "not found", "invalid"]):
            return False
        if check_key == "idor" and len(resp.text) > 80:
            return True
        if check_key in ["multi_account_manipulation", "bfla"] and len(resp.text) > 100:
            return True
        return True

    async def check_client_side_trust(self):
        payloads = [{"price": 0.01, "quantity": 9999}, {"total": 1.0}, {"amount": -50}]
        paths = self.discovered["paths"] or ["/checkout", "/api/order", "/cart/update", "/api/cart"]
        for payload in payloads:
            for path in paths:
                resp = await self._request("POST", f"{self.target}{path}", json_data=payload)
                if self._is_vulnerable(resp, "client_side_trust"):
                    self._add_finding("client_side_trust", {"url": str(resp.url), "payload": payload})

    async def check_idor(self):
        ids = self.discovered["ids"] or [str(i) for i in range(1, 30)]
        base_paths = [p for p in self.discovered["paths"] if any(x in p.lower() for x in ["user", "order", "profile", "resource"])] or ["/user/", "/order/", "/profile/", "/api/resource/", "/api/user/"]
        for iid in ids:
            for base in base_paths:
                url = f"{self.target}{base}{iid}"
                resp = await self._request("GET", url)
                if self._is_vulnerable(resp, "idor"):
                    self._add_finding("idor", {"url": url, "id": iid, "evidence": resp.text[:200] if resp else ""})

    async def check_bfla(self):
        paths = [p for p in self.discovered["paths"] if "admin" in p.lower()] or ["/admin", "/api/admin", "/dashboard/admin", "/api/v1/admin", "/api/admin/users"]
        for path in paths:
            resp = await self._request("GET", f"{self.target}{path}")
            if self._is_vulnerable(resp, "bfla"):
                self._add_finding("bfla", {"url": str(resp.url)})

    async def check_workflow_bypass(self):
        payloads = [{"step": "complete"}, {"status": "paid"}]
        paths = self.discovered["paths"] or ["/api/checkout/complete", "/api/order/confirm"]
        for payload in payloads:
            for path in paths:
                resp = await self._request("POST", f"{self.target}{path}", json_data=payload)
                if self._is_vulnerable(resp, "workflow_bypass"):
                    self._add_finding("workflow_bypass", {"url": str(resp.url), "payload": payload})

    async def check_race_condition(self):
        async def race():
            tasks = [self._request("POST", f"{self.target}/api/redeem", json_data={"code": "TEST123"}) for _ in range(5)]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            success_count = sum(1 for r in results if isinstance(r, httpx.Response) and self._is_vulnerable(r, "race_condition"))
            if success_count > 2:
                self._add_finding("race_condition", {"attempts": 5, "successes": success_count})
        await race()

    async def check_price_manipulation(self):
        payloads = [{"price": -100}, {"coupon": "INVALID"}, {"refund_amount": 9999}, {"discount": 1000}]
        paths = self.discovered["paths"] or ["/api/order", "/checkout", "/api/payment"]
        for payload in payloads:
            for path in paths:
                resp = await self._request("POST", f"{self.target}{path}", json_data=payload)
                if self._is_vulnerable(resp, "price_manipulation"):
                    self._add_finding("price_manipulation", {"url": str(resp.url), "payload": payload})

    async def register_account(self, username: str, email: str, password: str):
        payload = {"username": username, "email": email, "password": password}
        paths = self.discovered["paths"] or ["/register", "/api/register", "/signup", "/api/auth/register"]
        for path in paths:
            resp = await self._request("POST", f"{self.target}{path}", json_data=payload)
            if resp and resp.status_code in (200, 201):
                return resp
        return None

    async def login_account(self, username: str, password: str):
        payload = {"username": username, "password": password}
        paths = self.discovered["paths"] or ["/login", "/api/login", "/auth/login", "/api/auth/login"]
        for path in paths:
            resp = await self._request("POST", f"{self.target}{path}", json_data=payload)
            if resp and resp.status_code in (200, 201):
                return resp
        return None

    async def check_multi_account_manipulation(self):
        accounts = []
        base_cookies = dict(self.auth_cookies)

        for i in range(3):
            username = f"vulnora_test_{i}_{random.randint(10000, 99999)}"
            email = f"{username}@example.test"
            password = "VulnoraTest123!"
            reg_resp = await self.register_account(username, email, password)
            if reg_resp:
                login_resp = await self.login_account(username, password)
                if login_resp:
                    acc_cookies = dict(login_resp.cookies) if login_resp.cookies else {}
                    accounts.append({"username": username, "cookies": {**base_cookies, **acc_cookies}})

        if len(accounts) < 2:
            return

        a_cookies = accounts[0]["cookies"]
        for victim in accounts[1:]:
            victim_name = victim["username"]
            test_paths = self.discovered["paths"] or ["/api/user/me", "/api/profile", "/api/order", "/api/balance", f"/api/user/{victim_name}"]
            for path in test_paths:
                resp = await self._request("GET", f"{self.target}{path}", cookies=a_cookies)
                if self._is_vulnerable(resp, "multi_account_manipulation"):
                    self._add_finding("multi_account_manipulation", {
                        "attacker": accounts[0]["username"],
                        "victim": victim_name,
                        "url": str(resp.url),
                        "evidence": resp.text[:300] if resp else ""
                    })
                    break

    async def check_mass_assignment(self):
        payloads = [{"role": "admin"}, {"balance": 999999}, {"is_admin": True}, {"permissions": ["*"]}]
        paths = self.discovered["paths"] or ["/api/profile/update", "/api/user", "/api/account"]
        for payload in payloads:
            for path in paths:
                resp = await self._request("POST", f"{self.target}{path}", json_data=payload)
                if self._is_vulnerable(resp, "mass_assignment"):
                    self._add_finding("mass_assignment", {"url": str(resp.url), "payload": payload})

    async def check_http_parameter_pollution(self):
        paths = self.discovered["paths"] or ["/api/order", "/checkout"]
        for path in paths:
            resp = await self._request("GET", f"{self.target}{path}?id=1&id=2&admin=true", params={"id": "1", "admin": "true"})
            if self._is_vulnerable(resp, "http_parameter_pollution"):
                self._add_finding("http_parameter_pollution", {"url": str(resp.url)})

    async def check_forced_state_transition(self):
        payloads = [{"status": "paid", "bypass": True}, {"step": 999}]
        paths = self.discovered["paths"] or ["/api/order/confirm", "/api/checkout/complete"]
        for payload in payloads:
            for path in paths:
                resp = await self._request("POST", f"{self.target}{path}", json_data=payload)
                if self._is_vulnerable(resp, "forced_state_transition"):
                    self._add_finding("forced_state_transition", {"url": str(resp.url), "payload": payload})

    async def check_coupon_stacking(self):
        payloads = [{"coupon": "SUMMER"}, {"coupon": "SUMMER"}, {"coupon": "WINTER"}]
        paths = self.discovered["paths"] or ["/api/cart/apply", "/api/discount"]
        for payload in payloads:
            for path in paths:
                resp = await self._request("POST", f"{self.target}{path}", json_data=payload)
                if self._is_vulnerable(resp, "coupon_stacking"):
                    self._add_finding("coupon_stacking", {"url": str(resp.url), "payload": payload})

    async def check_balance_manipulation(self):
        payloads = [{"amount": -9999}, {"refund": 999999}]
        paths = self.discovered["paths"] or ["/api/balance", "/api/payment/refund"]
        for payload in payloads:
            for path in paths:
                resp = await self._request("POST", f"{self.target}{path}", json_data=payload)
                if self._is_vulnerable(resp, "balance_manipulation"):
                    self._add_finding("balance_manipulation", {"url": str(resp.url), "payload": payload})

    async def run_selected_checks(self):
        await self._discover_endpoints()
        tasks = []
        for check_key in self.selected_checks:
            method_name = f"check_{check_key}"
            if hasattr(self, method_name):
                tasks.append(getattr(self, method_name)())
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        await self.client.aclose()
        return self.findings
