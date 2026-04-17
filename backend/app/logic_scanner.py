import asyncio
import json
import random
import re
import time
import uuid
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

class LogicFlawScanner:
    LOGIC_CHECKS = {
        "client_side_trust": {"name": "Excessive Trust in Client-Side Controls (Price/Quantity Manipulation)", "severity": "high", "description": "Checks if price, quantity, or totals can be tampered client-side."},
        "idor": {"name": "IDOR / Broken Object Level Authorization (BOLA)", "severity": "high", "description": "Tests advanced Insecure Direct Object Reference and Broken Object Level Authorization flaws."},
        "bfla": {"name": "Broken Function Level Authorization (Privilege Escalation)", "severity": "critical", "description": "Checks if admin or high-privilege functions are accessible."},
        "workflow_bypass": {"name": "Workflow / State Machine Bypass", "severity": "high", "description": "Tests skipping steps in multi-step processes."},
        "race_condition": {"name": "Race Conditions (Concurrent Requests)", "severity": "high", "description": "Tests limit bypass via simultaneous requests."},
        "price_manipulation": {"name": "Price / Discount / Refund Abuse", "severity": "high", "description": "Tests negative values, zero, invalid coupons, refund logic."},
        "multi_account_manipulation": {"name": "Multi-Account Broken Authorization (Cross-User IDOR/BOLA via Cookie/Session)", "severity": "critical", "description": "Creates test accounts and performs cross-user object access/modification."},
        "mass_assignment": {"name": "Mass Assignment / Object Injection", "severity": "high", "description": "Tests injection of privileged fields (role, balance, is_admin, etc.)."},
        "http_parameter_pollution": {"name": "HTTP Parameter Pollution (HPP)", "severity": "medium", "description": "Uses duplicate or malformed parameters to bypass validation."},
        "forced_state_transition": {"name": "Forced State Transition", "severity": "high", "description": "Forces business state changes without proper payment/flow."},
        "coupon_stacking": {"name": "Coupon / Discount Stacking Abuse", "severity": "medium", "description": "Tests applying multiple or repeated discounts illegally."},
        "balance_manipulation": {"name": "Balance Manipulation / Refund Loop", "severity": "high", "description": "Creates negative balances or exploits refund logic."}
    }

    def __init__(self, target: str, selected_checks: Optional[List[str]] = None,
                 auth_cookies: Optional[Dict[str, str]] = None, auth_jwt: Optional[str] = None,
                 aggression: str = "medium"):
        self.target = target.rstrip("/")
        self.client = httpx.AsyncClient(timeout=20.0, follow_redirects=True)
        self.findings: List[Dict] = []
        self.selected_checks = selected_checks or list(self.LOGIC_CHECKS.keys())
        self.discovered: Dict[str, Any] = {"paths": [], "ids": [], "objects": [], "endpoints": {}}
        self.auth_cookies = auth_cookies or {}
        self.auth_jwt = auth_jwt
        self.aggression = aggression
        self.base_headers = {"User-Agent": "Vulnora-IDORForge-Pro-v2/1.0"}
        if self.auth_jwt:
            self.base_headers["Authorization"] = f"Bearer {self.auth_jwt}"
        self.object_graph: Dict[str, Dict] = {}
        self.test_accounts: List[Dict] = []

    async def close(self):
        await self.client.aclose()

    async def _request(self, method: str, url: str, json_data=None, params=None, cookies=None,
                       headers=None, jwt_override=None) -> Optional[httpx.Response]:
        effective_cookies = {**self.auth_cookies, **(cookies or {})}
        effective_headers = {**self.base_headers, **(headers or {})}
        if jwt_override:
            effective_headers["Authorization"] = f"Bearer {jwt_override}"
        try:
            resp = await self.client.request(
                method, url, json=json_data, params=params,
                cookies=effective_cookies, headers=effective_headers
            )
            return resp
        except Exception:
            return None

    def _add_finding(self, check_key: str, poc: Dict[str, Any], confidence: float = 0.8):
        check = self.LOGIC_CHECKS[check_key]
        poc["confidence"] = round(confidence, 2)
        self.findings.append({
            "flaw_type": check_key,
            "name": check["name"],
            "severity": check["severity"],
            "description": check["description"],
            "poc": poc,
            "timestamp": time.time()
        })

    async def _smart_discovery(self):
        discovered_paths = set()
        discovered_ids = set()
        discovered_objects = []

        start_urls = [
            self.target, f"{self.target}/", f"{self.target}/api", f"{self.target}/dashboard",
            f"{self.target}/api/v1", f"{self.target}/users", f"{self.target}/orders"
        ]

        if PLAYWRIGHT_AVAILABLE:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context()
                if self.auth_cookies:
                    await context.add_cookies([{"name": k, "value": v, "url": self.target} for k, v in self.auth_cookies.items()])
                page = await context.new_page()
                visited = set()
                to_visit = start_urls[:5]
                depth = 0
                while to_visit and depth < 3:
                    new_to_visit = []
                    for url in to_visit[:10]:
                        if url in visited:
                            continue
                        visited.add(url)
                        try:
                            await page.goto(url, wait_until="networkidle", timeout=15000)
                            content = await page.content()
                            soup = BeautifulSoup(content, 'html.parser')
                            for a in soup.find_all('a', href=True):
                                link = urljoin(self.target, a['href'])
                                if link.startswith(self.target) and link not in visited:
                                    new_to_visit.append(link)
                                    path = link.replace(self.target, '') or '/'
                                    discovered_paths.add(path)
                            await page.route("**/*", lambda route: route.continue_())
                            responses = []
                            async def capture_response(response):
                                if "application/json" in response.headers.get("content-type", ""):
                                    try:
                                        body = await response.body()
                                        data = json.loads(body)
                                        self._extract_object_ids(data, discovered_ids, discovered_objects)
                                    except Exception:
                                        pass
                            page.on("response", capture_response)
                            await asyncio.sleep(0.5)
                        except Exception:
                            pass
                    to_visit = new_to_visit
                    depth += 1
                await browser.close()
        else:
            visited = set()
            to_visit = start_urls[:]
            depth = 0
            while to_visit and depth < 3:
                new_to_visit = []
                for url in to_visit[:15]:
                    if url in visited or not url.startswith(self.target):
                        continue
                    visited.add(url)
                    resp = await self._request("GET", url)
                    if not resp:
                        continue
                    soup = BeautifulSoup(resp.text, 'html.parser')
                    for a in soup.find_all('a', href=True):
                        link = urljoin(self.target, a['href'])
                        if link.startswith(self.target) and link not in visited:
                            new_to_visit.append(link)
                            discovered_paths.add(link.replace(self.target, '') or '/')
                    if "application/json" in resp.headers.get("content-type", "").lower():
                        try:
                            data = resp.json()
                            self._extract_object_ids(data, discovered_ids, discovered_objects)
                        except Exception:
                            pass
                to_visit = new_to_visit
                depth += 1

        for path in list(discovered_paths)[:60]:
            if any(k in path.lower() for k in ["user", "order", "profile", "resource", "account", "item", "post"]):
                self.discovered["endpoints"][path] = {"methods": ["GET", "POST", "PUT", "PATCH", "DELETE"]}

        self.discovered["paths"] = list(discovered_paths)[:80]
        self.discovered["ids"] = list(discovered_ids)[:50]
        self.discovered["objects"] = discovered_objects[:30]

    def _extract_object_ids(self, data: Any, ids_set: set, objects_list: list):
        if isinstance(data, dict):
            obj = {}
            for k, v in data.items():
                if isinstance(v, (str, int, float)) and k.lower() in ["id", "uuid", "_id", "user_id", "order_id", "resource_id", "slug", "email"]:
                    val_str = str(v)
                    if re.match(r'^\d+$', val_str) or re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', val_str, re.I) or re.match(r'^[0-9a-f]{24}$', val_str, re.I):
                        ids_set.add(val_str)
                        obj[k] = val_str
                elif isinstance(v, (list, dict)):
                    self._extract_object_ids(v, ids_set, objects_list)
            if obj:
                objects_list.append(obj)
        elif isinstance(data, list):
            for item in data:
                self._extract_object_ids(item, ids_set, objects_list)

    def _response_similarity(self, resp1: Optional[httpx.Response], resp2: Optional[httpx.Response]) -> Tuple[float, bool]:
        if not resp1 or not resp2:
            return 0.0, False
        if resp1.status_code != resp2.status_code:
            return 0.0, False
        len_diff = abs(len(resp1.text) - len(resp2.text)) / max(len(resp1.text), len(resp2.text), 1)
        if len_diff > 0.6:
            return 0.3, False
        try:
            j1 = resp1.json() if resp1.text else {}
            j2 = resp2.json() if resp2.text else {}
            if j1 == j2:
                return 1.0, True
        except Exception:
            pass
        common = len(set(resp1.text.lower().split()) & set(resp2.text.lower().split()))
        total = len(set(resp1.text.lower().split())) + len(set(resp2.text.lower().split()))
        sim = common / max(total, 1)
        is_leak = resp1.status_code == 200 and resp2.status_code == 200 and sim > 0.65
        return sim, is_leak

    async def _create_test_account(self, index: int) -> Optional[Dict]:
        register_paths = ["/register", "/api/register", "/auth/register", "/signup", "/api/auth/register", "/api/v1/register"]
        email = f"vulnora_test_{index}_{random.randint(10000,99999)}@example.test"
        password = "VulnoraTestPass123!"
        username = f"vulnora_testuser_{index}"
        for reg_path in register_paths:
            payload = {"email": email, "password": password, "username": username, "name": username}
            resp = await self._request("POST", f"{self.target}{reg_path}", json_data=payload)
            if resp and resp.status_code in (200, 201, 202):
                login_paths = ["/login", "/api/login", "/auth/login", "/api/auth/login"]
                for login_path in login_paths:
                    login_payload = {"email": email, "password": password}
                    login_resp = await self._request("POST", f"{self.target}{login_path}", json_data=login_payload)
                    if login_resp and login_resp.status_code in (200, 201):
                        cookies = dict(login_resp.cookies)
                        jwt = None
                        try:
                            data = login_resp.json()
                            jwt = data.get("token") or data.get("access_token") or data.get("jwt")
                        except Exception:
                            pass
                        return {"email": email, "cookies": cookies, "jwt": jwt, "index": index}
        return None

    async def check_idor(self):
        await self._smart_discovery()
        if not self.discovered["ids"] and not self.discovered["objects"]:
            for i in range(1, 41):
                self.discovered["ids"].append(str(i))
        id_types = self.discovered["ids"]

        base_paths = [p for p in self.discovered["paths"] if any(k in p.lower() for k in ["user", "order", "profile", "resource", "account", "item", "post"])] or ["/api/users/", "/api/orders/", "/api/resources/"]

        for base_path in base_paths[:15]:
            for obj_id in id_types[:20]:
                for method in ["GET", "POST", "PUT", "PATCH", "DELETE"]:
                    url = f"{self.target}{base_path.rstrip('/')}/{obj_id}"
                    owner_resp = await self._request(method, url)
                    attacker_resp = await self._request(method, url, cookies={}, jwt_override=None)
                    sim, leak = self._response_similarity(owner_resp, attacker_resp)
                    if leak or (owner_resp and owner_resp.status_code == 200 and attacker_resp and attacker_resp.status_code in (200, 201, 204)):
                        confidence = 0.85 if leak else 0.65
                        self._add_finding("idor", {
                            "url": url,
                            "method": method,
                            "id": obj_id,
                            "id_type": "numeric/uuid",
                            "owner_status": owner_resp.status_code if owner_resp else None,
                            "attacker_status": attacker_resp.status_code if attacker_resp else None,
                            "similarity": round(sim, 2),
                            "evidence": attacker_resp.text[:400] if attacker_resp else ""
                        }, confidence)

        for path, info in list(self.discovered["endpoints"].items())[:10]:
            full = f"{self.target}{path}"
            for param in ["id", "user_id", "order_id", "resource_id", "uuid"]:
                for oid in id_types[:15]:
                    params = {param: oid}
                    resp = await self._request("GET", full, params=params)
                    if resp and resp.status_code == 200:
                        self._add_finding("idor", {"url": full, "param": param, "value": oid, "location": "query"}, 0.7)

    async def check_multi_account_manipulation(self):
        if not self.test_accounts:
            for i in range(3):
                acc = await self._create_test_account(i)
                if acc:
                    self.test_accounts.append(acc)
        if len(self.test_accounts) < 2:
            return

        victim = self.test_accounts[0]
        attacker = self.test_accounts[1]

        created_obj = None
        create_paths = ["/api/orders", "/api/resources", "/api/profiles", "/api/items", "/order", "/resource"]
        for cpath in create_paths:
            url = f"{self.target}{cpath}"
            payload = {"name": f"Vulnora Test Object {random.randint(1000,9999)}", "description": "Advanced IDOR test object"}
            resp = await self._request("POST", url, json_data=payload, cookies=victim["cookies"], jwt_override=victim["jwt"])
            if resp and resp.status_code in (200, 201):
                try:
                    data = resp.json()
                    for key in ["id", "uuid", "_id", "order_id", "resource_id"]:
                        if key in data:
                            created_obj = str(data[key])
                            break
                except Exception:
                    pass
                if created_obj:
                    break
        if not created_obj:
            return

        self.object_graph[created_obj] = {"owner": victim["email"]}

        test_paths = [
            f"/api/order/{created_obj}", f"/api/resource/{created_obj}",
            f"/user/{created_obj}", f"/profile/{created_obj}", f"/api/items/{created_obj}"
        ]
        for tpath in test_paths:
            url = f"{self.target}{tpath}"
            for method in ["GET", "PUT", "DELETE"]:
                resp = await self._request(method, url, cookies=attacker["cookies"], jwt_override=attacker["jwt"])
                if resp and resp.status_code in (200, 201, 204):
                    self._add_finding("multi_account_manipulation", {
                        "victim": victim["email"],
                        "attacker": attacker["email"],
                        "object_id": created_obj,
                        "accessed_url": url,
                        "method": method,
                        "status": resp.status_code,
                        "evidence": resp.text[:500] if resp else ""
                    }, 0.9)
                    break

    async def check_bfla(self):
        await self._smart_discovery()
        admin_paths = [p for p in self.discovered["paths"] if any(k in p.lower() for k in ["admin", "dashboard", "superuser", "manager", "panel"])] or ["/admin", "/api/admin/users", "/dashboard"]
        for path in admin_paths[:12]:
            url = f"{self.target}{path}"
            resp = await self._request("GET", url)
            if resp and resp.status_code in (200, 201):
                self._add_finding("bfla", {"url": url, "status": resp.status_code, "evidence": resp.text[:300] if resp else ""}, 0.75)

    async def check_client_side_trust(self):
        await self._smart_discovery()
        paths = self.discovered["paths"] or ["/checkout", "/api/order", "/cart"]
        payloads = [{"price": 0.01, "quantity": 99999}, {"total": 1}, {"amount": -999}, {"discount": 100}]
        for path in paths[:10]:
            for payload in payloads:
                resp = await self._request("POST", f"{self.target}{path}", json_data=payload)
                if resp and resp.status_code in (200, 201):
                    self._add_finding("client_side_trust", {"url": f"{self.target}{path}", "payload": payload}, 0.7)

    async def check_race_condition(self):
        await self._smart_discovery()
        url = f"{self.target}/api/add-to-cart" if any("cart" in p for p in self.discovered["paths"]) else f"{self.target}/api/resource/1"
        tasks = [self._request("POST", url, json_data={"item": 1}) for _ in range(8)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        success_count = sum(1 for r in results if isinstance(r, httpx.Response) and r.status_code in (200, 201))
        if success_count > 3:
            self._add_finding("race_condition", {"url": url, "concurrent_success": success_count}, 0.8)

    async def check_mass_assignment(self):
        await self._smart_discovery()
        paths = self.discovered["paths"] or ["/api/user", "/api/profile"]
        payloads = [{"role": "admin"}, {"is_admin": True}, {"balance": 9999999}, {"permissions": ["all"]}]
        for path in paths[:8]:
            for payload in payloads:
                resp = await self._request("POST", f"{self.target}{path}", json_data=payload)
                if resp and resp.status_code in (200, 201):
                    self._add_finding("mass_assignment", {"url": f"{self.target}{path}", "payload": payload}, 0.75)

    async def check_http_parameter_pollution(self):
        await self._smart_discovery()
        for path in (self.discovered["paths"] or ["/api/search"])[:5]:
            url = f"{self.target}{path}?id=1&id=999999"
            resp = await self._request("GET", url)
            if resp and resp.status_code == 200:
                self._add_finding("http_parameter_pollution", {"url": url}, 0.6)

    async def check_workflow_bypass(self):
        await self._smart_discovery()
        for path in (self.discovered["paths"] or ["/checkout", "/payment/confirm"])[:6]:
            resp = await self._request("POST", f"{self.target}{path}", json_data={"status": "completed", "step": "final"})
            if resp and resp.status_code in (200, 201):
                self._add_finding("workflow_bypass", {"url": f"{self.target}{path}"}, 0.7)

    async def check_price_manipulation(self):
        await self._smart_discovery()
        paths = self.discovered["paths"] or ["/checkout", "/api/order"]
        payloads = [{"price": 0.01}, {"discount": 999}, {"total": -500}]
        for path in paths[:8]:
            for p in payloads:
                resp = await self._request("POST", f"{self.target}{path}", json_data=p)
                if resp and resp.status_code in (200, 201):
                    self._add_finding("price_manipulation", {"url": f"{self.target}{path}", "payload": p}, 0.7)

    async def check_forced_state_transition(self):
        await self._smart_discovery()
        for path in (self.discovered["paths"] or ["/order/complete", "/payment/confirm"])[:5]:
            resp = await self._request("POST", f"{self.target}{path}", json_data={"status": "paid"})
            if resp and resp.status_code in (200, 201):
                self._add_finding("forced_state_transition", {"url": f"{self.target}{path}"}, 0.65)

    async def check_coupon_stacking(self):
        await self._smart_discovery()
        for path in (self.discovered["paths"] or ["/checkout", "/api/cart/coupon"])[:5]:
            resp = await self._request("POST", f"{self.target}{path}", json_data={"coupon": ["TEST1", "TEST2"]})
            if resp and resp.status_code in (200, 201):
                self._add_finding("coupon_stacking", {"url": f"{self.target}{path}"}, 0.6)

    async def check_balance_manipulation(self):
        await self._smart_discovery()
        paths = self.discovered["paths"] or ["/api/balance", "/api/refund"]
        for path in paths[:6]:
            for payload in [{"amount": -99999}, {"refund": 999999}]:
                resp = await self._request("POST", f"{self.target}{path}", json_data=payload)
                if resp and resp.status_code in (200, 201):
                    self._add_finding("balance_manipulation", {"url": f"{self.target}{path}", "payload": payload}, 0.7)

    async def run_all(self):
        await self._smart_discovery()
        tasks = []
        for check in self.selected_checks:
            if check == "idor":
                tasks.append(self.check_idor())
            elif check == "multi_account_manipulation":
                tasks.append(self.check_multi_account_manipulation())
            elif check == "bfla":
                tasks.append(self.check_bfla())
            elif check == "client_side_trust":
                tasks.append(self.check_client_side_trust())
            elif check == "race_condition":
                tasks.append(self.check_race_condition())
            elif check == "mass_assignment":
                tasks.append(self.check_mass_assignment())
            elif check == "http_parameter_pollution":
                tasks.append(self.check_http_parameter_pollution())
            elif check == "workflow_bypass":
                tasks.append(self.check_workflow_bypass())
            elif check == "price_manipulation":
                tasks.append(self.check_price_manipulation())
            elif check == "forced_state_transition":
                tasks.append(self.check_forced_state_transition())
            elif check == "coupon_stacking":
                tasks.append(self.check_coupon_stacking())
            elif check == "balance_manipulation":
                tasks.append(self.check_balance_manipulation())
        await asyncio.gather(*tasks, return_exceptions=True)
        await self.close()
        return self.findings
