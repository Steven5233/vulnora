import asyncio
import json
import logging
import random
import re
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin

import httpx
from bs4 import BeautifulSoup

try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

logger = logging.getLogger("vulnora.scanner")

_AGGRESSION_PROFILES: Dict[str, Dict[str, Any]] = {
    "low":    {"crawl_depth": 1, "max_paths": 10,  "max_ids": 5,   "burst": 3,  "delay": 1.0,  "max_check_paths": 3},
    "medium": {"crawl_depth": 3, "max_paths": 80,  "max_ids": 50,  "burst": 8,  "delay": 0.3,  "max_check_paths": 10},
    "high":   {"crawl_depth": 5, "max_paths": 200, "max_ids": 100, "burst": 15, "delay": 0.05, "max_check_paths": 20},
}


class LogicFlawScanner:
    LOGIC_CHECKS = {
        "client_side_trust":          {"name": "Excessive Trust in Client-Side Controls (Price/Quantity Manipulation)", "severity": "high",     "description": "Checks if price, quantity, or totals can be tampered client-side."},
        "idor":                       {"name": "IDOR / Broken Object Level Authorization (BOLA)",                       "severity": "high",     "description": "Tests advanced Insecure Direct Object Reference and Broken Object Level Authorization flaws."},
        "bfla":                       {"name": "Broken Function Level Authorization (Privilege Escalation)",            "severity": "critical", "description": "Checks if admin or high-privilege functions are accessible."},
        "workflow_bypass":            {"name": "Workflow / State Machine Bypass",                                       "severity": "high",     "description": "Tests skipping steps in multi-step processes."},
        "race_condition":             {"name": "Race Conditions (Concurrent Requests)",                                 "severity": "high",     "description": "Tests limit bypass via simultaneous requests."},
        "price_manipulation":         {"name": "Price / Discount / Refund Abuse",                                      "severity": "high",     "description": "Tests negative values, zero, invalid coupons, refund logic."},
        "multi_account_manipulation": {"name": "Multi-Account Broken Authorization (Cross-User IDOR/BOLA)",            "severity": "critical", "description": "Creates test accounts and performs cross-user object access/modification."},
        "mass_assignment":            {"name": "Mass Assignment / Object Injection",                                    "severity": "high",     "description": "Tests injection of privileged fields (role, balance, is_admin, etc.)."},
        "http_parameter_pollution":   {"name": "HTTP Parameter Pollution (HPP)",                                       "severity": "medium",   "description": "Uses duplicate or malformed parameters to bypass validation."},
        "forced_state_transition":    {"name": "Forced State Transition",                                              "severity": "high",     "description": "Forces business state changes without proper payment/flow."},
        "coupon_stacking":            {"name": "Coupon / Discount Stacking Abuse",                                     "severity": "medium",   "description": "Tests applying multiple or repeated discounts illegally."},
        "balance_manipulation":       {"name": "Balance Manipulation / Refund Loop",                                   "severity": "high",     "description": "Creates negative balances or exploits refund logic."},
    }

    def __init__(self, target: str, selected_checks: Optional[List[str]] = None,
                 auth_cookies: Optional[Dict[str, str]] = None, auth_jwt: Optional[str] = None,
                 aggression: str = "medium", max_retries: int = 2, request_timeout: float = 20.0):
        self.target = target.rstrip("/")
        self._closed = False

        if aggression not in _AGGRESSION_PROFILES:
            raise ValueError(f"aggression must be one of {list(_AGGRESSION_PROFILES)}")
        self.aggression = aggression
        self._profile = _AGGRESSION_PROFILES[aggression]

        transport = httpx.AsyncHTTPTransport(retries=max_retries)
        self.client = httpx.AsyncClient(timeout=request_timeout, follow_redirects=True, transport=transport)

        self.findings: List[Dict] = []
        self._finding_keys: Set[str] = set()
        self.selected_checks = selected_checks or list(self.LOGIC_CHECKS.keys())

        unknown = set(self.selected_checks) - set(self.LOGIC_CHECKS)
        if unknown:
            raise ValueError(f"Unknown check(s): {unknown}")

        self.discovered: Dict[str, Any] = {"paths": [], "ids": [], "objects": [], "endpoints": {}}
        self.auth_cookies = auth_cookies or {}
        self.auth_jwt = auth_jwt
        self.base_headers: Dict[str, str] = {"User-Agent": "Vulnora-IDORForge-Pro-v2/1.0"}
        if self.auth_jwt:
            self.base_headers["Authorization"] = f"Bearer {self.auth_jwt}"
        self.object_graph: Dict[str, Dict] = {}
        self.test_accounts: List[Dict] = []
        self._delay = self._profile["delay"]

    async def close(self):
        if not self._closed:
            self._closed = True
            await self.client.aclose()

    async def _request(self, method: str, url: str, json_data=None, params=None,
                       raw_query: Optional[str] = None, cookies=None,
                       headers=None, jwt_override=None) -> Optional[httpx.Response]:
        effective_cookies = {**self.auth_cookies, **(cookies or {})}
        effective_headers = {**self.base_headers, **(headers or {})}

        if jwt_override is not None:
            if jwt_override:
                effective_headers["Authorization"] = f"Bearer {jwt_override}"
            else:
                effective_headers.pop("Authorization", None)

        full_url = url
        if raw_query:
            sep = "&" if "?" in url else "?"
            full_url = f"{url}{sep}{raw_query}"

        try:
            if self._delay:
                await asyncio.sleep(self._delay)
            resp = await self.client.request(
                method, full_url,
                json=json_data,
                params=params if not raw_query else None,
                cookies=effective_cookies,
                headers=effective_headers
            )
            return resp
        except httpx.TimeoutException:
            return None
        except httpx.RequestError:
            return None

    def _add_finding(self, check_key: str, poc: Dict[str, Any], confidence: float = 0.8):
        check = self.LOGIC_CHECKS[check_key]
        dedup_key = f"{check_key}|{poc.get('url', '')}|{poc.get('method', 'GET')}"
        if dedup_key in self._finding_keys:
            return
        self._finding_keys.add(dedup_key)
        poc["confidence"] = round(confidence, 2)
        self.findings.append({
            "flaw_type":   check_key,
            "name":        check["name"],
            "severity":    check["severity"],
            "description": check["description"],
            "poc":         poc,
            "timestamp":   time.time()
        })

    async def _smart_discovery(self):
        if self.discovered["paths"] or self.discovered["ids"]:
            return

        discovered_paths: Set[str] = set()
        discovered_ids: Set[str] = set()
        discovered_objects: List[Dict] = []

        start_urls = [
            self.target, f"{self.target}/api", f"{self.target}/dashboard",
            f"{self.target}/api/v1", f"{self.target}/users", f"{self.target}/orders",
        ]

        max_depth = self._profile["crawl_depth"]
        max_paths = self._profile["max_paths"]

        if PLAYWRIGHT_AVAILABLE:
            await self._playwright_crawl(start_urls, discovered_paths, discovered_ids, discovered_objects, max_depth, max_paths)
        else:
            await self._httpx_crawl(start_urls, discovered_paths, discovered_ids, discovered_objects, max_depth, max_paths)

        for path in list(discovered_paths)[:max_paths]:
            if any(k in path.lower() for k in ["user", "order", "profile", "resource", "account", "item", "post"]):
                self.discovered["endpoints"][path] = {"methods": ["GET", "POST", "PUT", "PATCH", "DELETE"]}

        self.discovered["paths"]   = list(discovered_paths)[:max_paths]
        self.discovered["ids"]     = list(discovered_ids)[:self._profile["max_ids"]]
        self.discovered["objects"] = discovered_objects[:30]

    async def _playwright_crawl(self, start_urls, discovered_paths, discovered_ids, discovered_objects, max_depth, max_paths):
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context()
            if self.auth_cookies:
                await context.add_cookies([{"name": k, "value": v, "url": self.target} for k, v in self.auth_cookies.items()])
            page = await context.new_page()
            visited: Set[str] = set()
            to_visit = start_urls[:5]

            async def on_response(response):
                if "application/json" in response.headers.get("content-type", ""):
                    try:
                        body = await response.body()
                        data = json.loads(body)
                        self._extract_object_ids(data, discovered_ids, discovered_objects)
                    except Exception:
                        pass

            page.on("response", on_response)

            for _ in range(max_depth):
                if not to_visit:
                    break
                new_to_visit: List[str] = []
                for url in to_visit[:10]:
                    if url in visited or len(discovered_paths) >= max_paths:
                        continue
                    visited.add(url)
                    try:
                        await page.goto(url, wait_until="networkidle", timeout=15000)
                        content = await page.content()
                        soup = BeautifulSoup(content, "html.parser")
                        for a in soup.find_all("a", href=True):
                            link = urljoin(self.target, a["href"])
                            if link.startswith(self.target) and link not in visited:
                                new_to_visit.append(link)
                                discovered_paths.add(link.replace(self.target, "") or "/")
                    except Exception:
                        pass
                to_visit = new_to_visit

            await browser.close()

    async def _httpx_crawl(self, start_urls, discovered_paths, discovered_ids, discovered_objects, max_depth, max_paths):
        visited: Set[str] = set()
        to_visit = start_urls[:]
        for _ in range(max_depth):
            if not to_visit:
                break
            new_to_visit: List[str] = []
            for url in to_visit[:15]:
                if url in visited or not url.startswith(self.target):
                    continue
                if len(discovered_paths) >= max_paths:
                    break
                visited.add(url)
                resp = await self._request("GET", url)
                if not resp:
                    continue
                ct = resp.headers.get("content-type", "").lower()
                if "text/html" in ct:
                    soup = BeautifulSoup(resp.text, "html.parser")
                    for a in soup.find_all("a", href=True):
                        link = urljoin(self.target, a["href"])
                        if link.startswith(self.target) and link not in visited:
                            new_to_visit.append(link)
                            discovered_paths.add(link.replace(self.target, "") or "/")
                if "application/json" in ct:
                    try:
                        self._extract_object_ids(resp.json(), discovered_ids, discovered_objects)
                    except Exception:
                        pass
            to_visit = new_to_visit

    _NUMERIC_RE = re.compile(r"^\d+$")
    _UUID_RE    = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
    _MONGO_RE   = re.compile(r"^[0-9a-f]{24}$", re.I)
    _ID_KEYS    = frozenset(["id", "uuid", "_id", "user_id", "order_id", "resource_id", "slug", "email"])

    def _extract_object_ids(self, data: Any, ids_set: Set[str], objects_list: List[Dict]):
        if isinstance(data, dict):
            obj: Dict[str, str] = {}
            for k, v in data.items():
                if k.lower() in self._ID_KEYS and isinstance(v, (str, int, float)):
                    val_str = str(v)
                    if self._NUMERIC_RE.match(val_str) or self._UUID_RE.match(val_str) or self._MONGO_RE.match(val_str):
                        ids_set.add(val_str)
                        obj[k] = val_str
                if isinstance(v, (list, dict)):
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

        t1, t2  = resp1.text, resp2.text
        max_len = max(len(t1), len(t2), 1)

        if abs(len(t1) - len(t2)) / max_len > 0.6:
            return 0.3, False

        try:
            if t1 and t2 and resp1.json() == resp2.json():
                return 1.0, resp1.status_code == 200
        except Exception:
            pass

        words1 = set(t1.lower().split())
        words2 = set(t2.lower().split())
        union  = len(words1) + len(words2)
        if union == 0:
            return 0.0, False
        sim     = len(words1 & words2) / union
        is_leak = resp1.status_code == 200 and resp2.status_code == 200 and sim > 0.65
        return sim, is_leak

    async def _create_test_account(self, index: int) -> Optional[Dict]:
        register_paths = ["/register", "/api/register", "/auth/register", "/signup", "/api/auth/register", "/api/v1/register"]
        login_paths    = ["/login", "/api/login", "/auth/login", "/api/auth/login"]

        uid      = random.randint(10000, 99999)
        email    = f"vulnora_test_{index}_{uid}@example.test"
        password = "VulnoraTestPass123!"
        username = f"vulnora_testuser_{index}_{uid}"

        for reg_path in register_paths:
            payload = {"email": email, "password": password, "username": username, "name": username}
            resp = await self._request("POST", f"{self.target}{reg_path}", json_data=payload)
            if not resp or resp.status_code not in (200, 201, 202):
                continue
            for login_path in login_paths:
                login_resp = await self._request("POST", f"{self.target}{login_path}", json_data={"email": email, "password": password})
                if not login_resp or login_resp.status_code not in (200, 201):
                    continue
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

        if not self.discovered["ids"]:
            self.discovered["ids"] = [str(i) for i in range(1, 41)]

        id_types  = self.discovered["ids"]
        max_paths = self._profile["max_check_paths"]

        base_paths = [
            p for p in self.discovered["paths"]
            if any(k in p.lower() for k in ["user", "order", "profile", "resource", "account", "item", "post"])
        ] or ["/api/users/", "/api/orders/", "/api/resources/"]

        for base_path in base_paths[:max_paths]:
            for obj_id in id_types[:20]:
                for method in ["GET", "PUT", "PATCH", "DELETE"]:
                    url           = f"{self.target}{base_path.rstrip('/')}/{obj_id}"
                    owner_resp    = await self._request(method, url)
                    attacker_resp = await self._request(method, url, cookies={}, jwt_override="")
                    sim, leak     = self._response_similarity(owner_resp, attacker_resp)
                    if leak or (owner_resp and owner_resp.status_code == 200 and attacker_resp and attacker_resp.status_code in (200, 201, 204)):
                        confidence = 0.85 if leak else 0.65
                        self._add_finding("idor", {
                            "url":             url,
                            "method":          method,
                            "id":              obj_id,
                            "id_type":         "numeric/uuid",
                            "owner_status":    owner_resp.status_code    if owner_resp    else None,
                            "attacker_status": attacker_resp.status_code if attacker_resp else None,
                            "similarity":      round(sim, 2),
                            "evidence":        attacker_resp.text[:400]  if attacker_resp else "",
                        }, confidence)

        for path, _info in list(self.discovered["endpoints"].items())[:max_paths]:
            full = f"{self.target}{path}"
            for param in ["id", "user_id", "order_id", "resource_id", "uuid"]:
                for oid in id_types[:15]:
                    resp = await self._request("GET", full, params={param: oid}, cookies={}, jwt_override="")
                    if resp and resp.status_code == 200:
                        self._add_finding("idor", {"url": full, "param": param, "value": oid, "location": "query"}, 0.7)

    async def check_multi_account_manipulation(self):
        if not self.test_accounts:
            results = await asyncio.gather(*[self._create_test_account(i) for i in range(3)], return_exceptions=True)
            self.test_accounts = [r for r in results if isinstance(r, dict)]

        if len(self.test_accounts) < 2:
            return

        victim   = self.test_accounts[0]
        attacker = self.test_accounts[1]

        created_obj: Optional[str] = None
        for cpath in ["/api/orders", "/api/resources", "/api/profiles", "/api/items", "/order", "/resource"]:
            url     = f"{self.target}{cpath}"
            payload = {"name": f"Vulnora Test Object {random.randint(1000, 9999)}", "description": "Advanced IDOR test object"}
            resp    = await self._request("POST", url, json_data=payload, cookies=victim["cookies"], jwt_override=victim["jwt"])
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

        for tpath in [f"/api/order/{created_obj}", f"/api/resource/{created_obj}", f"/user/{created_obj}", f"/profile/{created_obj}", f"/api/items/{created_obj}"]:
            url = f"{self.target}{tpath}"
            for method in ["GET", "PUT", "DELETE"]:
                resp = await self._request(method, url, cookies=attacker["cookies"], jwt_override=attacker["jwt"])
                if resp and resp.status_code in (200, 201, 204):
                    self._add_finding("multi_account_manipulation", {
                        "victim":       victim["email"],
                        "attacker":     attacker["email"],
                        "object_id":    created_obj,
                        "accessed_url": url,
                        "method":       method,
                        "status":       resp.status_code,
                        "evidence":     resp.text[:500] if resp else "",
                    }, 0.9)
                    break

    async def check_bfla(self):
        await self._smart_discovery()
        admin_paths = [
            p for p in self.discovered["paths"]
            if any(k in p.lower() for k in ["admin", "dashboard", "superuser", "manager", "panel"])
        ] or ["/admin", "/api/admin/users", "/dashboard"]

        for path in admin_paths[:12]:
            url = f"{self.target}{path}"
            for jwt in [self.auth_jwt, ""]:
                resp = await self._request("GET", url, jwt_override=jwt)
                if resp and resp.status_code in (200, 201):
                    self._add_finding("bfla", {"url": url, "auth_used": bool(jwt), "status": resp.status_code, "evidence": resp.text[:300]}, 0.75)
                    break

    async def check_client_side_trust(self):
        await self._smart_discovery()
        paths    = self.discovered["paths"] or ["/checkout", "/api/order", "/cart"]
        payloads = [{"price": 0.01, "quantity": 99999}, {"total": 1}, {"amount": -999}, {"discount": 100}]
        for path in paths[:self._profile["max_check_paths"]]:
            for payload in payloads:
                resp = await self._request("POST", f"{self.target}{path}", json_data=payload)
                if resp and resp.status_code in (200, 201):
                    self._add_finding("client_side_trust", {"url": f"{self.target}{path}", "payload": payload}, 0.7)

    async def check_race_condition(self):
        await self._smart_discovery()
        burst      = self._profile["burst"]
        cart_paths = [p for p in self.discovered["paths"] if "cart" in p.lower()]
        url        = f"{self.target}{cart_paths[0]}" if cart_paths else f"{self.target}/api/resource/1"
        sem        = asyncio.Semaphore(burst)

        async def _guarded():
            async with sem:
                return await self._request("POST", url, json_data={"item": 1})

        results       = await asyncio.gather(*[_guarded() for _ in range(burst)], return_exceptions=True)
        success_count = sum(1 for r in results if isinstance(r, httpx.Response) and r.status_code in (200, 201))
        threshold     = max(3, burst // 3)
        if success_count > threshold:
            self._add_finding("race_condition", {"url": url, "concurrent_success": success_count}, 0.8)

    async def check_mass_assignment(self):
        await self._smart_discovery()
        paths    = self.discovered["paths"] or ["/api/user", "/api/profile"]
        payloads = [{"role": "admin"}, {"is_admin": True}, {"balance": 9999999}, {"permissions": ["all"]}, {"plan": "enterprise"}]
        for path in paths[:self._profile["max_check_paths"]]:
            for method in ["POST", "PUT", "PATCH"]:
                for payload in payloads:
                    resp = await self._request(method, f"{self.target}{path}", json_data=payload)
                    if resp and resp.status_code in (200, 201):
                        try:
                            body       = resp.json()
                            confidence = 0.90 if list(payload.keys())[0] in body else 0.65
                        except Exception:
                            confidence = 0.65
                        self._add_finding("mass_assignment", {"url": f"{self.target}{path}", "method": method, "payload": payload}, confidence)

    async def check_http_parameter_pollution(self):
        await self._smart_discovery()
        paths = self.discovered["paths"] or ["/api/search"]
        for path in paths[:5]:
            url = f"{self.target}{path}"
            for raw_q, variant in [("id=1&id=999999", "duplicate_key"), ("id[]=1&id[]=999999", "array_style")]:
                resp = await self._request("GET", url, raw_query=raw_q)
                if resp and resp.status_code == 200:
                    self._add_finding("http_parameter_pollution", {"url": url, "raw_query": raw_q, "variant": variant}, 0.6)

    async def check_workflow_bypass(self):
        await self._smart_discovery()
        paths = self.discovered["paths"] or ["/checkout", "/payment/confirm"]
        for path in paths[:6]:
            resp = await self._request("POST", f"{self.target}{path}", json_data={"status": "completed", "step": "final"})
            if resp and resp.status_code in (200, 201):
                self._add_finding("workflow_bypass", {"url": f"{self.target}{path}"}, 0.7)

    async def check_price_manipulation(self):
        await self._smart_discovery()
        paths    = self.discovered["paths"] or ["/checkout", "/api/order"]
        payloads = [{"price": 0.01}, {"discount": 999}, {"total": -500}]
        for path in paths[:self._profile["max_check_paths"]]:
            for p in payloads:
                resp = await self._request("POST", f"{self.target}{path}", json_data=p)
                if resp and resp.status_code in (200, 201):
                    self._add_finding("price_manipulation", {"url": f"{self.target}{path}", "payload": p}, 0.7)

    async def check_forced_state_transition(self):
        await self._smart_discovery()
        paths = self.discovered["paths"] or ["/order/complete", "/payment/confirm"]
        for path in paths[:5]:
            resp = await self._request("POST", f"{self.target}{path}", json_data={"status": "paid"})
            if resp and resp.status_code in (200, 201):
                self._add_finding("forced_state_transition", {"url": f"{self.target}{path}"}, 0.65)

    async def check_coupon_stacking(self):
        await self._smart_discovery()
        paths = self.discovered["paths"] or ["/checkout", "/api/cart/coupon"]
        for path in paths[:5]:
            url  = f"{self.target}{path}"
            resp = await self._request("POST", url, json_data={"coupon": ["TEST1", "TEST2"]})
            if resp and resp.status_code in (200, 201):
                self._add_finding("coupon_stacking", {"url": url, "variant": "parallel_array"}, 0.6)
            resp2 = None
            for _ in range(2):
                resp2 = await self._request("POST", url, json_data={"coupon": "TEST1"})
            if resp2 and resp2.status_code in (200, 201):
                self._add_finding("coupon_stacking", {"url": url, "variant": "sequential_reuse"}, 0.6)

    async def check_balance_manipulation(self):
        await self._smart_discovery()
        paths = self.discovered["paths"] or ["/api/balance", "/api/refund"]
        for path in paths[:6]:
            for payload in [{"amount": -99999}, {"refund": 999999}]:
                resp = await self._request("POST", f"{self.target}{path}", json_data=payload)
                if resp and resp.status_code in (200, 201):
                    self._add_finding("balance_manipulation", {"url": f"{self.target}{path}", "payload": payload}, 0.7)

    _CHECK_MAP: Dict[str, str] = {
        "idor":                       "check_idor",
        "multi_account_manipulation": "check_multi_account_manipulation",
        "bfla":                       "check_bfla",
        "client_side_trust":          "check_client_side_trust",
        "race_condition":             "check_race_condition",
        "mass_assignment":            "check_mass_assignment",
        "http_parameter_pollution":   "check_http_parameter_pollution",
        "workflow_bypass":            "check_workflow_bypass",
        "price_manipulation":         "check_price_manipulation",
        "forced_state_transition":    "check_forced_state_transition",
        "coupon_stacking":            "check_coupon_stacking",
        "balance_manipulation":       "check_balance_manipulation",
    }

    async def run_all(self):
        await self._smart_discovery()

        tasks = []
        for check in self.selected_checks:
            method_name = self._CHECK_MAP.get(check)
            if method_name:
                tasks.append(getattr(self, method_name)())

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for check, result in zip(self.selected_checks, results):
            if isinstance(result, Exception):
                logger.error("Check '%s' raised an exception: %s", check, result, exc_info=result)

        await self.close()
        return self.findings
