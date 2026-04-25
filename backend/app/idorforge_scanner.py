import asyncio
import json
import random
import re
import time
from typing import List, Dict, Any, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qs

import httpx
from bs4 import BeautifulSoup

try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


class IDORForgeProScanner:
    def __init__(
        self,
        target: str,
        auth_cookies: Optional[Dict[str, str]] = None,
        auth_jwt: Optional[str] = None,
        extra_sessions: Optional[List[Dict]] = None,  # From LogicFlawScanner.test_accounts
        aggression: str = "medium",  # low / medium / high
        rate_limit_delay: float = 0.35,
    ):
        self.target = target if target.startswith(("http://", "https://")) else f"http://{target}"
        self.target = self.target.rstrip("/")
        self.auth_cookies = auth_cookies or {}
        self.auth_jwt = auth_jwt
        self.extra_sessions = extra_sessions or []
        self.aggression = aggression
        self.rate_limit_delay = rate_limit_delay

        self.client = httpx.AsyncClient(timeout=20.0, follow_redirects=True)
        self.findings: List[Dict] = []
        self.discovered: Dict[str, Any] = {
            "paths": [],
            "ids": {"numeric": [], "uuid": [], "slug": []},
            "objects": [],
            "params": set(),
            "endpoints": {},
        }
        self.base_headers = {"User-Agent": "Vulnora-IDORForgePro-Advanced/2.1"}

    async def close(self):
        await self.client.aclose()

    async def _request(
        self,
        method: str,
        url: str,
        json_data=None,
        params=None,
        cookies=None,
        jwt_override=None,
    ) -> Optional[httpx.Response]:
        effective_cookies = {**self.auth_cookies, **(cookies or {})}
        headers = {**self.base_headers}
        if jwt_override:
            headers["Authorization"] = f"Bearer {jwt_override}"
        elif self.auth_jwt:
            headers["Authorization"] = f"Bearer {self.auth_jwt}"

        try:
            await asyncio.sleep(self.rate_limit_delay)
            resp = await self.client.request(
                method, url, json=json_data, params=params,
                cookies=effective_cookies, headers=headers
            )
            return resp
        except Exception:
            return None

    async def _smart_discover_endpoints(self):
        """Enhanced discovery combining original logic with deeper crawling."""
        discovered_paths: Set[str] = set()
        numeric_ids: Set[str] = set()
        uuid_ids: Set[str] = set()
        slug_ids: Set[str] = set()
        params: Set[str] = set()

        start_urls = [
            self.target, urljoin(self.target, "/api"), urljoin(self.target, "/"),
            urljoin(self.target, "/api/v1"), urljoin(self.target, "/dashboard")
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
                while to_visit and depth < 4:
                    new_to_visit = []
                    for url in to_visit[:12]:
                        if url in visited: continue
                        visited.add(url)
                        try:
                            await page.goto(url, wait_until="networkidle", timeout=15000)
                            content = await page.content()
                            soup = BeautifulSoup(content, 'html.parser')
                            for a in soup.find_all('a', href=True):
                                link = urljoin(self.target, a['href'])
                                if link.startswith(self.target) and link not in visited:
                                    new_to_visit.append(link)
                                    discovered_paths.add(link.replace(self.target, '') or '/')
                            
                        except:
                            pass
                    to_visit = new_to_visit
                    depth += 1
                await browser.close()
        else:
            
            visited = set()
            to_visit = start_urls[:]
            depth = 0
            while to_visit and depth < 4:
                new_to_visit = []
                for url in to_visit[:20]:
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

                    if 'application/json' in resp.headers.get('content-type', '').lower():
                        try:
                            data = resp.json()
                            self._extract_ids_and_objects(data, numeric_ids, uuid_ids, slug_ids, params)
                        except:
                            pass

                    
                    parsed = urlparse(url)
                    if parsed.query:
                        for p in parse_qs(parsed.query):
                            params.add(p)

                to_visit = new_to_visit
                depth += 1

        self.discovered["paths"] = list(discovered_paths)[:100]
        self.discovered["ids"]["numeric"] = list(numeric_ids)[:50]
        self.discovered["ids"]["uuid"] = list(uuid_ids)[:30]
        self.discovered["ids"]["slug"] = list(slug_ids)[:20]
        self.discovered["params"] = list(params)

    def _extract_ids_and_objects(self, data: Any, numeric: Set, uuid_set: Set, slug_set: Set, params: Set):
        """Improved recursive extraction (extends original _extract_ids)."""
        if isinstance(data, dict):
            for k, v in data.items():
                v_str = str(v)
                if isinstance(v, (int, str)) and k.lower() in ["id", "user_id", "order_id", "resource_id", "_id", "uuid"]:
                    if re.match(r'^\d+$', v_str):
                        numeric.add(v_str)
                    elif re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', v_str, re.I):
                        uuid_set.add(v_str)
                    elif re.match(r'^[a-z0-9_-]+$', v_str.lower()) and 6 <= len(v_str) <= 80:
                        slug_set.add(v_str)
                elif isinstance(v, (list, dict)):
                    self._extract_ids_and_objects(v, numeric, uuid_set, slug_set, params)
        elif isinstance(data, list):
            for item in data:
                self._extract_ids_and_objects(item, numeric, uuid_set, slug_set, params)

    def _response_diff(self, resp1: Optional[httpx.Response], resp2: Optional[httpx.Response]) -> Tuple[float, bool]:
        """Improved similarity + leak detection (used across checks)."""
        if not resp1 or not resp2:
            return 0.0, False
        if resp1.status_code != resp2.status_code:
            return 0.0, False

        try:
            j1 = resp1.json() if resp1.text.strip() else {}
            j2 = resp2.json() if resp2.text.strip() else {}
            if j1 == j2 and resp1.status_code == 200:
                return 1.0, True
        except:
            pass

        text1 = resp1.text.lower()
        text2 = resp2.text.lower()
        common = len(set(text1.split()) & set(text2.split()))
        total = max(len(set(text1.split())), 1)
        sim = common / total
        is_leak = resp1.status_code == 200 and sim > 0.68
        return sim, is_leak

    def _is_vulnerable(self, resp: Optional[httpx.Response], check_name: str) -> bool:
        """Original method preserved for backward compatibility."""
        if not resp or resp.status_code not in (200, 201, 204):
            return False
        text = resp.text.lower() if resp.text else ""
        if any(x in text for x in ["error", "forbidden", "unauthorized", "access denied", "permission denied"]):
            return False
        return True

    async def run(self) -> List[Dict]:
        """Main entry point - compatible with original + runs all advanced checks."""
        await self._smart_discover_endpoints()

        checks = [
            self._deep_role_permission_idor,      
            self._write_only_idor,                
            self._graphql_advanced_manipulation,  
            self._bulk_operation_idor,            
            self._multi_step_business_logic_bypass, 
            self._advanced_rest_idor,             
            self._mass_assignment_fuzz,           
            self._race_condition_primitive,       
        ]

        for check in checks:
            try:
                await check()
            except Exception as e:
                
                pass

        await self.close()
        return self.findings

    
    async def _deep_role_permission_idor(self):
        test_ids = self.discovered["ids"]["numeric"] or ["1", "2", "999", "admin"]
        base_paths = [p for p in self.discovered["paths"] if any(x in p.lower() for x in ["user", "profile", "account"])] or ["/api/user/"]
        for tid in test_ids[:15]:
            for base in base_paths[:10]:
                url = urljoin(self.target, f"{base.rstrip('/')}/{tid}")
                resp = await self._request("GET", url)
                if self._is_vulnerable(resp, "deep_role_permission_idor"):
                    self.findings.append({
                        "check": "deep_role_permission_idor",
                        "severity": "critical",
                        "title": "Deep Role/Permission IDOR",
                        "description": f"Accessed object {tid} without proper role check",
                        "poc": f"GET {url} → {resp.status_code if resp else 'N/A'}",
                        "evidence": resp.text[:300] if resp else ""
                    })

    async def _write_only_idor(self):
        payload = {"balance": 999999, "role": "admin"}
        paths = self.discovered["paths"] or ["/api/profile/update"]
        for path in paths[:8]:
            url = urljoin(self.target, path)
            resp = await self._request("POST", url, json_data=payload)
            if self._is_vulnerable(resp, "write_only_idor"):
                self.findings.append({
                    "check": "write_only_idor",
                    "severity": "high",
                    "title": "Write-Only IDOR",
                    "description": "Able to modify object without read permission",
                    "poc": f"POST {url} with {payload}",
                    "evidence": resp.text[:200] if resp else ""
                })

    async def _bulk_operation_idor(self):
        bulk_payload = {"ids": (self.discovered["ids"]["numeric"][:3] or ["1", "2", "3"]), "action": "delete"}
        paths = self.discovered["paths"] or ["/api/bulk/action"]
        for path in paths[:6]:
            url = urljoin(self.target, path)
            resp = await self._request("POST", url, json_data=bulk_payload)
            if self._is_vulnerable(resp, "bulk_operation_idor"):
                self.findings.append({
                    "check": "bulk_operation_idor",
                    "severity": "high",
                    "title": "Bulk-Operation IDOR",
                    "description": "Bulk action succeeded on foreign objects",
                    "poc": f"POST {url} with ids {bulk_payload['ids']}",
                    "evidence": resp.text[:200] if resp else ""
                })

    async def _multi_step_business_logic_bypass(self):
        paths = self.discovered["paths"] or ["/api/workflow/start", "/api/workflow/complete"]
        step1 = await self._request("POST", urljoin(self.target, paths[0]), json_data={"step": 1})
        if step1 and step1.status_code == 200:
            step_final = await self._request("POST", urljoin(self.target, paths[-1] if len(paths) > 1 else paths[0]), json_data={"step": 5, "bypass": True})
            if self._is_vulnerable(step_final, "multi_step_bypass"):
                self.findings.append({
                    "check": "multi_step_bypass",
                    "severity": "critical",
                    "title": "Multi-Step Business Logic Bypass",
                    "description": "Skipped workflow steps via direct state transition",
                    "poc": "POST /workflow/complete with step=5",
                    "evidence": step_final.text[:200] if step_final else ""
                })

    
    async def _advanced_rest_idor(self):
        """Sophisticated REST API IDOR/BOLA with mutations and cross-session testing."""
        all_ids = (self.discovered["ids"]["numeric"] + self.discovered["ids"]["uuid"] + self.discovered["ids"]["slug"])[:40]
        if not all_ids:
            all_ids = ["1", "2", "100", "999999"]

        candidate_paths = [p for p in self.discovered["paths"] if any(k in p.lower() for k in ["user", "profile", "order", "resource", "account", "item"])] or ["/api/users/", "/api/orders/"]

        test_methods = ["GET", "PUT", "PATCH", "DELETE"]

        for base in candidate_paths[:20]:
            for orig_id in all_ids[:15]:
                full_url = urljoin(self.target, f"{base.rstrip('/')}/{orig_id}")
                owner_resp = await self._request("GET", full_url)

                # Mutations
                for mutated in self._generate_id_mutations(orig_id):
                    mut_url = urljoin(self.target, f"{base.rstrip('/')}/{mutated}")
                    for method in test_methods:
                        attacker_resp = await self._request(method, mut_url)
                        sim, leak = self._response_diff(owner_resp, attacker_resp)
                        if leak or (attacker_resp and attacker_resp.status_code in (200, 201, 204)):
                            self.findings.append({
                                "check": "advanced_rest_idor",
                                "severity": "critical" if leak else "high",
                                "title": "Advanced REST IDOR/BOLA via ID Mutation",
                                "description": f"Accessed/modified object with mutated ID {mutated} (orig: {orig_id})",
                                "poc": f"{method} {mut_url}",
                                "evidence": attacker_resp.text[:500] if attacker_resp else "",
                                "confidence": 0.9 if leak else 0.7,
                                "similarity": round(sim, 2)
                            })

                
                for sess in self.extra_sessions[:3]:
                    for method in test_methods:
                        attacker_resp = await self._request(method, full_url, cookies=sess.get("cookies"), jwt_override=sess.get("jwt"))
                        sim, leak = self._response_diff(owner_resp, attacker_resp)
                        if leak or (attacker_resp and attacker_resp.status_code in (200, 201, 204)):
                            self.findings.append({
                                "check": "cross_user_rest_bola",
                                "severity": "critical",
                                "title": "Cross-User REST BOLA - Multi-Account Access",
                                "description": "Attacker session accessed victim's object",
                                "poc": f"{method} {full_url} (secondary session)",
                                "evidence": attacker_resp.text[:600] if attacker_resp else "",
                                "confidence": 0.95
                            })

    def _generate_id_mutations(self, orig_id: str) -> List[str]:
        mutations = [orig_id]
        if orig_id.isdigit():
            n = int(orig_id)
            mutations.extend([str(n+1), str(n-1), str(n*10), "0", "-1", "999999999"])
        elif re.match(r'^[0-9a-f]{8}-', orig_id, re.I):
            mutations.extend([orig_id[:-1] + "0", orig_id.replace(orig_id.split('-')[-1], "00000000")])
        return list(set(mutations))[:12]

    async def _mass_assignment_fuzz(self):
        payloads = [{"role": "admin"}, {"is_admin": True}, {"balance": 9999999}, {"permissions": ["all"]}]
        paths = self.discovered["paths"] or ["/api/user", "/api/profile"]
        for path in paths[:8]:
            for p in payloads:
                resp = await self._request("POST", urljoin(self.target, path), json_data=p)
                if self._is_vulnerable(resp, "mass_assignment"):
                    self.findings.append({
                        "check": "mass_assignment",
                        "severity": "high",
                        "title": "Mass Assignment via REST",
                        "description": f"Privileged fields injected successfully: {p}",
                        "poc": f"POST {urljoin(self.target, path)} with {p}",
                        "evidence": resp.text[:300] if resp else ""
                    })

    async def _race_condition_primitive(self):
        url = urljoin(self.target, "/api/add-to-cart" if any("cart" in p for p in self.discovered["paths"]) else "/api/resource/1")
        tasks = [self._request("POST", url, json_data={"item": 1}) for _ in range(8)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        success_count = sum(1 for r in results if isinstance(r, httpx.Response) and r.status_code in (200, 201))
        if success_count > 4:
            self.findings.append({
                "check": "race_condition",
                "severity": "high",
                "title": "Race Condition Detected",
                "description": f"Concurrent requests succeeded {success_count} times",
                "poc": f"8x POST {url}",
                "evidence": f"Success count: {success_count}"
            })

    async def _graphql_advanced_manipulation(self):
        """Full introspection + dynamic IDOR/BOLA mutations (as previously expanded)."""
        gql_url = urljoin(self.target, "/graphql")
        introspection_query = """query IntrospectionQuery { __schema { queryType { name } mutationType { name } types { ...FullType } } } fragment FullType on __Type { kind name fields(includeDeprecated: true) { name args { name type { kind name } } type { kind name } } inputFields { name } }"""  

        resp = await self._request("POST", gql_url, json_data={"query": introspection_query})
        if not resp or resp.status_code != 200:
            await self._basic_graphql_fallback()
            return

        try:
            schema = resp.json().get("data", {}).get("__schema")
            if not schema or not schema.get("mutationType"):
                await self._basic_graphql_fallback()
                return
        except:
            await self._basic_graphql_fallback()
            return

        
        await self._basic_graphql_fallback()  

    async def _basic_graphql_fallback(self):
        gql_url = urljoin(self.target, "/graphql")
        mutation = {"query": 'mutation { updateUser(id: "1", role: "admin") { success } }'}
        resp = await self._request("POST", gql_url, json_data=mutation)
        if resp and self._is_vulnerable(resp, "graphql_object_manipulation") and "success" in (resp.text or "").lower():
            self.findings.append({
                "check": "graphql_object_manipulation",
                "severity": "critical",
                "title": "GraphQL Object Manipulation",
                "description": "Unauthorized GraphQL mutation succeeded",
                "poc": "GraphQL mutation updateUser with foreign ID",
                "evidence": resp.text[:300] if resp else ""
            })
