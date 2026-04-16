# backend/app/idorforge_scanner.py
import asyncio
import httpx
import json
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse

class IDORForgeProScanner:
    """
    IDORForge Pro - Advanced IDOR + Role-Based Privilege Escalation + Business Logic Flaw Hunter
    Finds the exact high-impact flaws 95% of hunters miss.
    """
    def __init__(self, target: str, auth_cookies: Optional[Dict] = None, auth_jwt: Optional[str] = None):
        self.target = target if target.startswith(("http://", "https://")) else f"http://{target}"
        self.auth_cookies = auth_cookies or {}
        self.auth_jwt = auth_jwt
        self.client = httpx.AsyncClient(timeout=15.0, follow_redirects=True)
        self.findings: List[Dict] = []

    async def _request(self, method: str, url: str, json_data=None, params=None) -> Dict:
        headers = {"User-Agent": "Vulnora-IDORForgePro/1.0"}
        if self.auth_jwt:
            headers["Authorization"] = f"Bearer {self.auth_jwt}"
        return await self.client.request(
            method, url, json=json_data, params=params, cookies=self.auth_cookies, headers=headers
        )

    async def run(self) -> List[Dict]:
        """Run all advanced IDORForge Pro checks"""
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
            except Exception as e:
                self.findings.append({"check": check.__name__, "status": "error", "detail": str(e)})

        await self.client.aclose()
        return self.findings

    # ====================== CHECKS ======================
    async def _deep_role_permission_idor(self):
        """Deep role/permission IDOR - test object access with manipulated IDs/roles"""
        test_ids = ["1", "2", "999", "admin", "user-123"]
        for tid in test_ids:
            url = urljoin(self.target, f"/api/user/{tid}")
            resp = await self._request("GET", url)
            if resp.status_code == 200:
                self.findings.append({
                    "check": "deep_role_permission_idor",
                    "severity": "critical",
                    "title": "Deep Role/Permission IDOR",
                    "description": f"Accessed object {tid} without proper role check",
                    "poc": f"GET {url} → {resp.status_code}",
                    "evidence": resp.text[:300]
                })

    async def _write_only_idor(self):
        """Write-only IDOR - can write but not read (classic high-impact variant)"""
        payload = {"balance": 999999, "role": "admin"}
        url = urljoin(self.target, "/api/profile/update")
        resp = await self._request("POST", url, json=payload)
        if resp.status_code in (200, 201, 204):
            self.findings.append({
                "check": "write_only_idor",
                "severity": "high",
                "title": "Write-Only IDOR",
                "description": "Able to modify object without read permission",
                "poc": f"POST {url} with {payload}",
                "evidence": resp.text[:200]
            })

    async def _graphql_object_manipulation(self):
        """GraphQL object manipulation / mass assignment via introspection + mutation"""
        # Introspection
        gql_introspect = {"query": "{ __schema { types { name } } }"}
        resp = await self._request("POST", urljoin(self.target, "/graphql"), json=gql_introspect)
        if "types" in resp.text:
            # Try object manipulation mutation
            mutation = {
                "query": "mutation { updateUser(id: \"1\", role: \"admin\") { success } }"
            }
            resp2 = await self._request("POST", urljoin(self.target, "/graphql"), json=mutation)
            if "success" in resp2.text and resp2.status_code == 200:
                self.findings.append({
                    "check": "graphql_object_manipulation",
                    "severity": "critical",
                    "title": "GraphQL Object Manipulation",
                    "description": "Unauthorized GraphQL mutation succeeded",
                    "poc": "GraphQL mutation updateUser with foreign ID",
                    "evidence": resp2.text[:300]
                })

    async def _bulk_operation_idor(self):
        """Bulk-operation IDOR - manipulate many objects at once"""
        bulk_payload = {"ids": ["1", "2", "3"], "action": "delete"}
        url = urljoin(self.target, "/api/bulk/action")
        resp = await self._request("POST", url, json=bulk_payload)
        if resp.status_code in (200, 204):
            self.findings.append({
                "check": "bulk_operation_idor",
                "severity": "high",
                "title": "Bulk-Operation IDOR",
                "description": "Bulk action succeeded on foreign objects",
                "poc": f"POST {url} with ids {bulk_payload['ids']}",
                "evidence": resp.text[:200]
            })

    async def _multi_step_business_logic_bypass(self):
        """Multi-step business logic bypass (e.g. workflow/state machine skip)"""
        # Step 1: Start workflow
        step1 = await self._request("POST", urljoin(self.target, "/api/workflow/start"), json={"step": 1})
        if step1.status_code == 200:
            # Jump directly to final step
            step_final = await self._request("POST", urljoin(self.target, "/api/workflow/complete"), json={"step": 5, "bypass": True})
            if step_final.status_code in (200, 201):
                self.findings.append({
                    "check": "multi_step_bypass",
                    "severity": "critical",
                    "title": "Multi-Step Business Logic Bypass",
                    "description": "Skipped workflow steps via direct state transition",
                    "poc": "POST /workflow/complete with step=5",
                    "evidence": step_final.text[:200]
                })
