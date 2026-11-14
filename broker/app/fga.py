"""Thin OpenFGA client over the REST API (same approach as scripts/load_store.py).

POST /stores/{store_id}/check returns {"allowed": bool}.
"""

from __future__ import annotations

import httpx


class PolicyEngineError(Exception):
    """OpenFGA unreachable or returned an error. The gate fails closed on this."""


class FGAClient:
    def __init__(self, api_url: str, store_id: str, model_id: str) -> None:
        self._store_id = store_id
        self._model_id = model_id
        self._http = httpx.AsyncClient(base_url=api_url, timeout=3.0)

    async def check(self, user: str, relation: str, obj: str, context: dict) -> bool:
        body = {
            "authorization_model_id": self._model_id,
            "tuple_key": {"user": user, "relation": relation, "object": obj},
            "context": context,
        }
        try:
            resp = await self._http.post(f"/stores/{self._store_id}/check", json=body)
        except httpx.HTTPError as exc:
            raise PolicyEngineError(f"OpenFGA unreachable: {exc}") from exc
        if resp.status_code != 200:
            raise PolicyEngineError(f"OpenFGA check failed ({resp.status_code}): {resp.text[:200]}")
        return bool(resp.json().get("allowed", False))

    async def ping(self) -> bool:
        try:
            resp = await self._http.get(f"/stores/{self._store_id}")
            return resp.status_code == 200
        except httpx.HTTPError:
            return False

    async def close(self) -> None:
        await self._http.aclose()
