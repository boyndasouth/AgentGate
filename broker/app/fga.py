"""Thin OpenFGA client over the REST API (same approach as scripts/load_store.py).

POST /stores/{store_id}/check returns {"allowed": bool}. Day 10 adds write and read
(delegations are tuples written at runtime, so the store must persist: see deploy/render).
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

    async def write(self, writes: list[dict] | None = None, deletes: list[dict] | None = None) -> None:
        """Day 10: write and/or delete tuples in one request (OpenFGA applies it atomically).
        Each tuple: {"user", "relation", "object"} plus an optional "condition" when writing."""
        body: dict = {"authorization_model_id": self._model_id}
        if writes:
            body["writes"] = {"tuple_keys": writes}
        if deletes:
            body["deletes"] = {"tuple_keys": [{k: t[k] for k in ("user", "relation", "object")} for t in deletes]}
        if len(body) == 1:
            return
        try:
            resp = await self._http.post(f"/stores/{self._store_id}/write", json=body)
        except httpx.HTTPError as exc:
            raise PolicyEngineError(f"OpenFGA unreachable: {exc}") from exc
        if resp.status_code != 200:
            raise PolicyEngineError(f"OpenFGA write failed ({resp.status_code}): {resp.text[:200]}")

    async def read(self, tuple_key: dict | None = None) -> list[dict]:
        """Day 10: every stored tuple matching tuple_key (all tuples if None), following pages.
        Returns OpenFGA's tuple keys: {"user", "relation", "object", "condition"?}."""
        out: list[dict] = []
        token = ""
        for _ in range(100):   # 100 pages x 100 tuples is far beyond this demo
            body: dict = {"page_size": 100}
            if tuple_key:
                body["tuple_key"] = tuple_key
            if token:
                body["continuation_token"] = token
            try:
                resp = await self._http.post(f"/stores/{self._store_id}/read", json=body)
            except httpx.HTTPError as exc:
                raise PolicyEngineError(f"OpenFGA unreachable: {exc}") from exc
            if resp.status_code != 200:
                raise PolicyEngineError(f"OpenFGA read failed ({resp.status_code}): {resp.text[:200]}")
            data = resp.json()
            out.extend(t["key"] for t in data.get("tuples", []))
            token = data.get("continuation_token") or ""
            if not token:
                break
        return out

    async def ping(self) -> bool:
        try:
            resp = await self._http.get(f"/stores/{self._store_id}")
            return resp.status_code == 200
        except httpx.HTTPError:
            return False

    async def close(self) -> None:
        await self._http.aclose()
