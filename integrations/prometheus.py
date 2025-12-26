from __future__ import annotations

from typing import Any, Dict, Optional

import requests


def prometheus_instant_query(
    *,
    base_url: str,
    query: str,
    auth_type: str = "none",
    bearer_token: Optional[str] = None,
    timeout_s: int = 15,
) -> Dict[str, Any]:
    b = (base_url or "").rstrip("/")
    q = (query or "").strip()
    if not b:
        return {"status": "error", "message": "base_url is required"}
    if not q:
        return {"status": "error", "message": "query is required"}

    headers: Dict[str, str] = {}
    if (auth_type or "none").lower() == "bearer" and bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"

    try:
        resp = requests.get(
            f"{b}/api/v1/query",
            params={"query": q},
            headers=headers,
            timeout=timeout_s,
        )
        resp.raise_for_status()
        body = resp.json() or {}
        if body.get("status") != "success":
            return {"status": "error", "message": "Prometheus returned non-success", "details": body}
        return {"status": "ok", "data": body.get("data")}
    except requests.HTTPError as e:
        return {"status": "error", "message": f"Prometheus HTTP error: {str(e)}", "details": _safe_json(resp)}
    except Exception as e:
        return {"status": "error", "message": f"Prometheus request failed: {str(e)}"}


def _safe_json(resp: Any) -> Any:
    try:
        return resp.json()
    except Exception:
        try:
            return getattr(resp, "text", None)
        except Exception:
            return None
