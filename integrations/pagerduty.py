from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

import requests

from .infisical import get_many, set_many


PAGERDUTY_API_BASE_URL = "https://api.pagerduty.com"


def get_pagerduty_config(mail: str) -> Dict[str, Optional[str]]:
    vals = get_many(
        mail,
        (
            "PAGERDUTY_API_TOKEN",
            # Optional scoping fields (comma-separated)
            "PAGERDUTY_SERVICE_IDS",
            "PAGERDUTY_TEAM_IDS",
        ),
    )
    return {
        "api_token": vals.get("PAGERDUTY_API_TOKEN"),
        "service_ids": vals.get("PAGERDUTY_SERVICE_IDS"),
        "team_ids": vals.get("PAGERDUTY_TEAM_IDS"),
    }


def set_pagerduty_config(
    mail: str,
    *,
    api_token: Optional[str] = None,
    service_ids: Optional[str] = None,
    team_ids: Optional[str] = None,
) -> None:
    set_many(
        mail,
        {
            "PAGERDUTY_API_TOKEN": api_token,
            "PAGERDUTY_SERVICE_IDS": service_ids,
            "PAGERDUTY_TEAM_IDS": team_ids,
        },
    )


def _pd_headers(token: str) -> Dict[str, str]:
    return {
        "Accept": "application/vnd.pagerduty+json;version=2",
        "Authorization": f"Token token={token}",
        "Content-Type": "application/json",
    }


def pagerduty_list_incidents(
    *,
    mail: str,
    statuses: Optional[List[str]] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    limit: int = 25,
) -> Dict[str, Any]:
    cfg = get_pagerduty_config(mail)
    token = cfg.get("api_token")
    if not token:
        return {"status": "not_configured", "message": "PagerDuty API token is not configured"}

    st = statuses or ["triggered", "acknowledged"]
    lim = max(1, min(int(limit), 100))

    params: Dict[str, Any] = {"limit": lim}
    for s in st:
        params.setdefault("statuses[]", []).append(s)

    # Optional narrowing
    if since:
        params["since"] = since
    if until:
        params["until"] = until

    # If user stored scoping fields, apply them by default
    service_ids = (cfg.get("service_ids") or "").strip()
    team_ids = (cfg.get("team_ids") or "").strip()
    if service_ids:
        for sid in [s.strip() for s in service_ids.split(",") if s.strip()]:
            params.setdefault("service_ids[]", []).append(sid)
    if team_ids:
        for tid in [t.strip() for t in team_ids.split(",") if t.strip()]:
            params.setdefault("team_ids[]", []).append(tid)

    try:
        resp = requests.get(
            f"{PAGERDUTY_API_BASE_URL}/incidents",
            headers=_pd_headers(token),
            params=params,
            timeout=25,
        )
        resp.raise_for_status()
        body = resp.json() or {}
        incs = body.get("incidents") or []
        items: List[Dict[str, Any]] = []
        for it in incs:
            items.append(
                {
                    "id": it.get("id"),
                    "incident_number": it.get("incident_number"),
                    "title": it.get("title"),
                    "status": it.get("status"),
                    "urgency": it.get("urgency"),
                    "created_at": it.get("created_at"),
                    "html_url": it.get("html_url"),
                    "service": (it.get("service") or {}).get("summary") if isinstance(it.get("service"), dict) else it.get("service"),
                    "assigned_via": it.get("assigned_via"),
                }
            )
        return {
            "status": "ok",
            "items": items,
            "limit": lim,
            "queried_at": datetime.utcnow().isoformat(),
        }
    except requests.HTTPError as e:
        return {"status": "error", "message": f"PagerDuty API error: {str(e)}", "details": _safe_json(resp)}
    except Exception as e:
        return {"status": "error", "message": f"PagerDuty request failed: {str(e)}"}


def pagerduty_get_incident(*, mail: str, incident_id: str) -> Dict[str, Any]:
    cfg = get_pagerduty_config(mail)
    token = cfg.get("api_token")
    if not token:
        return {"status": "not_configured", "message": "PagerDuty API token is not configured"}

    if not (incident_id or "").strip():
        return {"status": "error", "message": "incident_id is required"}

    try:
        resp = requests.get(
            f"{PAGERDUTY_API_BASE_URL}/incidents/{incident_id}",
            headers=_pd_headers(token),
            timeout=25,
        )
        resp.raise_for_status()
        body = resp.json() or {}
        it = body.get("incident") or {}
        return {"status": "ok", "incident": it}
    except requests.HTTPError as e:
        return {"status": "error", "message": f"PagerDuty API error: {str(e)}", "details": _safe_json(resp)}
    except Exception as e:
        return {"status": "error", "message": f"PagerDuty request failed: {str(e)}"}


def _safe_json(resp: Any) -> Any:
    try:
        return resp.json()
    except Exception:
        try:
            return getattr(resp, "text", None)
        except Exception:
            return None
