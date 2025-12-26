from __future__ import annotations

from typing import Any, Dict, List, Optional

import requests
from requests.auth import HTTPBasicAuth

from .infisical import get_many, set_many


def get_confluence_config(mail: str) -> Dict[str, Optional[str]]:
    vals = get_many(
        mail,
        (
            "CONFLUENCE_BASE_URL",
            "CONFLUENCE_EMAIL",
            "CONFLUENCE_API_TOKEN",
        ),
    )
    return {
        # Typical: https://your-domain.atlassian.net/wiki
        "base_url": (vals.get("CONFLUENCE_BASE_URL") or "").rstrip("/"),
        "email": vals.get("CONFLUENCE_EMAIL") or mail,
        "api_token": vals.get("CONFLUENCE_API_TOKEN"),
    }


def set_confluence_config(
    mail: str,
    *,
    base_url: Optional[str] = None,
    email: Optional[str] = None,
    api_token: Optional[str] = None,
) -> None:
    set_many(
        mail,
        {
            "CONFLUENCE_BASE_URL": base_url,
            "CONFLUENCE_EMAIL": email,
            "CONFLUENCE_API_TOKEN": api_token,
        },
    )


def confluence_search_pages(
    *,
    mail: str,
    cql: str,
    limit: int = 10,
) -> Dict[str, Any]:
    cfg = get_confluence_config(mail)
    if not cfg.get("base_url") or not cfg.get("api_token") or not cfg.get("email"):
        return {"status": "not_configured", "message": "Confluence is not configured (base_url/email/api_token)"}

    base_url = cfg["base_url"].rstrip("/")
    auth = HTTPBasicAuth(cfg["email"], cfg["api_token"])

    if not (cql or "").strip():
        return {"status": "error", "message": "cql is required"}

    try:
        resp = requests.get(
            f"{base_url}/rest/api/search",
            params={"cql": cql, "limit": max(1, min(int(limit), 25))},
            auth=auth,
            headers={"Accept": "application/json"},
            timeout=25,
        )
        resp.raise_for_status()
        body = resp.json() or {}
        results = body.get("results") or []

        items: List[Dict[str, Any]] = []
        for r in results:
            content = (r.get("content") or {}) if isinstance(r, dict) else {}
            space = content.get("space") or {}
            links = content.get("_links") or {}
            webui = links.get("webui")
            full_url = None
            if isinstance(webui, str):
                # Confluence returns relative webui like /spaces/...
                full_url = f"{base_url}{webui}" if webui.startswith("/") else webui

            items.append(
                {
                    "id": content.get("id"),
                    "type": content.get("type"),
                    "title": content.get("title"),
                    "space": space.get("key"),
                    "url": full_url,
                }
            )

        return {
            "status": "ok",
            "cql": cql,
            "items": items,
            "totalSize": body.get("totalSize"),
        }
    except requests.HTTPError as e:
        return {"status": "error", "message": f"Confluence API error: {str(e)}", "details": _safe_json(resp)}
    except Exception as e:
        return {"status": "error", "message": f"Confluence request failed: {str(e)}"}


def confluence_get_page(
    *,
    mail: str,
    page_id: str,
    expand: str = "body.storage,version,space",
) -> Dict[str, Any]:
    cfg = get_confluence_config(mail)
    if not cfg.get("base_url") or not cfg.get("api_token") or not cfg.get("email"):
        return {"status": "not_configured", "message": "Confluence is not configured (base_url/email/api_token)"}

    base_url = cfg["base_url"].rstrip("/")
    auth = HTTPBasicAuth(cfg["email"], cfg["api_token"])

    if not (page_id or "").strip():
        return {"status": "error", "message": "page_id is required"}

    try:
        resp = requests.get(
            f"{base_url}/rest/api/content/{page_id}",
            params={"expand": expand},
            auth=auth,
            headers={"Accept": "application/json"},
            timeout=25,
        )
        resp.raise_for_status()
        body = resp.json() or {}
        storage = (((body.get("body") or {}).get("storage") or {}).get("value"))
        return {
            "status": "ok",
            "page": {
                "id": body.get("id"),
                "type": body.get("type"),
                "title": body.get("title"),
                "space": ((body.get("space") or {}).get("key")),
                "version": ((body.get("version") or {}).get("number")),
                "body_storage": storage,
                "_links": body.get("_links"),
            },
        }
    except requests.HTTPError as e:
        return {"status": "error", "message": f"Confluence API error: {str(e)}", "details": _safe_json(resp)}
    except Exception as e:
        return {"status": "error", "message": f"Confluence request failed: {str(e)}"}


def _safe_json(resp: Any) -> Any:
    try:
        return resp.json()
    except Exception:
        try:
            return getattr(resp, "text", None)
        except Exception:
            return None
