from __future__ import annotations

from typing import Any, Dict, List, Optional

import requests
from requests.auth import HTTPBasicAuth

from .infisical import get_many, set_many


def get_jira_config(mail: str) -> Dict[str, Optional[str]]:
    vals = get_many(
        mail,
        (
            "JIRA_BASE_URL",
            "JIRA_EMAIL",
            "JIRA_API_TOKEN",
        ),
    )
    return {
        "base_url": (vals.get("JIRA_BASE_URL") or "").rstrip("/"),
        "email": vals.get("JIRA_EMAIL") or mail,
        "api_token": vals.get("JIRA_API_TOKEN"),
    }


def set_jira_config(
    mail: str,
    *,
    base_url: Optional[str] = None,
    email: Optional[str] = None,
    api_token: Optional[str] = None,
) -> None:
    set_many(
        mail,
        {
            "JIRA_BASE_URL": base_url,
            "JIRA_EMAIL": email,
            "JIRA_API_TOKEN": api_token,
        },
    )


def jira_search_issues(
    *,
    mail: str,
    jql: str,
    fields: Optional[List[str]] = None,
    max_results: int = 10,
) -> Dict[str, Any]:
    cfg = get_jira_config(mail)
    if not cfg.get("base_url") or not cfg.get("api_token") or not cfg.get("email"):
        return {"status": "not_configured", "message": "Jira is not configured (base_url/email/api_token)"}

    base_url = cfg["base_url"].rstrip("/")
    auth = HTTPBasicAuth(cfg["email"], cfg["api_token"])  # Jira Cloud basic auth

    payload: Dict[str, Any] = {
        "jql": (jql or "").strip(),
        "maxResults": max(1, min(int(max_results), 50)),
    }
    if fields:
        payload["fields"] = fields

    if not payload["jql"]:
        return {"status": "error", "message": "jql is required"}

    try:
        resp = requests.post(
            f"{base_url}/rest/api/3/search",
            json=payload,
            auth=auth,
            headers={"Accept": "application/json"},
            timeout=25,
        )
        resp.raise_for_status()
        body = resp.json() or {}
        issues = body.get("issues") or []
        items: List[Dict[str, Any]] = []
        for it in issues:
            f = it.get("fields") or {}
            items.append(
                {
                    "key": it.get("key"),
                    "id": it.get("id"),
                    "summary": f.get("summary"),
                    "status": (f.get("status") or {}).get("name") if isinstance(f.get("status"), dict) else f.get("status"),
                    "issuetype": (f.get("issuetype") or {}).get("name") if isinstance(f.get("issuetype"), dict) else f.get("issuetype"),
                    "priority": (f.get("priority") or {}).get("name") if isinstance(f.get("priority"), dict) else f.get("priority"),
                    "assignee": (f.get("assignee") or {}).get("displayName") if isinstance(f.get("assignee"), dict) else f.get("assignee"),
                    "reporter": (f.get("reporter") or {}).get("displayName") if isinstance(f.get("reporter"), dict) else f.get("reporter"),
                    "updated": f.get("updated"),
                    "created": f.get("created"),
                }
            )
        return {
            "status": "ok",
            "jql": payload["jql"],
            "total": body.get("total"),
            "items": items,
        }
    except requests.HTTPError as e:
        return {"status": "error", "message": f"Jira API error: {str(e)}", "details": _safe_json(resp)}
    except Exception as e:
        return {"status": "error", "message": f"Jira request failed: {str(e)}"}


def jira_get_issue(
    *,
    mail: str,
    issue_key: str,
    fields: Optional[List[str]] = None,
) -> Dict[str, Any]:
    cfg = get_jira_config(mail)
    if not cfg.get("base_url") or not cfg.get("api_token") or not cfg.get("email"):
        return {"status": "not_configured", "message": "Jira is not configured (base_url/email/api_token)"}

    base_url = cfg["base_url"].rstrip("/")
    auth = HTTPBasicAuth(cfg["email"], cfg["api_token"])

    params: Dict[str, Any] = {}
    if fields:
        params["fields"] = ",".join(fields)

    try:
        resp = requests.get(
            f"{base_url}/rest/api/3/issue/{issue_key}",
            params=params,
            auth=auth,
            headers={"Accept": "application/json"},
            timeout=25,
        )
        resp.raise_for_status()
        it = resp.json() or {}
        f = it.get("fields") or {}
        return {
            "status": "ok",
            "issue": {
                "key": it.get("key"),
                "id": it.get("id"),
                "summary": f.get("summary"),
                "description": f.get("description"),
                "status": (f.get("status") or {}).get("name") if isinstance(f.get("status"), dict) else f.get("status"),
                "priority": (f.get("priority") or {}).get("name") if isinstance(f.get("priority"), dict) else f.get("priority"),
                "issuetype": (f.get("issuetype") or {}).get("name") if isinstance(f.get("issuetype"), dict) else f.get("issuetype"),
                "assignee": (f.get("assignee") or {}).get("displayName") if isinstance(f.get("assignee"), dict) else f.get("assignee"),
                "reporter": (f.get("reporter") or {}).get("displayName") if isinstance(f.get("reporter"), dict) else f.get("reporter"),
                "updated": f.get("updated"),
                "created": f.get("created"),
            },
        }
    except requests.HTTPError as e:
        return {"status": "error", "message": f"Jira API error: {str(e)}", "details": _safe_json(resp)}
    except Exception as e:
        return {"status": "error", "message": f"Jira request failed: {str(e)}"}


def _safe_json(resp: Any) -> Any:
    try:
        return resp.json()
    except Exception:
        try:
            return getattr(resp, "text", None)
        except Exception:
            return None
