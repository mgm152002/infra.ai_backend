from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

import requests

from .infisical import get_many, set_many


DEFAULT_GITHUB_API_BASE_URL = "https://api.github.com"


def get_github_config(mail: str) -> Dict[str, Optional[str]]:
    vals = get_many(
        mail,
        (
            "GITHUB_TOKEN",
            "GITHUB_BASE_URL",
            "GITHUB_DEFAULT_OWNER",
            "GITHUB_DEFAULT_REPO",
        ),
    )
    return {
        "token": vals.get("GITHUB_TOKEN"),
        "base_url": (vals.get("GITHUB_BASE_URL") or DEFAULT_GITHUB_API_BASE_URL).rstrip("/"),
        "default_owner": vals.get("GITHUB_DEFAULT_OWNER"),
        "default_repo": vals.get("GITHUB_DEFAULT_REPO"),
    }


def set_github_config(
    mail: str,
    *,
    token: Optional[str] = None,
    base_url: Optional[str] = None,
    default_owner: Optional[str] = None,
    default_repo: Optional[str] = None,
) -> None:
    set_many(
        mail,
        {
            "GITHUB_TOKEN": token,
            "GITHUB_BASE_URL": base_url,
            "GITHUB_DEFAULT_OWNER": default_owner,
            "GITHUB_DEFAULT_REPO": default_repo,
        },
    )


def _github_headers(token: str) -> Dict[str, str]:
    return {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def github_search_issues(
    *,
    mail: str,
    query: str,
    owner: Optional[str] = None,
    repo: Optional[str] = None,
    max_results: int = 10,
) -> Dict[str, Any]:
    cfg = get_github_config(mail)
    token = cfg.get("token")
    if not token:
        return {"status": "not_configured", "message": "GitHub token is not configured"}

    base_url = (cfg.get("base_url") or DEFAULT_GITHUB_API_BASE_URL).rstrip("/")

    q = (query or "").strip()
    if not q:
        return {"status": "error", "message": "query is required"}

    eff_owner = owner or cfg.get("default_owner")
    eff_repo = repo or cfg.get("default_repo")
    if eff_owner and eff_repo:
        # Avoid double repo: spec if user already included it
        if not re.search(r"\brepo:\S+", q):
            q = f"repo:{eff_owner}/{eff_repo} {q}".strip()

    try:
        resp = requests.get(
            f"{base_url}/search/issues",
            headers=_github_headers(token),
            params={"q": q, "per_page": max(1, min(int(max_results), 50))},
            timeout=20,
        )
        resp.raise_for_status()
        body = resp.json() or {}
        items = body.get("items") or []
        results: List[Dict[str, Any]] = []
        for it in items:
            results.append(
                {
                    "title": it.get("title"),
                    "state": it.get("state"),
                    "url": it.get("html_url"),
                    "number": it.get("number"),
                    "repository_url": it.get("repository_url"),
                    "created_at": it.get("created_at"),
                    "updated_at": it.get("updated_at"),
                    "user": (it.get("user") or {}).get("login"),
                    "labels": [l.get("name") for l in (it.get("labels") or []) if isinstance(l, dict)],
                }
            )
        return {
            "status": "ok",
            "query": q,
            "total_count": body.get("total_count"),
            "items": results,
        }
    except requests.HTTPError as e:
        return {"status": "error", "message": f"GitHub API error: {str(e)}", "details": _safe_json(resp)}
    except Exception as e:
        return {"status": "error", "message": f"GitHub request failed: {str(e)}"}


def github_get_issue(
    *,
    mail: str,
    owner: str,
    repo: str,
    number: int,
) -> Dict[str, Any]:
    cfg = get_github_config(mail)
    token = cfg.get("token")
    if not token:
        return {"status": "not_configured", "message": "GitHub token is not configured"}

    base_url = (cfg.get("base_url") or DEFAULT_GITHUB_API_BASE_URL).rstrip("/")

    try:
        resp = requests.get(
            f"{base_url}/repos/{owner}/{repo}/issues/{int(number)}",
            headers=_github_headers(token),
            timeout=20,
        )
        resp.raise_for_status()
        it = resp.json() or {}
        return {
            "status": "ok",
            "item": {
                "title": it.get("title"),
                "state": it.get("state"),
                "url": it.get("html_url"),
                "number": it.get("number"),
                "created_at": it.get("created_at"),
                "updated_at": it.get("updated_at"),
                "user": (it.get("user") or {}).get("login"),
                "labels": [l.get("name") for l in (it.get("labels") or []) if isinstance(l, dict)],
                "body": it.get("body"),
            },
        }
    except requests.HTTPError as e:
        return {"status": "error", "message": f"GitHub API error: {str(e)}", "details": _safe_json(resp)}
    except Exception as e:
        return {"status": "error", "message": f"GitHub request failed: {str(e)}"}


def _safe_json(resp: Any) -> Any:
    try:
        return resp.json()
    except Exception:
        try:
            return getattr(resp, "text", None)
        except Exception:
            return None
