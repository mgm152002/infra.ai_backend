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



def github_search_commits(
    *,
    mail: str,
    query: str,
    owner: Optional[str] = None,
    repo: Optional[str] = None,
    max_results: int = 10,
) -> Dict[str, Any]:
    """Search GitHub commits (commit messages and metadata) for the given query.

    If `owner`/`repo` are not provided, fall back to the user's configured
    `GITHUB_DEFAULT_OWNER`/`GITHUB_DEFAULT_REPO`.
    """
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

    headers = _github_headers(token)
    # GitHub's commit search API historically required a preview Accept header.
    # This is backwards compatible for other endpoints as well.
    headers["Accept"] = "application/vnd.github.cloak-preview+json"

    try:
        resp = requests.get(
            f"{base_url}/search/commits",
            headers=headers,
            params={"q": q, "per_page": max(1, min(int(max_results), 50))},
            timeout=20,
        )
        resp.raise_for_status()
        body = resp.json() or {}
        items = body.get("items") or []
        results: List[Dict[str, Any]] = []
        for it in items:
            commit = it.get("commit") or {}
            author_info = commit.get("author") or {}
            committer_info = commit.get("committer") or {}
            repo_info = it.get("repository") or {}
            results.append(
                {
                    "sha": it.get("sha"),
                    "url": it.get("html_url"),
                    "repository": repo_info.get("full_name"),
                    "message": commit.get("message"),
                    "author_name": author_info.get("name"),
                    "author_email": author_info.get("email"),
                    "author_date": author_info.get("date") or committer_info.get("date"),
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
    include_diff: bool = False,
    max_files: int = 20,
    max_patch_bytes: int = 20000,
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
        is_pr = bool(it.get("pull_request"))
        diff: Optional[Dict[str, Any]] = None

        if include_diff and is_pr:
            try:
                files_resp = requests.get(
                    f"{base_url}/repos/{owner}/{repo}/pulls/{int(number)}/files",
                    headers=_github_headers(token),
                    params={"per_page": max(1, min(int(max_files), 100))},
                    timeout=20,
                )
                files_resp.raise_for_status()
                files_body = files_resp.json() or []
                diff = _build_diff_summary(
                    files_body,
                    max_files=max_files,
                    max_patch_bytes=max_patch_bytes,
                )
            except requests.HTTPError as e:
                diff = {
                    "status": "error",
                    "message": f"GitHub API error when fetching PR diff: {str(e)}",
                    "details": _safe_json(files_resp),
                }
            except Exception as e:
                diff = {
                    "status": "error",
                    "message": f"Failed to fetch PR diff: {str(e)}",
                }

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
                "is_pull_request": is_pr,
                "diff": diff,
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


def _build_diff_summary(
    files: List[Dict[str, Any]],
    *,
    max_files: int,
    max_patch_bytes: Optional[int],
) -> Dict[str, Any]:
    """Normalize and size-bound GitHub diff file metadata.

    The input ``files`` list should be the raw ``files`` array returned by the
    GitHub API for either commits or pull requests.

    ``max_files`` limits how many files are returned.
    ``max_patch_bytes`` limits the total size of all patches combined. When the
    limit is exceeded, remaining patches are truncated and ``patch_truncated``
    is set to True on the affected files.
    """
    try:
        max_files_int = max(1, min(int(max_files), 300))
    except Exception:
        max_files_int = 20

    files = files or []
    total_files = len(files)
    selected = list(files)[:max_files_int]

    if max_patch_bytes is None:
        bytes_limit: Optional[int] = None
    else:
        try:
            bytes_limit = max(0, int(max_patch_bytes))
        except Exception:
            bytes_limit = 20000

    used_bytes = 0
    out_files: List[Dict[str, Any]] = []

    for f in selected:
        patch_full = f.get("patch") or ""
        patch = patch_full
        patch_truncated = False

        if bytes_limit is not None:
            remaining = bytes_limit - used_bytes
            if remaining <= 0:
                patch = ""
                patch_truncated = True
            elif len(patch_full) > remaining:
                patch = patch_full[:remaining]
                patch_truncated = True
                used_bytes += remaining
            else:
                used_bytes += len(patch_full)

        out_files.append(
            {
                "filename": f.get("filename"),
                "status": f.get("status"),
                "additions": f.get("additions"),
                "deletions": f.get("deletions"),
                "changes": f.get("changes"),
                "patch": patch,
                "patch_truncated": patch_truncated,
            }
        )

    return {
        "status": "ok",
        "files": out_files,
        "total_files": total_files,
        "returned_files": len(out_files),
        "has_more_files": total_files > len(out_files),
        "max_files": max_files_int,
        "max_patch_bytes": bytes_limit,
    }



def github_get_commit(
    *,
    mail: str,
    owner: str,
    repo: str,
    sha: str,
    include_diff: bool = False,
    max_files: int = 20,
    max_patch_bytes: int = 20000,
) -> Dict[str, Any]:
    cfg = get_github_config(mail)
    token = cfg.get("token")
    if not token:
        return {"status": "not_configured", "message": "GitHub token is not configured"}

    base_url = (cfg.get("base_url") or DEFAULT_GITHUB_API_BASE_URL).rstrip("/")

    try:
        resp = requests.get(
            f"{base_url}/repos/{owner}/{repo}/commits/{sha}",
            headers=_github_headers(token),
            timeout=20,
        )
        resp.raise_for_status()
        body = resp.json() or {}
        commit = body.get("commit") or {}
        author_info = commit.get("author") or {}
        committer_info = commit.get("committer") or {}
        stats = body.get("stats") or {}
        files = body.get("files") or []

        diff: Optional[Dict[str, Any]] = None
        if include_diff and files:
            diff = _build_diff_summary(
                files,
                max_files=max_files,
                max_patch_bytes=max_patch_bytes,
            )

        return {
            "status": "ok",
            "item": {
                "sha": body.get("sha"),
                "url": body.get("html_url"),
                "message": commit.get("message"),
                "author_name": author_info.get("name"),
                "author_email": author_info.get("email"),
                "author_date": author_info.get("date") or committer_info.get("date"),
                "stats": {
                    "additions": stats.get("additions"),
                    "deletions": stats.get("deletions"),
                    "total": stats.get("total"),
                },
                "diff": diff,
            },
        }
    except requests.HTTPError as e:
        return {"status": "error", "message": f"GitHub API error: {str(e)}", "details": _safe_json(resp)}
    except Exception as e:
        return {"status": "error", "message": f"GitHub request failed: {str(e)}"}
