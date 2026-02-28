"""
GitHub MCP (Model Context Protocol) Server

This module provides an MCP server for GitHub operations using credentials
stored in Infisical. The credentials are user-scoped and retrieved dynamically.

MCP Server Features:
- GitHub repository operations (list, search)
- Issue management (list, get, create, update)
- Pull request operations (list, get, review)
- Commit operations (list, get, compare)
- Branch operations (list, get, create)
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional, Union
from datetime import datetime

import requests

from .infisical import get_many, set_many, user_scoped_secret


# Default GitHub API URL
DEFAULT_GITHUB_API_BASE_URL = "https://api.github.com"
DEFAULT_GITHUB_GRAPHQL_URL = "https://api.github.com/graphql"


def get_github_config(mail: str) -> Dict[str, Optional[str]]:
    """
    Retrieve GitHub configuration from Infisical for a given user.
    
    Args:
        mail: User's email address used as identifier in Infisical
        
    Returns:
        Dictionary containing:
        - token: GitHub personal access token
        - base_url: GitHub API base URL (for GitHub Enterprise)
        - default_owner: Default GitHub owner/organization
        - default_repo: Default GitHub repository
    """
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
    """
    Store GitHub configuration in Infisical for a given user.
    
    Args:
        mail: User's email address used as identifier in Infisical
        token: GitHub personal access token
        base_url: GitHub API base URL (for GitHub Enterprise)
        default_owner: Default GitHub owner/organization
        default_repo: Default GitHub repository
    """
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
    """Generate headers for GitHub API requests."""
    return {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def _safe_json(resp: requests.Response) -> Any:
    """Safely parse JSON from response."""
    try:
        return resp.json()
    except Exception:
        return resp.text


# ============================================================
# MCP Tool Implementations
# ============================================================


def mcp_list_repositories(
    mail: str,
    *,
    owner: Optional[str] = None,
    repo: Optional[str] = None,
    max_results: int = 100,
    page: int = 1,
    all_pages: bool = True,
    affiliation: str = "all",
) -> Dict[str, Any]:
    """
    List GitHub repositories for the authenticated user or organization.
    
    MCP Tool: github_list_repositories
    
    Args:
        mail: User's email address
        owner: Optional organization owner (if not provided, lists user's repos)
        repo: Repository name (optional, not used for listing)
        max_results: Maximum results per page (default 100, max 100)
        page: Page number to fetch (default 1)
        all_pages: If True, fetch all available pages (respects max_results limit)
        affiliation: Filter by affiliation (owner, collaborator, organization_member, all)
                     Default "all" includes repos you own, collaborate on, and org repos
    """
    cfg = get_github_config(mail)
    token = cfg.get("token")
    
    if not token:
        return {
            "status": "not_configured", 
            "message": "GitHub token is not configured. Please configure your GitHub token first.",
            "debug": {"mail": mail, "has_token": False}
        }
    
    base_url = (cfg.get("base_url") or DEFAULT_GITHUB_API_BASE_URL).rstrip("/")
    
    # First, verify the token works by getting authenticated user info
    try:
        user_resp = requests.get(
            f"{base_url}/user",
            headers=_github_headers(token),
            timeout=20,
        )
        user_resp.raise_for_status()
        user_data = user_resp.json()
        username = user_data.get("login")
        user_id = user_data.get("id")
    except Exception as e:
        return {
            "status": "error",
            "message": f"Failed to authenticate with GitHub: {str(e)}",
            "help": "Please verify your GitHub token is valid."
        }
    
    # Get the default owner from config if not provided
    eff_owner = owner or cfg.get("default_owner")
    
    # Debug: log what we're using
    debug_info = {
        "mail": mail,
        "has_token": bool(token),
        "token_prefix": token[:10] + "..." if token else None,
        "github_username": username,
        "github_user_id": user_id,
        "owner_param": owner,
        "default_owner_cfg": cfg.get("default_owner"),
        "eff_owner": eff_owner,
    }
    
    # Determine which endpoint to use and build appropriate URL
    if eff_owner:
        url = f"{base_url}/orgs/{eff_owner}/repos"
    else:
        url = f"{base_url}/user/repos"
    
    debug_info["url"] = url
    
    try:
        # GitHub API allows max 100 per page
        per_page = max(1, min(int(max_results), 100))
        
        results = []
        current_page = page
        
        while True:
            params = {
                "per_page": per_page,
                "sort": "updated",
                "page": current_page,
            }
            
            # Add affiliation filter for user repos (not org repos)
            if not eff_owner:
                params["affiliation"] = affiliation
            
            debug_info["params"] = params
            
            resp = requests.get(
                url,
                headers=_github_headers(token),
                params=params,
                timeout=20,
            )
            
            # Debug: log response status
            debug_info["response_status"] = resp.status_code
            
            resp.raise_for_status()
            
            repos = resp.json() or []
            
            # Debug: log what we got
            debug_info["repos_count"] = len(repos)
            
            if not repos:
                break
            
            for r in repos:
                results.append({
                    "name": r.get("name"),
                    "full_name": r.get("full_name"),
                    "private": r.get("private"),
                    "html_url": r.get("html_url"),
                    "description": r.get("description"),
                    "language": r.get("language"),
                    "stargazers_count": r.get("stargazers_count"),
                    "forks_count": r.get("forks_count"),
                    "updated_at": r.get("updated_at"),
                    "fork": r.get("fork"),
                })
            
            # Stop if not fetching all pages or if we got fewer than per_page results
            if not all_pages or len(repos) < per_page:
                break
            
            current_page += 1
        
        # Check if no repositories were found
        if not results:
            # Try alternative approach: list all repos without affiliation filter
            if not eff_owner and affiliation != "owner":
                # Try with just "owner" affiliation (repos user owns)
                debug_info["trying_alternative"] = True
                alt_params = {
                    "per_page": per_page,
                    "sort": "updated",
                    "page": 1,
                    "affiliation": "owner",
                }
                
                alt_resp = requests.get(
                    f"{base_url}/user/repos",
                    headers=_github_headers(token),
                    params=alt_params,
                    timeout=20,
                )
                
                if alt_resp.status_code == 200:
                    alt_repos = alt_resp.json() or []
                    debug_info["alt_repos_count"] = len(alt_repos)
                    
                    if alt_repos:
                        for r in alt_repos:
                            results.append({
                                "name": r.get("name"),
                                "full_name": r.get("full_name"),
                                "private": r.get("private"),
                                "html_url": r.get("html_url"),
                                "description": r.get("description"),
                                "language": r.get("language"),
                                "stargazers_count": r.get("stargazers_count"),
                                "forks_count": r.get("forks_count"),
                                "updated_at": r.get("updated_at"),
                                "fork": r.get("fork"),
                            })
            
            if not results:
                return {
                    "status": "error",
                    "message": f"No repositories found for user '{username}'.",
                    "debug": debug_info,
                    "help": f"Your GitHub account '{username}' exists but has no accessible repositories. This could mean:\n1. You don't have any repositories\n2. Your token scope is restricted (use a token with 'repo' scope for private repos)\n3. Your fine-grained token doesn't have access to any repositories\n\nTry: Creating a new classic GitHub token with 'repo' scope at https://github.com/settings/tokens"
                }
        
        # Format output as a table
        table_lines = []
        table_lines.append("=" * 150)
        table_lines.append(f"{'Repo':<28} {'Full Name':<38} {'Language':<12} {'Stars':<6} {'Forks':<6} {'Updated UTC':<20} {'URL':<35}")
        table_lines.append("=" * 150)
        
        for r in results:
            name = r.get('name', '')[:26] if r.get('name') else ''
            full_name = r.get('full_name', '')[:36] if r.get('full_name') else ''
            language = r.get('language', '')[:10] if r.get('language') else 'N/A'
            stars = str(r.get('stargazers_count', 0))
            forks = str(r.get('forks_count', 0))
            updated = r.get('updated_at', '')[:19] if r.get('updated_at') else 'N/A'
            url = r.get('html_url', '')[:35] if r.get('html_url') else ''
            
            table_lines.append(f"{name:<28} {full_name:<38} {language:<12} {stars:<6} {forks:<6} {updated:<20} {url:<35}")
        
        table_lines.append("=" * 150)
        table_lines.append(f"Total repositories: {len(results)}")
        
        # Build formatted table string
        formatted_table = "\n".join(table_lines)
        
        return {
            "status": "ok",
            "total_count": len(results),
            "page": page,
            "per_page": per_page,
            "all_pages_fetched": all_pages,
            "affiliation": affiliation,
            "owner": eff_owner,
            "github_user": username,
            "formatted_table": formatted_table,
            "repositories": results,
        }
    except requests.HTTPError as e:
        error_details = _safe_json(resp)
        debug_info["error"] = str(e)
        debug_info["error_details"] = error_details
        
        if resp.status_code == 401:
            return {
                "status": "error",
                "message": "GitHub authentication failed. Please verify your GitHub token is valid and has not expired.",
                "debug": debug_info,
            }
        elif resp.status_code == 403:
            return {
                "status": "error", 
                "message": "GitHub API access forbidden. Your token may lack required scopes. For organization repositories, ensure the token has 'read:org' scope. For private repositories, ensure it has 'repo' scope.",
                "debug": debug_info,
            }
        elif resp.status_code == 404:
            return {
                "status": "error",
                "message": f"Organization '{eff_owner}' not found. Please verify the organization name is correct.",
                "debug": debug_info,
            }
        return {"status": "error", "message": f"GitHub API error: {str(e)}", "debug": debug_info}
    except Exception as e:
        debug_info["error"] = str(e)
        return {"status": "error", "message": f"GitHub request failed: {str(e)}", "debug": debug_info}


def mcp_search_repositories(
    mail: str,
    *,
    query: str,
    max_results: int = 100,
    page: int = 1,
    all_pages: bool = False,
) -> Dict[str, Any]:
    """
    Search GitHub repositories.
    
    MCP Tool: github_search_repositories
    
    Args:
        mail: User's email address
        query: Search query
        max_results: Maximum results per page (default 100, max 100)
        page: Page number to fetch (default 1)
        all_pages: If True, fetch all available pages
    """
    cfg = get_github_config(mail)
    token = cfg.get("token")
    
    if not token:
        return {"status": "not_configured", "message": "GitHub token is not configured"}
    
    base_url = (cfg.get("base_url") or DEFAULT_GITHUB_API_BASE_URL).rstrip("/")
    
    if not query or not query.strip():
        return {"status": "error", "message": "query is required"}
    
    try:
        # GitHub API allows max 100 per page
        per_page = max(1, min(int(max_results), 100))
        
        results = []
        total_count = 0
        current_page = page
        
        while True:
            resp = requests.get(
                f"{base_url}/search/repositories",
                headers=_github_headers(token),
                params={"q": query, "per_page": per_page, "page": current_page},
                timeout=20,
            )
            resp.raise_for_status()
            
            body = resp.json() or {}
            items = body.get("items") or []
            
            if total_count == 0:
                total_count = body.get("total_count", 0)
            
            if not items:
                break
            
            for r in items:
                results.append({
                    "name": r.get("name"),
                    "full_name": r.get("full_name"),
                    "private": r.get("private"),
                    "html_url": r.get("html_url"),
                    "description": r.get("description"),
                    "language": r.get("language"),
                    "stargazers_count": r.get("stargazers_count"),
                    "forks_count": r.get("forks_count"),
                })
            
            # Stop if not fetching all pages or if we got fewer than per_page results
            if not all_pages or len(items) < per_page:
                break
            
            current_page += 1
        
        return {
            "status": "ok",
            "query": query,
            "total_count": total_count,
            "page": page,
            "per_page": per_page,
            "all_pages_fetched": all_pages,
            "repositories": results,
        }
    except requests.HTTPError as e:
        return {"status": "error", "message": f"GitHub API error: {str(e)}", "details": _safe_json(resp)}
    except Exception as e:
        return {"status": "error", "message": f"GitHub request failed: {str(e)}"}


def mcp_list_issues(
    mail: str,
    *,
    owner: Optional[str] = None,
    repo: Optional[str] = None,
    state: str = "open",
    max_results: int = 10,
) -> Dict[str, Any]:
    """
    List issues for a repository.
    
    MCP Tool: github_list_issues
    """
    cfg = get_github_config(mail)
    token = cfg.get("token")
    
    if not token:
        return {"status": "not_configured", "message": "GitHub token is not configured"}
    
    base_url = (cfg.get("base_url") or DEFAULT_GITHUB_API_BASE_URL).rstrip("/")
    
    eff_owner = owner or cfg.get("default_owner")
    eff_repo = repo or cfg.get("default_repo")
    
    if not eff_owner or not eff_repo:
        return {"status": "error", "message": "owner and repo are required (provide explicitly or set defaults)"}
    
    try:
        resp = requests.get(
            f"{base_url}/repos/{eff_owner}/{eff_repo}/issues",
            headers=_github_headers(token),
            params={
                "state": state,
                "per_page": max(1, min(int(max_results), 100)),
                "sort": "updated",
            },
            timeout=20,
        )
        resp.raise_for_status()
        
        issues = resp.json() or []
        results = []
        for issue in issues:
            # Skip pull requests (they appear as issues in GitHub API)
            if issue.get("pull_request"):
                continue
            results.append({
                "number": issue.get("number"),
                "title": issue.get("title"),
                "state": issue.get("state"),
                "html_url": issue.get("html_url"),
                "user": (issue.get("user") or {}).get("login"),
                "labels": [l.get("name") for l in (issue.get("labels") or []) if isinstance(l, dict)],
                "created_at": issue.get("created_at"),
                "updated_at": issue.get("updated_at"),
                "comments": issue.get("comments"),
            })
        
        return {
            "status": "ok",
            "owner": eff_owner,
            "repo": eff_repo,
            "total_count": len(results),
            "issues": results,
        }
    except requests.HTTPError as e:
        return {"status": "error", "message": f"GitHub API error: {str(e)}", "details": _safe_json(resp)}
    except Exception as e:
        return {"status": "error", "message": f"GitHub request failed: {str(e)}"}


def mcp_get_issue(
    mail: str,
    *,
    owner: str,
    repo: str,
    number: int,
) -> Dict[str, Any]:
    """
    Get a specific issue.
    
    MCP Tool: github_get_issue
    """
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
        
        issue = resp.json() or {}
        is_pr = bool(issue.get("pull_request"))
        
        return {
            "status": "ok",
            "issue": {
                "number": issue.get("number"),
                "title": issue.get("title"),
                "state": issue.get("state"),
                "html_url": issue.get("html_url"),
                "user": (issue.get("user") or {}).get("login"),
                "body": issue.get("body"),
                "labels": [l.get("name") for l in (issue.get("labels") or []) if isinstance(l, dict)],
                "assignees": [(a.get("login")) for a in (issue.get("assignees") or [])],
                "created_at": issue.get("created_at"),
                "updated_at": issue.get("updated_at"),
                "closed_at": issue.get("closed_at"),
                "comments": issue.get("comments"),
                "is_pull_request": is_pr,
            },
        }
    except requests.HTTPError as e:
        return {"status": "error", "message": f"GitHub API error: {str(e)}", "details": _safe_json(resp)}
    except Exception as e:
        return {"status": "error", "message": f"GitHub request failed: {str(e)}"}


def mcp_create_issue(
    mail: str,
    *,
    owner: str,
    repo: str,
    title: str,
    body: Optional[str] = None,
    labels: Optional[List[str]] = None,
    assignees: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Create a new issue.
    
    MCP Tool: github_create_issue
    """
    cfg = get_github_config(mail)
    token = cfg.get("token")
    
    if not token:
        return {"status": "not_configured", "message": "GitHub token is not configured"}
    
    base_url = (cfg.get("base_url") or DEFAULT_GITHUB_API_BASE_URL).rstrip("/")
    
    if not title or not title.strip():
        return {"status": "error", "message": "title is required"}
    
    payload: Dict[str, Any] = {"title": title}
    if body:
        payload["body"] = body
    if labels:
        payload["labels"] = labels
    if assignees:
        payload["assignees"] = assignees
    
    try:
        resp = requests.post(
            f"{base_url}/repos/{owner}/{repo}/issues",
            headers=_github_headers(token),
            json=payload,
            timeout=20,
        )
        resp.raise_for_status()
        
        issue = resp.json() or {}
        
        return {
            "status": "ok",
            "message": f"Issue created successfully: #{issue.get('number')}",
            "issue": {
                "number": issue.get("number"),
                "title": issue.get("title"),
                "html_url": issue.get("html_url"),
                "state": issue.get("state"),
            },
        }
    except requests.HTTPError as e:
        return {"status": "error", "message": f"GitHub API error: {str(e)}", "details": _safe_json(resp)}
    except Exception as e:
        return {"status": "error", "message": f"GitHub request failed: {str(e)}"}


def mcp_update_issue(
    mail: str,
    *,
    owner: str,
    repo: str,
    number: int,
    title: Optional[str] = None,
    body: Optional[str] = None,
    state: Optional[str] = None,
    labels: Optional[List[str]] = None,
    assignees: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Update an existing issue.
    
    MCP Tool: github_update_issue
    """
    cfg = get_github_config(mail)
    token = cfg.get("token")
    
    if not token:
        return {"status": "not_configured", "message": "GitHub token is not configured"}
    
    base_url = (cfg.get("base_url") or DEFAULT_GITHUB_API_BASE_URL).rstrip("/")
    
    payload: Dict[str, Any] = {}
    if title:
        payload["title"] = title
    if body is not None:
        payload["body"] = body
    if state:
        payload["state"] = state
    if labels is not None:
        payload["labels"] = labels
    if assignees is not None:
        payload["assignees"] = assignees
    
    if not payload:
        return {"status": "error", "message": "At least one field to update is required"}
    
    try:
        resp = requests.patch(
            f"{base_url}/repos/{owner}/{repo}/issues/{int(number)}",
            headers=_github_headers(token),
            json=payload,
            timeout=20,
        )
        resp.raise_for_status()
        
        issue = resp.json() or {}
        
        return {
            "status": "ok",
            "message": f"Issue #{number} updated successfully",
            "issue": {
                "number": issue.get("number"),
                "title": issue.get("title"),
                "state": issue.get("state"),
                "html_url": issue.get("html_url"),
            },
        }
    except requests.HTTPError as e:
        return {"status": "error", "message": f"GitHub API error: {str(e)}", "details": _safe_json(resp)}
    except Exception as e:
        return {"status": "error", "message": f"GitHub request failed: {str(e)}"}


def mcp_list_pull_requests(
    mail: str,
    *,
    owner: Optional[str] = None,
    repo: Optional[str] = None,
    state: str = "open",
    max_results: int = 10,
) -> Dict[str, Any]:
    """
    List pull requests for a repository.
    
    MCP Tool: github_list_pull_requests
    """
    cfg = get_github_config(mail)
    token = cfg.get("token")
    
    if not token:
        return {"status": "not_configured", "message": "GitHub token is not configured"}
    
    base_url = (cfg.get("base_url") or DEFAULT_GITHUB_API_BASE_URL).rstrip("/")
    
    eff_owner = owner or cfg.get("default_owner")
    eff_repo = repo or cfg.get("default_repo")
    
    if not eff_owner or not eff_repo:
        return {"status": "error", "message": "owner and repo are required"}
    
    try:
        resp = requests.get(
            f"{base_url}/repos/{eff_owner}/{eff_repo}/pulls",
            headers=_github_headers(token),
            params={
                "state": state,
                "per_page": max(1, min(int(max_results), 100)),
                "sort": "updated",
            },
            timeout=20,
        )
        resp.raise_for_status()
        
        prs = resp.json() or []
        results = []
        for pr in prs:
            results.append({
                "number": pr.get("number"),
                "title": pr.get("title"),
                "state": pr.get("state"),
                "html_url": pr.get("html_url"),
                "user": (pr.get("user") or {}).get("login"),
                "head": pr.get("head", {}).get("ref"),
                "base": pr.get("base", {}).get("ref"),
                "created_at": pr.get("created_at"),
                "updated_at": pr.get("updated_at"),
                "merged_at": pr.get("merged_at"),
                "draft": pr.get("draft"),
            })
        
        return {
            "status": "ok",
            "owner": eff_owner,
            "repo": eff_repo,
            "total_count": len(results),
            "pull_requests": results,
        }
    except requests.HTTPError as e:
        return {"status": "error", "message": f"GitHub API error: {str(e)}", "details": _safe_json(resp)}
    except Exception as e:
        return {"status": "error", "message": f"GitHub request failed: {str(e)}"}


def mcp_get_pull_request(
    mail: str,
    *,
    owner: str,
    repo: str,
    number: int,
) -> Dict[str, Any]:
    """
    Get a specific pull request.
    
    MCP Tool: github_get_pull_request
    """
    cfg = get_github_config(mail)
    token = cfg.get("token")
    
    if not token:
        return {"status": "not_configured", "message": "GitHub token is not configured"}
    
    base_url = (cfg.get("base_url") or DEFAULT_GITHUB_API_BASE_URL).rstrip("/")
    
    try:
        resp = requests.get(
            f"{base_url}/repos/{owner}/{repo}/pulls/{int(number)}",
            headers=_github_headers(token),
            timeout=20,
        )
        resp.raise_for_status()
        
        pr = resp.json() or []
        
        return {
            "status": "ok",
            "pull_request": {
                "number": pr.get("number"),
                "title": pr.get("title"),
                "state": pr.get("state"),
                "html_url": pr.get("html_url"),
                "user": (pr.get("user") or {}).get("login"),
                "body": pr.get("body"),
                "head": pr.get("head", {}).get("ref"),
                "base": pr.get("base", {}).get("ref"),
                "draft": pr.get("draft"),
                "merged": pr.get("merged"),
                "mergeable": pr.get("mergeable"),
                "created_at": pr.get("created_at"),
                "updated_at": pr.get("updated_at"),
                "merged_at": pr.get("merged_at"),
            },
        }
    except requests.HTTPError as e:
        return {"status": "error", "message": f"GitHub API error: {str(e)}", "details": _safe_json(resp)}
    except Exception as e:
        return {"status": "error", "message": f"GitHub request failed: {str(e)}"}


def mcp_list_commits(
    mail: str,
    *,
    owner: Optional[str] = None,
    repo: Optional[str] = None,
    max_results: int = 10,
    sha: Optional[str] = None,
    path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    List commits for a repository.
    
    MCP Tool: github_list_commits
    """
    cfg = get_github_config(mail)
    token = cfg.get("token")
    
    if not token:
        return {"status": "not_configured", "message": "GitHub token is not configured"}
    
    base_url = (cfg.get("base_url") or DEFAULT_GITHUB_API_BASE_URL).rstrip("/")
    
    eff_owner = owner or cfg.get("default_owner")
    eff_repo = repo or cfg.get("default_repo")
    
    if not eff_owner or not eff_repo:
        return {"status": "error", "message": "owner and repo are required"}
    
    try:
        params: Dict[str, Any] = {
            "per_page": max(1, min(int(max_results), 100)),
        }
        if sha:
            params["sha"] = sha
        if path:
            params["path"] = path
        
        resp = requests.get(
            f"{base_url}/repos/{eff_owner}/{eff_repo}/commits",
            headers=_github_headers(token),
            params=params,
            timeout=20,
        )
        resp.raise_for_status()
        
        commits = resp.json() or []
        results = []
        for c in commits:
            commit = c.get("commit") or {}
            author_info = commit.get("author") or {}
            results.append({
                "sha": c.get("sha"),
                "html_url": c.get("html_url"),
                "message": commit.get("message"),
                "author_name": author_info.get("name"),
                "author_email": author_info.get("email"),
                "author_date": author_info.get("date"),
                "committer": (c.get("committer") or {}).get("login"),
            })
        
        return {
            "status": "ok",
            "owner": eff_owner,
            "repo": eff_repo,
            "total_count": len(results),
            "commits": results,
        }
    except requests.HTTPError as e:
        return {"status": "error", "message": f"GitHub API error: {str(e)}", "details": _safe_json(resp)}
    except Exception as e:
        return {"status": "error", "message": f"GitHub request failed: {str(e)}"}


def mcp_get_commit(
    mail: str,
    *,
    owner: str,
    repo: str,
    sha: str,
) -> Dict[str, Any]:
    """
    Get a specific commit.
    
    MCP Tool: github_get_commit
    """
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
        
        commit = resp.json() or {}
        commit_info = commit.get("commit") or {}
        author_info = commit_info.get("author") or {}
        committer_info = commit_info.get("committer") or {}
        stats = commit.get("stats") or {}
        
        return {
            "status": "ok",
            "commit": {
                "sha": commit.get("sha"),
                "html_url": commit.get("html_url"),
                "message": commit_info.get("message"),
                "author_name": author_info.get("name"),
                "author_email": author_info.get("email"),
                "author_date": author_info.get("date") or committer_info.get("date"),
                "committer_name": committer_info.get("name"),
                "committer_email": committer_info.get("email"),
                "stats": {
                    "additions": stats.get("additions"),
                    "deletions": stats.get("deletions"),
                    "total": stats.get("total"),
                },
            },
        }
    except requests.HTTPError as e:
        return {"status": "error", "message": f"GitHub API error: {str(e)}", "details": _safe_json(resp)}
    except Exception as e:
        return {"status": "error", "message": f"GitHub request failed: {str(e)}"}


def mcp_list_branches(
    mail: str,
    *,
    owner: Optional[str] = None,
    repo: Optional[str] = None,
) -> Dict[str, Any]:
    """
    List branches for a repository.
    
    MCP Tool: github_list_branches
    """
    cfg = get_github_config(mail)
    token = cfg.get("token")
    
    if not token:
        return {"status": "not_configured", "message": "GitHub token is not configured"}
    
    base_url = (cfg.get("base_url") or DEFAULT_GITHUB_API_BASE_URL).rstrip("/")
    
    eff_owner = owner or cfg.get("default_owner")
    eff_repo = repo or cfg.get("default_repo")
    
    if not eff_owner or not eff_repo:
        return {"status": "error", "message": "owner and repo are required"}
    
    try:
        resp = requests.get(
            f"{base_url}/repos/{eff_owner}/{eff_repo}/branches",
            headers=_github_headers(token),
            params={"per_page": 100},
            timeout=20,
        )
        resp.raise_for_status()
        
        branches = resp.json() or []
        results = []
        for b in branches:
            results.append({
                "name": b.get("name"),
                "protected": b.get("protected"),
                "sha": (b.get("commit") or {}).get("sha"),
            })
        
        return {
            "status": "ok",
            "owner": eff_owner,
            "repo": eff_repo,
            "total_count": len(results),
            "branches": results,
        }
    except requests.HTTPError as e:
        return {"status": "error", "message": f"GitHub API error: {str(e)}", "details": _safe_json(resp)}
    except Exception as e:
        return {"status": "error", "message": f"GitHub request failed: {str(e)}"}


def mcp_get_branch(
    mail: str,
    *,
    owner: str,
    repo: str,
    branch: str,
) -> Dict[str, Any]:
    """
    Get a specific branch.
    
    MCP Tool: github_get_branch
    """
    cfg = get_github_config(mail)
    token = cfg.get("token")
    
    if not token:
        return {"status": "not_configured", "message": "GitHub token is not configured"}
    
    base_url = (cfg.get("base_url") or DEFAULT_GITHUB_API_BASE_URL).rstrip("/")
    
    try:
        resp = requests.get(
            f"{base_url}/repos/{owner}/{repo}/branches/{branch}",
            headers=_github_headers(token),
            timeout=20,
        )
        resp.raise_for_status()
        
        b = resp.json() or {}
        
        return {
            "status": "ok",
            "branch": {
                "name": b.get("name"),
                "protected": b.get("protected"),
                "sha": (b.get("commit") or {}).get("sha"),
                "html_url": (b.get("commit") or {}).get("html_url"),
            },
        }
    except requests.HTTPError as e:
        return {"status": "error", "message": f"GitHub API error: {str(e)}", "details": _safe_json(resp)}
    except Exception as e:
        return {"status": "error", "message": f"GitHub request failed: {str(e)}"}


def mcp_list_workflows(
    mail: str,
    *,
    owner: Optional[str] = None,
    repo: Optional[str] = None,
) -> Dict[str, Any]:
    """
    List GitHub Actions workflows for a repository.
    
    MCP Tool: github_list_workflows
    """
    cfg = get_github_config(mail)
    token = cfg.get("token")
    
    if not token:
        return {"status": "not_configured", "message": "GitHub token is not configured"}
    
    base_url = (cfg.get("base_url") or DEFAULT_GITHUB_API_BASE_URL).rstrip("/")
    
    eff_owner = owner or cfg.get("default_owner")
    eff_repo = repo or cfg.get("default_repo")
    
    if not eff_owner or not eff_repo:
        return {"status": "error", "message": "owner and repo are required"}
    
    try:
        resp = requests.get(
            f"{base_url}/repos/{eff_owner}/{eff_repo}/actions/workflows",
            headers=_github_headers(token),
            params={"per_page": 100},
            timeout=20,
        )
        resp.raise_for_status()
        
        data = resp.json() or {}
        workflows = data.get("workflows") or []
        results = []
        for w in workflows:
            results.append({
                "id": w.get("id"),
                "name": w.get("name"),
                "path": w.get("path"),
                "state": w.get("state"),
                "html_url": w.get("html_url"),
                "created_at": w.get("created_at"),
                "updated_at": w.get("updated_at"),
            })
        
        return {
            "status": "ok",
            "owner": eff_owner,
            "repo": eff_repo,
            "total_count": len(results),
            "workflows": results,
        }
    except requests.HTTPError as e:
        return {"status": "error", "message": f"GitHub API error: {str(e)}", "details": _safe_json(resp)}
    except Exception as e:
        return {"status": "error", "message": f"GitHub request failed: {str(e)}"}


def mcp_list_workflow_runs(
    mail: str,
    *,
    owner: Optional[str] = None,
    repo: Optional[str] = None,
    workflow_id: Optional[int] = None,
    status: Optional[str] = None,
    max_results: int = 10,
) -> Dict[str, Any]:
    """
    List GitHub Actions workflow runs.
    
    MCP Tool: github_list_workflow_runs
    """
    cfg = get_github_config(mail)
    token = cfg.get("token")
    
    if not token:
        return {"status": "not_configured", "message": "GitHub token is not configured"}
    
    base_url = (cfg.get("base_url") or DEFAULT_GITHUB_API_BASE_URL).rstrip("/")
    
    eff_owner = owner or cfg.get("default_owner")
    eff_repo = repo or cfg.get("default_repo")
    
    if not eff_owner or not eff_repo:
        return {"status": "error", "message": "owner and repo are required"}
    
    try:
        if workflow_id:
            url = f"{base_url}/repos/{eff_owner}/{eff_repo}/actions/workflows/{workflow_id}/runs"
        else:
            url = f"{base_url}/repos/{eff_owner}/{eff_repo}/actions/runs"
        
        params: Dict[str, Any] = {
            "per_page": max(1, min(int(max_results), 100)),
        }
        if status:
            params["status"] = status
        
        resp = requests.get(
            url,
            headers=_github_headers(token),
            params=params,
            timeout=20,
        )
        resp.raise_for_status()
        
        data = resp.json() or {}
        runs = data.get("workflow_runs") or []
        results = []
        for r in runs:
            results.append({
                "id": r.get("id"),
                "name": r.get("name"),
                "head_branch": r.get("head_branch"),
                "head_sha": r.get("head_sha"),
                "status": r.get("status"),
                "conclusion": r.get("conclusion"),
                "html_url": r.get("html_url"),
                "created_at": r.get("created_at"),
                "updated_at": r.get("updated_at"),
                "actor": (r.get("actor") or {}).get("login"),
                "run_number": r.get("run_number"),
            })
        
        return {
            "status": "ok",
            "owner": eff_owner,
            "repo": eff_repo,
            "total_count": len(results),
            "workflow_runs": results,
        }
    except requests.HTTPError as e:
        return {"status": "error", "message": f"GitHub API error: {str(e)}", "details": _safe_json(resp)}
    except Exception as e:
        return {"status": "error", "message": f"GitHub request failed: {str(e)}"}


def mcp_get_workflow_run(
    mail: str,
    *,
    owner: str,
    repo: str,
    run_id: int,
) -> Dict[str, Any]:
    """
    Get a specific workflow run.
    
    MCP Tool: github_get_workflow_run
    """
    cfg = get_github_config(mail)
    token = cfg.get("token")
    
    if not token:
        return {"status": "not_configured", "message": "GitHub token is not configured"}
    
    base_url = (cfg.get("base_url") or DEFAULT_GITHUB_API_BASE_URL).rstrip("/")
    
    try:
        resp = requests.get(
            f"{base_url}/repos/{owner}/{repo}/actions/runs/{run_id}",
            headers=_github_headers(token),
            timeout=20,
        )
        resp.raise_for_status()
        
        r = resp.json() or {}
        
        return {
            "status": "ok",
            "workflow_run": {
                "id": r.get("id"),
                "name": r.get("name"),
                "head_branch": r.get("head_branch"),
                "head_sha": r.get("head_sha"),
                "status": r.get("status"),
                "conclusion": r.get("conclusion"),
                "html_url": r.get("html_url"),
                "created_at": r.get("created_at"),
                "updated_at": r.get("updated_at"),
                "actor": (r.get("actor") or {}).get("login"),
                "run_number": r.get("run_number"),
                "event": r.get("event"),
                "triggering_actor": (r.get("triggering_actor") or {}).get("login"),
            },
        }
    except requests.HTTPError as e:
        return {"status": "error", "message": f"GitHub API error: {str(e)}", "details": _safe_json(resp)}
    except Exception as e:
        return {"status": "error", "message": f"GitHub request failed: {str(e)}"}


def mcp_list_actions_artifacts(
    mail: str,
    *,
    owner: Optional[str] = None,
    repo: Optional[str] = None,
    max_results: int = 10,
) -> Dict[str, Any]:
    """
    List artifacts for a repository.
    
    MCP Tool: github_list_artifacts
    """
    cfg = get_github_config(mail)
    token = cfg.get("token")
    
    if not token:
        return {"status": "not_configured", "message": "GitHub token is not configured"}
    
    base_url = (cfg.get("base_url") or DEFAULT_GITHUB_API_BASE_URL).rstrip("/")
    
    eff_owner = owner or cfg.get("default_owner")
    eff_repo = repo or cfg.get("default_repo")
    
    if not eff_owner or not eff_repo:
        return {"status": "error", "message": "owner and repo are required"}
    
    try:
        resp = requests.get(
            f"{base_url}/repos/{eff_owner}/{eff_repo}/actions/artifacts",
            headers=_github_headers(token),
            params={"per_page": max(1, min(int(max_results), 100))},
            timeout=20,
        )
        resp.raise_for_status()
        
        data = resp.json() or {}
        artifacts = data.get("artifacts") or []
        results = []
        for a in artifacts:
            results.append({
                "id": a.get("id"),
                "name": a.get("name"),
                "size_in_bytes": a.get("size_in_bytes"),
                "html_url": a.get("html_url"),
                "expired": a.get("expired"),
                "created_at": a.get("created_at"),
                "expires_at": a.get("expires_at"),
            })
        
        return {
            "status": "ok",
            "owner": eff_owner,
            "repo": eff_repo,
            "total_count": len(results),
            "artifacts": results,
        }
    except requests.HTTPError as e:
        return {"status": "error", "message": f"GitHub API error: {str(e)}", "details": _safe_json(resp)}
    except Exception as e:
        return {"status": "error", "message": f"GitHub request failed: {str(e)}"}


# ============================================================
# MCP Server Definition
# ============================================================

class GitHubMCPServer:
    """
    GitHub MCP Server providing tools for GitHub operations.
    
    This server wraps the GitHub API with credentials from Infisical,
    providing a unified interface for GitHub operations.
    """
    
    def __init__(self):
        self.name = "github"
        self.version = "1.0.0"
        self.description = "GitHub MCP Server - Manage GitHub repositories, issues, PRs, commits, and more"
    
    def get_tools(self) -> List[Dict[str, Any]]:
        """Return list of available MCP tools."""
        return [
            {
                "name": "github_list_repositories",
                "description": "List GitHub repositories for authenticated user or organization",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "owner": {"type": "string", "description": "Organization owner (optional)"},
                        "repo": {"type": "string", "description": "Repository name (optional)"},
                        "max_results": {"type": "integer", "description": "Max results per page (default 100, max 100)", "default": 100},
                        "page": {"type": "integer", "description": "Page number to fetch (default 1)", "default": 1},
                        "all_pages": {"type": "boolean", "description": "Fetch all pages (default true)", "default": true},
                        "affiliation": {"type": "string", "description": "Filter by affiliation: owner, collaborator, organization_member, all (default all)", "default": "all"},
                    },
                },
            },
            {
                "name": "github_search_repositories",
                "description": "Search GitHub repositories",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Search query"},
                        "max_results": {"type": "integer", "description": "Max results per page (default 100, max 100)", "default": 100},
                        "page": {"type": "integer", "description": "Page number to fetch (default 1)", "default": 1},
                        "all_pages": {"type": "boolean", "description": "Fetch all pages (default false)", "default": False},
                    },
                    "required": ["query"],
                },
            },
            {
                "name": "github_list_issues",
                "description": "List issues for a repository",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "owner": {"type": "string", "description": "Repository owner"},
                        "repo": {"type": "string", "description": "Repository name"},
                        "state": {"type": "string", "description": "Issue state (open/closed/all)", "default": "open"},
                        "max_results": {"type": "integer", "description": "Max results (default 10)", "default": 10},
                    },
                },
            },
            {
                "name": "github_get_issue",
                "description": "Get a specific issue",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "owner": {"type": "string", "description": "Repository owner"},
                        "repo": {"type": "string", "description": "Repository name"},
                        "number": {"type": "integer", "description": "Issue number"},
                    },
                    "required": ["owner", "repo", "number"],
                },
            },
            {
                "name": "github_create_issue",
                "description": "Create a new issue",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "owner": {"type": "string", "description": "Repository owner"},
                        "repo": {"type": "string", "description": "Repository name"},
                        "title": {"type": "string", "description": "Issue title"},
                        "body": {"type": "string", "description": "Issue body"},
                        "labels": {"type": "array", "items": {"type": "string"}, "description": "Issue labels"},
                        "assignees": {"type": "array", "items": {"type": "string"}, "description": "Assignees"},
                    },
                    "required": ["owner", "repo", "title"],
                },
            },
            {
                "name": "github_update_issue",
                "description": "Update an existing issue",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "owner": {"type": "string", "description": "Repository owner"},
                        "repo": {"type": "string", "description": "Repository name"},
                        "number": {"type": "integer", "description": "Issue number"},
                        "title": {"type": "string", "description": "New title"},
                        "body": {"type": "string", "description": "New body"},
                        "state": {"type": "string", "description": "New state (open/closed)"},
                        "labels": {"type": "array", "items": {"type": "string"}, "description": "New labels"},
                        "assignees": {"type": "array", "items": {"type": "string"}, "description": "New assignees"},
                    },
                    "required": ["owner", "repo", "number"],
                },
            },
            {
                "name": "github_list_pull_requests",
                "description": "List pull requests for a repository",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "owner": {"type": "string", "description": "Repository owner"},
                        "repo": {"type": "string", "description": "Repository name"},
                        "state": {"type": "string", "description": "PR state (open/closed/all)", "default": "open"},
                        "max_results": {"type": "integer", "description": "Max results (default 10)", "default": 10},
                    },
                },
            },
            {
                "name": "github_get_pull_request",
                "description": "Get a specific pull request",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "owner": {"type": "string", "description": "Repository owner"},
                        "repo": {"type": "string", "description": "Repository name"},
                        "number": {"type": "integer", "description": "PR number"},
                    },
                    "required": ["owner", "repo", "number"],
                },
            },
            {
                "name": "github_list_commits",
                "description": "List commits for a repository",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "owner": {"type": "string", "description": "Repository owner"},
                        "repo": {"type": "string", "description": "Repository name"},
                        "sha": {"type": "string", "description": "Branch or SHA"},
                        "path": {"type": "string", "description": "Filter by file path"},
                        "max_results": {"type": "integer", "description": "Max results (default 10)", "default": 10},
                    },
                },
            },
            {
                "name": "github_get_commit",
                "description": "Get a specific commit",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "owner": {"type": "string", "description": "Repository owner"},
                        "repo": {"type": "string", "description": "Repository name"},
                        "sha": {"type": "string", "description": "Commit SHA"},
                    },
                    "required": ["owner", "repo", "sha"],
                },
            },
            {
                "name": "github_list_branches",
                "description": "List branches for a repository",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "owner": {"type": "string", "description": "Repository owner"},
                        "repo": {"type": "string", "description": "Repository name"},
                    },
                },
            },
            {
                "name": "github_get_branch",
                "description": "Get a specific branch",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "owner": {"type": "string", "description": "Repository owner"},
                        "repo": {"type": "string", "description": "Repository name"},
                        "branch": {"type": "string", "description": "Branch name"},
                    },
                    "required": ["owner", "repo", "branch"],
                },
            },
            {
                "name": "github_list_workflows",
                "description": "List GitHub Actions workflows",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "owner": {"type": "string", "description": "Repository owner"},
                        "repo": {"type": "string", "description": "Repository name"},
                    },
                },
            },
            {
                "name": "github_list_workflow_runs",
                "description": "List GitHub Actions workflow runs",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "owner": {"type": "string", "description": "Repository owner"},
                        "repo": {"type": "string", "description": "Repository name"},
                        "workflow_id": {"type": "integer", "description": "Workflow ID"},
                        "status": {"type": "string", "description": "Filter by status"},
                        "max_results": {"type": "integer", "description": "Max results (default 10)", "default": 10},
                    },
                },
            },
            {
                "name": "github_get_workflow_run",
                "description": "Get a specific workflow run",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "owner": {"type": "string", "description": "Repository owner"},
                        "repo": {"type": "string", "description": "Repository name"},
                        "run_id": {"type": "integer", "description": "Run ID"},
                    },
                    "required": ["owner", "repo", "run_id"],
                },
            },
            {
                "name": "github_list_artifacts",
                "description": "List artifacts for a repository",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "owner": {"type": "string", "description": "Repository owner"},
                        "repo": {"type": "string", "description": "Repository name"},
                        "max_results": {"type": "integer", "description": "Max results (default 10)", "default": 10},
                    },
                },
            },
        ]
    
    def execute_tool(self, tool_name: str, arguments: Dict[str, Any], mail: str) -> Dict[str, Any]:
        """
        Execute an MCP tool.
        
        Args:
            tool_name: Name of the tool to execute
            arguments: Tool arguments
            mail: User's email for credential lookup
            
        Returns:
            Tool execution result
        """
        # Route to appropriate implementation
        tool_map = {
            "github_list_repositories": lambda: mcp_list_repositories(mail, **arguments),
            "github_search_repositories": lambda: mcp_search_repositories(mail, **arguments),
            "github_list_issues": lambda: mcp_list_issues(mail, **arguments),
            "github_get_issue": lambda: mcp_get_issue(mail, **arguments),
            "github_create_issue": lambda: mcp_create_issue(mail, **arguments),
            "github_update_issue": lambda: mcp_update_issue(mail, **arguments),
            "github_list_pull_requests": lambda: mcp_list_pull_requests(mail, **arguments),
            "github_get_pull_request": lambda: mcp_get_pull_request(mail, **arguments),
            "github_list_commits": lambda: mcp_list_commits(mail, **arguments),
            "github_get_commit": lambda: mcp_get_commit(mail, **arguments),
            "github_list_branches": lambda: mcp_list_branches(mail, **arguments),
            "github_get_branch": lambda: mcp_get_branch(mail, **arguments),
            "github_list_workflows": lambda: mcp_list_workflows(mail, **arguments),
            "github_list_workflow_runs": lambda: mcp_list_workflow_runs(mail, **arguments),
            "github_get_workflow_run": lambda: mcp_get_workflow_run(mail, **arguments),
            "github_list_artifacts": lambda: mcp_list_actions_artifacts(mail, **arguments),
        }
        
        tool_func = tool_map.get(tool_name)
        if not tool_func:
            return {"status": "error", "message": f"Unknown tool: {tool_name}"}
        
        try:
            return tool_func()
        except Exception as e:
            return {"status": "error", "message": f"Tool execution failed: {str(e)}"}


# Create singleton instance
github_mcp_server = GitHubMCPServer()
