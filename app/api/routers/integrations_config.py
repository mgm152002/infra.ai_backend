"""Integration configuration API router.

Extracts GitHub, Jira, Confluence, PagerDuty, and Prometheus config/query
endpoints from the monolithic main.py.
"""
import os
from typing import Optional, List
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from app.core.database import supabase
from app.core.security import verify_token
from app.core.logger import logger
from app.core.config import settings

router = APIRouter()


# --- Pydantic models for integration configs ---

class GitHubIntegrationConfig(BaseModel):
    base_url: Optional[str] = None
    token: Optional[str] = None
    default_owner: Optional[str] = None
    default_repo: Optional[str] = None


class JiraIntegrationConfig(BaseModel):
    base_url: str
    email: Optional[str] = None
    api_token: str


class ConfluenceIntegrationConfig(BaseModel):
    base_url: str
    email: Optional[str] = None
    api_token: str


class PagerDutyIntegrationConfig(BaseModel):
    api_token: str
    service_ids: Optional[str] = None
    team_ids: Optional[str] = None


class PrometheusConfig(BaseModel):
    name: Optional[str] = None
    base_url: str
    auth_type: Optional[str] = "none"
    bearer_token: Optional[str] = None


class DatadogConfig(BaseModel):
    api_key: str
    app_key: str
    site: Optional[str] = "datadoghq.com"


def _split_csv(value: Optional[str]) -> List[str]:
    if not value:
        return []
    return [v.strip() for v in value.split(",") if v.strip()]


# --- GitHub ---

@router.get("/integrations/github/config")
async def get_github_integration_config(user_data: dict = Depends(verify_token)):
    from integrations.github import get_github_config
    return {"response": get_github_config(user_data["email"])}


@router.post("/integrations/github/config")
async def save_github_integration_config(cfg: GitHubIntegrationConfig, user_data: dict = Depends(verify_token)):
    from integrations.github import set_github_config
    set_github_config(
        user_data["email"],
        token=cfg.token,
        base_url=cfg.base_url,
        default_owner=cfg.default_owner,
        default_repo=cfg.default_repo,
    )
    return {"status": "ok"}


@router.get("/integrations/github/issues/search")
async def github_issues_search(
    query: str,
    owner: Optional[str] = None,
    repo: Optional[str] = None,
    max_results: int = 10,
    user_data: dict = Depends(verify_token),
):
    from integrations.github import github_search_issues as github_search_issues_impl
    return {
        "response": github_search_issues_impl(
            mail=user_data["email"],
            query=query,
            owner=owner,
            repo=repo,
            max_results=max_results,
        )
    }


@router.get("/integrations/github/commits/search")
async def github_commits_search(
    query: str,
    owner: Optional[str] = None,
    repo: Optional[str] = None,
    max_results: int = 10,
    user_data: dict = Depends(verify_token),
):
    from integrations.github import github_search_commits as github_search_commits_impl
    return {
        "response": github_search_commits_impl(
            mail=user_data["email"],
            query=query,
            owner=owner,
            repo=repo,
            max_results=max_results,
        )
    }


@router.get("/integrations/github/issues/{owner}/{repo}/{number}")
async def github_issue_get(
    owner: str,
    repo: str,
    number: int,
    include_diff: bool = False,
    max_files: int = 20,
    max_patch_bytes: int = 20000,
    user_data: dict = Depends(verify_token),
):
    from integrations.github import github_get_issue as github_get_issue_impl
    return {
        "response": github_get_issue_impl(
            mail=user_data["email"],
            owner=owner,
            repo=repo,
            number=number,
            include_diff=include_diff,
            max_files=max_files,
            max_patch_bytes=max_patch_bytes,
        )
    }


@router.get("/integrations/github/commits/{owner}/{repo}/{sha}")
async def github_commit_get(
    owner: str,
    repo: str,
    sha: str,
    include_diff: bool = False,
    max_files: int = 20,
    max_patch_bytes: int = 20000,
    user_data: dict = Depends(verify_token),
):
    from integrations.github import github_get_commit as github_get_commit_impl
    return {
        "response": github_get_commit_impl(
            mail=user_data["email"],
            owner=owner,
            repo=repo,
            sha=sha,
            include_diff=include_diff,
            max_files=max_files,
            max_patch_bytes=max_patch_bytes,
        )
    }


# --- Jira ---

@router.get("/integrations/jira/config")
async def get_jira_integration_config(user_data: dict = Depends(verify_token)):
    from integrations.jira import get_jira_config
    return {"response": get_jira_config(user_data["email"])}


@router.post("/integrations/jira/config")
async def save_jira_integration_config(cfg: JiraIntegrationConfig, user_data: dict = Depends(verify_token)):
    from integrations.jira import set_jira_config
    set_jira_config(
        user_data["email"],
        base_url=cfg.base_url,
        email=cfg.email,
        api_token=cfg.api_token,
    )
    return {"status": "ok"}


@router.get("/integrations/jira/issues/search")
async def jira_issues_search(
    jql: str,
    fields: Optional[str] = None,
    max_results: int = 10,
    user_data: dict = Depends(verify_token),
):
    from integrations.jira import jira_search_issues as jira_search_issues_impl
    return {
        "response": jira_search_issues_impl(
            mail=user_data["email"],
            jql=jql,
            fields=_split_csv(fields) if fields else None,
            max_results=max_results,
        )
    }


@router.get("/integrations/jira/issues/{issue_key}")
async def jira_issue_get(
    issue_key: str,
    fields: Optional[str] = None,
    user_data: dict = Depends(verify_token),
):
    from integrations.jira import jira_get_issue as jira_get_issue_impl
    return {
        "response": jira_get_issue_impl(
            mail=user_data["email"],
            issue_key=issue_key,
            fields=_split_csv(fields) if fields else None,
        )
    }


# --- Confluence ---

@router.get("/integrations/confluence/config")
async def get_confluence_integration_config(user_data: dict = Depends(verify_token)):
    from integrations.confluence import get_confluence_config
    return {"response": get_confluence_config(user_data["email"])}


@router.post("/integrations/confluence/config")
async def save_confluence_integration_config(cfg: ConfluenceIntegrationConfig, user_data: dict = Depends(verify_token)):
    from integrations.confluence import set_confluence_config
    set_confluence_config(
        user_data["email"],
        base_url=cfg.base_url,
        email=cfg.email,
        api_token=cfg.api_token,
    )
    return {"status": "ok"}


@router.get("/integrations/confluence/pages/search")
async def confluence_pages_search(
    cql: str,
    limit: int = 10,
    user_data: dict = Depends(verify_token),
):
    from integrations.confluence import confluence_search_pages as confluence_search_pages_impl
    return {"response": confluence_search_pages_impl(mail=user_data["email"], cql=cql, limit=limit)}


@router.get("/integrations/confluence/pages/{page_id}")
async def confluence_page_get(
    page_id: str,
    user_data: dict = Depends(verify_token),
):
    from integrations.confluence import confluence_get_page as confluence_get_page_impl
    return {"response": confluence_get_page_impl(mail=user_data["email"], page_id=page_id)}


# --- PagerDuty ---

@router.get("/integrations/pagerduty/config")
async def get_pagerduty_integration_config(user_data: dict = Depends(verify_token)):
    from integrations.pagerduty import get_pagerduty_config
    return {"response": get_pagerduty_config(user_data["email"])}


@router.post("/integrations/pagerduty/config")
async def save_pagerduty_integration_config(cfg: PagerDutyIntegrationConfig, user_data: dict = Depends(verify_token)):
    from integrations.pagerduty import set_pagerduty_config
    set_pagerduty_config(
        user_data["email"],
        api_token=cfg.api_token,
        service_ids=cfg.service_ids,
        team_ids=cfg.team_ids,
    )
    return {"status": "ok"}


@router.get("/integrations/pagerduty/incidents")
async def pagerduty_incidents(
    statuses: Optional[str] = None,
    limit: int = 25,
    user_data: dict = Depends(verify_token),
):
    from integrations.pagerduty import pagerduty_list_incidents as pagerduty_list_incidents_impl
    return {
        "response": pagerduty_list_incidents_impl(
            mail=user_data["email"],
            statuses=_split_csv(statuses) if statuses else None,
            limit=limit,
        )
    }


@router.get("/integrations/pagerduty/incidents/{incident_id}")
async def pagerduty_incident_get(
    incident_id: str,
    user_data: dict = Depends(verify_token),
):
    from integrations.pagerduty import pagerduty_get_incident as pagerduty_get_incident_impl
    return {"response": pagerduty_get_incident_impl(mail=user_data["email"], incident_id=incident_id)}


# --- Prometheus ---

@router.get("/integrations/prometheus/query")
async def prometheus_query_endpoint(
    query: str,
    user_data: dict = Depends(verify_token),
):
    from integrations.prometheus import prometheus_instant_query

    user_id = user_data.get("user_id")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    resp = supabase.table("PrometheusConfigs").select("*").eq("user_id", user_id).limit(1).execute()
    if not resp.data:
        return {"response": {"status": "not_configured", "message": "Prometheus datasource is not configured"}}

    cfg = resp.data[0]
    return {
        "response": prometheus_instant_query(
            base_url=cfg.get("base_url"),
            query=query,
            auth_type=cfg.get("auth_type") or "none",
            bearer_token=cfg.get("bearer_token"),
        )
    }


@router.get("/integrations/prometheus/config")
async def get_prometheus_config_v2(user_data: dict = Depends(verify_token)):
    from integrations.infisical import get_many
    try:
        user_id = user_data["user_id"]
        user_email = user_data.get("email") or user_data.get("user_id")

        try:
            secrets = get_many(user_email, ("PROMETHEUS_URL", "PROMETHEUS_AUTH_TYPE", "PROMETHEUS_TOKEN"))
            if secrets.get("PROMETHEUS_URL"):
                bearer_token = secrets.get("PROMETHEUS_TOKEN", "")
                masked_token = f"****{bearer_token[-4:]}" if bearer_token and len(bearer_token) > 4 else ""
                return {"response": {
                    "name": "Default Prometheus",
                    "base_url": secrets.get("PROMETHEUS_URL", ""),
                    "auth_type": secrets.get("PROMETHEUS_AUTH_TYPE", "none"),
                    "bearer_token": masked_token
                }}
        except Exception:
            pass

        response = supabase.table("PrometheusConfigs").select("*").eq("user_id", user_id).limit(1).execute()
        if response.data:
            return {"response": response.data[0]}

        base_url = os.getenv("PROMETHEUS_URL", "")
        auth_type = os.getenv("PROMETHEUS_AUTH_TYPE", "none")
        bearer_token = os.getenv("PROMETHEUS_TOKEN", "")
        masked_token = f"****{bearer_token[-4:]}" if bearer_token and len(bearer_token) > 4 else ""
        return {"response": {"name": "Default Prometheus", "base_url": base_url, "auth_type": auth_type, "bearer_token": masked_token}}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch Prometheus configuration: {str(e)}",
        )


@router.post("/integrations/prometheus/config")
async def save_prometheus_config_v2(config: PrometheusConfig, user_data: dict = Depends(verify_token)):
    from integrations.infisical import set_many
    try:
        user_email = user_data.get("email") or user_data.get("user_id")
        secrets = {
            "PROMETHEUS_URL": config.base_url,
            "PROMETHEUS_AUTH_TYPE": config.auth_type or "none",
        }
        if config.bearer_token and not config.bearer_token.startswith("****"):
            secrets["PROMETHEUS_TOKEN"] = config.bearer_token
        set_many(user_email, secrets)
        return {"status": "success", "message": "Saved to Infisical"}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to save Prometheus configuration: {str(e)}",
        )


# --- ServiceNow ---

@router.post("/integrations/servicenow/incident")
def create_snow_incident(payload: dict, user_data: dict = Depends(verify_token)):
    from integrations.servicenow import servicenow_client
    return servicenow_client.create_incident(payload.get("data", {}), user_data['email'])


@router.get("/integrations/servicenow/incident/{inc_number}")
def get_snow_incident(inc_number: str, user_data: dict = Depends(verify_token)):
    from integrations.servicenow import servicenow_client
    result = servicenow_client.get_incident(inc_number, user_data['email'])
    if not result:
        raise HTTPException(status_code=404, detail="Incident not found in ServiceNow")
    return result


@router.post("/integrations/servicenow/sync-cmdb")
def sync_cmdb_from_servicenow(background_tasks, user_data: dict = Depends(verify_token)):
    from integrations.servicenow import servicenow_client
    import uuid as _uuid

    email = user_data['email']
    user_id = user_data['user_id']
    job_id = str(_uuid.uuid4())
    supabase.table("Jobs").insert({"id": job_id, "user_id": str(user_id), "task_type": "snow_sync", "status": "pending", "progress": 0}).execute()

    def background_sync_task(email, user_id, job_id):
        try:
            supabase.table("Jobs").update({"status": "running", "progress": 0}).eq("id", job_id).execute()
            assets = servicenow_client.fetch_cmdb_assets(email)
            total_assets = len(assets)
            supabase.table("Jobs").update({"total_items": total_assets}).eq("id", job_id).execute()

            for i, asset in enumerate(assets):
                sn_tag_id = asset.get('name') or 'Unknown'
                item_data = {
                    "user_id": user_id,
                    "tag_id": sn_tag_id,
                    "ip": asset.get('ip_address') or "0.0.0.0",
                    "addr": asset.get('location') or 'Unknown',
                    "os": asset.get('os') or 'Unknown',
                    "type": asset.get('sys_class_name') or 'Configuration Item',
                    "description": asset.get('short_description') or f"ServiceNow CI: {sn_tag_id}",
                    "source": "servicenow",
                    "sys_id": asset.get('sys_id'),
                    "last_sync": datetime.utcnow().isoformat(),
                }
                supabase.table("CMDB").upsert(item_data, on_conflict="user_id,tag_id").execute()

                if (i + 1) % 10 == 0 or (i + 1) == total_assets:
                    progress_pct = int(((i + 1) / total_assets) * 100)
                    supabase.table("Jobs").update({"progress": progress_pct, "processed_items": i + 1}).eq("id", job_id).execute()

            supabase.table("Jobs").update({"status": "completed", "progress": 100}).eq("id", job_id).execute()
        except Exception as e:
            print(f"CMDB sync failed: {e}")
            supabase.table("Jobs").update({"status": "failed", "details": {"error": str(e)}}).eq("id", job_id).execute()

    background_tasks.add_task(background_sync_task, email, user_id, job_id)
    return {"status": "success", "job_id": job_id}


# --- Datadog ---

@router.get("/integrations/datadog/config")
def get_datadog_config_v2(user_data: dict = Depends(verify_token)):
    api_key = os.getenv("DD_API_KEY", "")
    app_key = os.getenv("DD_APP_KEY", "")
    site = os.getenv("DD_SITE", "datadoghq.com")
    masked_api = f"****{api_key[-4:]}" if len(api_key) > 4 else ""
    masked_app = f"****{app_key[-4:]}" if len(app_key) > 4 else ""
    return {"response": {"api_key": masked_api, "app_key": masked_app, "site": site}}


@router.post("/integrations/datadog/config")
def save_datadog_config_v2(config: DatadogConfig, user_data: dict = Depends(verify_token)):
    if config.api_key and not config.api_key.startswith("****"):
        os.environ["DD_API_KEY"] = config.api_key
    if config.app_key and not config.app_key.startswith("****"):
        os.environ["DD_APP_KEY"] = config.app_key
    if config.site:
        os.environ["DD_SITE"] = config.site
    return {"status": "success", "message": "Datadog credentials saved"}
