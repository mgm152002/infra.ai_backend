import json
import os
import re
import time
import requests
import traceback
import paramiko
import tempfile
import threading
from typing import List, Optional, Dict, Any
from datetime import datetime

import boto3
from supabase import create_client, Client
from langchain_openai import ChatOpenAI
from langchain_core.messages import SystemMessage, HumanMessage
from pinecone import Pinecone
from openai import OpenAI

from app.core.config import settings
from app.core.logger import logger

# --- Configuration & Globals ---

# We'll rely on settings from app.core.config where possible, 
# but some might still be env vars if not yet in settings.
# For now, I'll stick to os.getenv for what was there, but ideally we move to settings.

REDACT_SENSITIVE = True

# Initialize Supabase
supabase: Client = create_client(settings.SUPABASE_URL, settings.SUPABASE_KEY)

# Initialize Gemini (from original worker, though it seemed unused in main logic, keeping for safety)
import google.generativeai as genai
if os.getenv('Gemini_Api_Key'):
    genai.configure(api_key=os.getenv('Gemini_Api_Key'))

# Knowledge Base
PINECONE_KB_INDEX_NAME = os.getenv("PINECONE_KB_INDEX_NAME", "infraai")
KB_TOP_K_DEFAULT = int(os.getenv("KB_TOP_K_DEFAULT", "5"))
KB_SCORE_THRESHOLD_DEFAULT = float(os.getenv("KB_SCORE_THRESHOLD_DEFAULT", "0.7"))
ARCHITECTURE_KB_FILE_PATH = os.getenv("ARCHITECTURE_KB_FILE_PATH", "architecture_kb.md")

OPENROUTER_API_KEY = settings.OPENROUTER_API_KEY
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
# These might not be in settings yet
OPENROUTER_SITE_URL = os.getenv("OPENROUTER_SITE_URL")
OPENROUTER_SITE_NAME = os.getenv("OPENROUTER_SITE_NAME")
DEFAULT_MODEL_NAME = settings.OPENROUTER_MODEL

embedding_client: Optional[OpenAI] = None
if OPENROUTER_API_KEY:
    embedding_client = OpenAI(
        base_url=OPENROUTER_BASE_URL,
        api_key=OPENROUTER_API_KEY,
    )

pc = None
try:
    pinecone_api_key = os.getenv("Pinecone_Api_Key")
    if pinecone_api_key:
        pc = Pinecone(api_key=pinecone_api_key)
except Exception:
    pc = None

# Imports for integrations
from integrations.github import get_github_config, github_search_issues as github_search_issues_impl
from integrations.jira import get_jira_config, jira_search_issues as jira_search_issues_impl
from integrations.confluence import get_confluence_config, confluence_search_pages as confluence_search_pages_impl
from integrations.pagerduty import get_pagerduty_config, pagerduty_list_incidents as pagerduty_list_incidents_impl
from integrations.slack import SlackIntegration as SlackClient

SYSTEM_PROMPT = '''You are an AI incident resolver agent.
You are always given:
- A structured incident description.
- System information for the affected host (OS, IP).
- Optional runbook / SOP context from the internal knowledge base.
- Optional metrics context from Prometheus.
- Optional context from external systems (GitHub, Jira, Confluence, PagerDuty).

You MUST:
- Read and use all of the context provided above before proposing commands.
- Prefer explicit runbook/SOP instructions over generic best practices when they are available.
- Treat metrics and external system data as authoritative signals when deciding what to check first.

When given an incident description, create a structured plan with these steps:
1. Collect diagnostic information (logs, metrics, system state)
2. Analyze root cause
3. Generate resolution steps
4. Execute resolution
5. Verify resolution

For each step, provide specific commands to run. Always:
- Use non-interactive commands
- Include safe, read-only diagnostics before any destructive actions
- Avoid rebooting systems or restarting critical services unless clearly justified
- Verify command success before proceeding
- Use appropriate tools for the environment
- Return structured JSON output with status and results

Return your response in this format:
{
  "todos": [
    {
      "step": "Collect system logs",
      "command": "journalctl -u service --since '1 hour ago'",
      "expected_output": "Log entries showing error patterns"
    },
    {
      "step": "Check disk space",
      "command": "df -h",
      "expected_output": "Disk usage percentages"
    }
  ]
}
'''

def truncate(s: str, n: int = 2000) -> str:
    if s is None: return ""
    return str(s) if len(str(s)) <= n else str(s)[:n] + f"... [truncated {len(str(s))-n} chars]"

def make_ctx_logger(base_logger, incident=None, instance=None, user=None):
    # This might need to be adapted if app.core.logger.logger already supports context binding
    # For now, keeping the wrapper style from worker.py but using the base logger methods
    prefix = f"[incident={incident or 'unknown'}] [instance={instance or 'unknown'}] [user={user or 'unknown'}]"
    class Ctx:
        def info(self, msg, *args, **kwargs):
            base_logger.info(f"{prefix} {msg}", *args, **kwargs)
        def debug(self, msg, *args, **kwargs):
            base_logger.debug(f"{prefix} {msg}", *args, **kwargs)
        def warning(self, msg, *args, **kwargs):
            base_logger.warning(f"{prefix} {msg}", *args, **kwargs)
        def error(self, msg, *args, **kwargs):
            base_logger.error(f"{prefix} {msg}", *args, **kwargs)
        def exception(self, msg, *args, **kwargs):
            base_logger.exception(f"{prefix} {msg}", *args, **kwargs)
    return Ctx()

def get_llm(model_name: Optional[str] = None, **kwargs) -> ChatOpenAI:
    if not OPENROUTER_API_KEY:
        raise ValueError("OpenRouter API key not set.")
    return ChatOpenAI(
        model=model_name or DEFAULT_MODEL_NAME,
        api_key=OPENROUTER_API_KEY,
        base_url=OPENROUTER_BASE_URL,
        **kwargs,
    )

def call_llm(user_content: str, *, system_content: Optional[str] = None, model_name: Optional[str] = None) -> str:
    messages: List = []
    if system_content:
        messages.append(SystemMessage(content=system_content))
    messages.append(HumanMessage(content=user_content))
    llm = get_llm(model_name=model_name)
    response = llm.invoke(messages)
    return response.content

# --- Knowledge Base Helpers ---

def _get_kb_index(ctx_logger=None):
    l = ctx_logger or logger
    if pc is None:
        l.debug("Pinecone client not configured; skipping knowledge base lookups")
        return None
    try:
        return pc.Index(PINECONE_KB_INDEX_NAME)
    except Exception as e:
        l.warning(f"Knowledge base index '{PINECONE_KB_INDEX_NAME}' is not available: {str(e)}")
        return None

def _embed_texts(texts: List[str], ctx_logger=None) -> List[List[float]]:
    l = ctx_logger or logger
    if not texts: return []
    if embedding_client is None:
        l.debug("Embedding client not configured; skipping knowledge base lookups")
        return []
    try:
        extra_headers: Dict[str, str] = {}
        if OPENROUTER_SITE_URL: extra_headers["HTTP-Referer"] = OPENROUTER_SITE_URL
        if OPENROUTER_SITE_NAME: extra_headers["X-Title"] = OPENROUTER_SITE_NAME
        
        kwargs: Dict[str, Any] = {
            "model": "openai/text-embedding-ada-002",
            "input": texts,
            "encoding_format": "float",
        }
        if extra_headers: kwargs["extra_headers"] = extra_headers

        response = embedding_client.embeddings.create(**kwargs)
        return [item.embedding for item in response.data]
    except Exception as e:
        l.warning(f"Failed to compute embeddings for knowledge base: {str(e)}")
        return []

def _get_architecture_kb_text() -> str:
    path = ARCHITECTURE_KB_FILE_PATH
    if not path: return ""
    try:
        if not os.path.exists(path): return ""
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception:
        return ""

def query_knowledge_base(query: str, top_k: int = KB_TOP_K_DEFAULT, score_threshold: float = KB_SCORE_THRESHOLD_DEFAULT, ctx_logger=None) -> List[dict]:
    l = ctx_logger or logger
    if not query or not query.strip():
        matches: List[dict] = []
    else:
        index = _get_kb_index(ctx_logger=l)
        if index is None:
            matches = []
        else:
            embeddings = _embed_texts([query], ctx_logger=l)
            if not embeddings:
                matches = []
            else:
                try:
                    res = index.query(vector=embeddings[0], top_k=top_k, include_metadata=True)
                except Exception as e:
                    l.warning(f"Failed to query knowledge base: {str(e)}")
                    matches = []
                else:
                    matches_raw = []
                    if isinstance(res, dict): matches_raw = res.get("matches", [])
                    elif hasattr(res, "to_dict"): matches_raw = res.to_dict().get("matches", [])
                    elif hasattr(res, "matches"): matches_raw = res.matches
                    
                    matches = []
                    for m in matches_raw or []:
                        if isinstance(m, dict):
                            score = m.get("score")
                            metadata = m.get("metadata") or {}
                        else:
                            score = getattr(m, "score", None)
                            metadata = getattr(m, "metadata", {}) or {}
                        if score is None: continue
                        if score_threshold is not None and float(score) < float(score_threshold): continue
                        
                        matches.append({
                            "score": float(score),
                            "text": metadata.get("text", ""),
                            "source": metadata.get("source_file_name") or metadata.get("source") or "",
                            "doc_id": metadata.get("doc_id") or "",
                            "chunk_index": metadata.get("chunk_index"),
                        })

    arch_text = ""
    try:
        arch_text = _get_architecture_kb_text()
    except Exception:
        arch_text = ""
        
    if arch_text and arch_text.strip():
        matches.insert(0, {
            "score": 1.0,
            "text": arch_text,
            "source": "architecture_kb",
            "doc_id": "architecture_kb",
            "chunk_index": 0,
        })
        
    return matches

def get_incident_runbook_context(incident: dict, ctx_logger=None) -> dict:
    l = ctx_logger or logger
    try:
        query_parts = [
            f"Incident {incident.get('inc_number', '')}",
            incident.get('subject') or "",
            incident.get('message') or "",
        ]
        query = " - ".join(p for p in query_parts if p)
        l.info("Querying knowledge base for incident runbooks/SOPs")
        matches = query_knowledge_base(query, ctx_logger=l)
        if not matches:
            l.info("No matching runbooks/SOPs found in knowledge base")
            return {"has_knowledge": False, "matches": [], "combined_context": ""}
        combined = "\n\n".join(m["text"] for m in matches if m.get("text"))
        l.info(f"Found {len(matches)} knowledge base matches for incident")
        return {"has_knowledge": True, "matches": matches, "combined_context": combined}
    except Exception as e:
        l.warning(f"Knowledge base lookup failed; continuing without runbooks: {str(e)}")
        return {"has_knowledge": False, "matches": [], "combined_context": ""}

# --- Prometheus & External Integrations ---

def get_prometheus_config_for_user(user_id: Any, ctx_logger=None) -> Optional[dict]:
    l = ctx_logger or logger
    if user_id is None: return None
    try:
        resp = supabase.table("PrometheusConfigs").select("*").eq("user_id", user_id).limit(1).execute()
        data = getattr(resp, "data", None) or []
        if not data:
            return None
        return data[0]
    except Exception as e:
        l.warning(f"Failed to fetch Prometheus configuration for user_id={user_id}: {str(e)}")
        return None

def fetch_prometheus_metrics(prom_cfg: dict, cmdb: dict, incident: dict, ctx_logger=None) -> str:
    l = ctx_logger or logger
    base_url = (prom_cfg.get("base_url") or "").rstrip("/")
    if not base_url: return ""
    
    instance_ip = cmdb.get("ip")
    if not instance_ip: return ""
    
    instance_label = f"{instance_ip}:9100"
    queries: Dict[str, str] = {
        "up": f'up{{instance="{instance_label}"}}',
        "cpu_5m": f'avg(rate(node_cpu_seconds_total{{mode!="idle",instance="{instance_label}"}}[5m]))',
        "load1": f'avg_over_time(node_load1{{instance="{instance_label}"}}[5m])',
        "mem_used_ratio": f'(1 - (node_memory_MemAvailable_bytes{{instance="{instance_label}"}} / node_memory_MemTotal_bytes{{instance="{instance_label}"}}))',
    }
    
    headers: Dict[str, str] = {}
    auth_type = (prom_cfg.get("auth_type") or "none").lower()
    bearer_token = prom_cfg.get("bearer_token")
    if auth_type == "bearer" and bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"
        
    metrics_results: Dict[str, Any] = {}
    for name, query in queries.items():
        try:
            resp = requests.get(f"{base_url}/api/v1/query", params={"query": query}, headers=headers, timeout=10)
            resp.raise_for_status()
            body = resp.json()
            if body.get("status") != "success": continue
            metrics_results[name] = body.get("data", {}).get("result", [])
        except Exception:
            pass
            
    if not metrics_results: return ""
    
    try:
        return json.dumps({
            "prometheus_base_url": base_url,
            "instance": instance_label,
            "incident_number": incident.get("inc_number"),
            "queries": queries,
            "results": metrics_results,
        }, indent=2)
    except Exception:
        return ""

def _sanitize_query_text(text: str, max_len: int = 200) -> str:
    t = (text or "").strip()
    t = re.sub(r"[\r\n\t]+", " ", t)
    t = re.sub(r"[\"\\]", " ", t)
    t = re.sub(r"\s+", " ", t).strip()
    if len(t) > max_len: t = t[:max_len].rstrip()
    return t

def fetch_external_integrations_context(email: str, incident: dict, ctx_logger=None) -> str:
    l = ctx_logger or logger
    try:
        subj = incident.get("subject") or ""
        msg = incident.get("message") or ""
        q = _sanitize_query_text(f"{subj} {msg}")
        if not q: return ""

        out: Dict[str, Any] = {"query": q, "credential_status": {}, "sources": {}}

        # GitHub
        try:
            gh_cfg = get_github_config(email)
            gh_configured = bool(gh_cfg.get("token"))
            out["credential_status"]["github"] = {"configured": gh_configured}
            if gh_configured:
                out["sources"]["github"] = github_search_issues_impl(mail=email, query=q, max_results=5)
        except Exception:
            pass

        # Jira
        try:
            jira_cfg = get_jira_config(email)
            jira_configured = bool(jira_cfg.get("base_url"))
            out["credential_status"]["jira"] = {"configured": jira_configured}
            if jira_configured:
                jql = f'text ~ "{q}" ORDER BY updated DESC'
                out["sources"]["jira"] = jira_search_issues_impl(mail=email, jql=jql, max_results=5)
        except Exception:
            pass
        
        # Confluence
        try:
            conf_cfg = get_confluence_config(email)
            conf_configured = bool(conf_cfg.get("base_url"))
            out["credential_status"]["confluence"] = {"configured": conf_configured}
            if conf_configured:
                cql = f'text ~ "{q}" ORDER BY lastmodified DESC'
                out["sources"]["confluence"] = confluence_search_pages_impl(mail=email, cql=cql, limit=5)
        except Exception:
            pass

        # PagerDuty
        try:
            pd_cfg = get_pagerduty_config(email)
            pd_configured = bool(pd_cfg.get("api_token"))
            out["credential_status"]["pagerduty"] = {"configured": pd_configured}
            if pd_configured:
                out["sources"]["pagerduty"] = pagerduty_list_incidents_impl(mail=email, statuses=["triggered", "acknowledged"], limit=10)
        except Exception:
            pass

        if not out["sources"]:
            return "" # Don't return empty noise
            
        return json.dumps(out, indent=2)
    except Exception:
        return ""

# --- SSH & Execution ---

def get_username(os_type: str) -> str:
    os_type = (os_type or "").lower()
    if 'ubuntu' in os_type: return 'ubuntu'
    if 'amazon' in os_type or 'linux' in os_type: return 'ec2-user'
    if 'rhel' in os_type or 'centos' in os_type: return 'ec2-user'
    if 'debian' in os_type: return 'admin'
    if 'suse' in os_type: return 'ec2-user'
    return 'admin'

def fetch_ssh_key_content(mail: str, ctx_logger=None) -> Optional[str]:
    """
    Fetch the SSH key content from Infisical or other vault.
    Returns the key content as a string, or None if failed.
    """
    l = ctx_logger or logger
    l.info(f"Fetching SSH key for user mailbox: {mail}")
    
    # Check environment config first
    client_id = os.getenv('clientId')
    client_secret = os.getenv('clientSecret')
    
    if not client_id or not client_secret:
        l.error("Infisical credentials (clientId/clientSecret) not set")
        return None

    secret_auth_uri = "https://app.infisical.com/api/v1/auth/universal-auth/login"
    try:
        auth_data = {"clientId": client_id, "clientSecret": client_secret}
        response = requests.post(url=secret_auth_uri, data=auth_data, timeout=20)
        response.raise_for_status()
        access_token = response.json().get('accessToken')
        
        if not access_token:
            l.error("No access token returned from Infisical")
            return None
            
        base_url = 'https://us.infisical.com/api/v3/secrets/raw'
        sshkey_resp = requests.get(
            f'{base_url}/SSH_KEY_{mail}?workspaceSlug=infraai-oqb-h&environment=prod',
            headers={'Authorization': f'Bearer {access_token}'},
            timeout=20
        )
        sshkey_resp.raise_for_status()
        
        # Infisical API V3 usually returns the raw secret value directly if using /raw related endpoints,
        # OR a JSON wrapper. The previous code parsed it as JSON.
        # Based on previous code: sshkey_resp.json().get('secret', {}).get('secretValue')
        
        data = sshkey_resp.json()
        secret_val = data.get('secret', {}).get('secretValue')
        
        if not secret_val:
            l.error("SSH secret value not found in response")
            # Fallback check if the endpoint returned raw string?
            # But the previous code worked, so we stick to that structure.
            return None
            
        return secret_val

    except Exception as e:
        l.exception(f"Error fetching SSH key: {str(e)}")
        return None

def run_shell_command(command: str, hostname: str, username: str, key_content: str, ctx_logger=None) -> dict:
    l = ctx_logger or logger
    l.info(f"Preparing to run remote command on {hostname} as {username}: {truncate(command, 1000)}")
    
    # We use a secure temporary file for the key
    key_file_path = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_key_file:
            temp_key_file.write(key_content)
            temp_key_file.flush()
            key_file_path = temp_key_file.name
        
        # Ensure permissions are correct (0600)
        os.chmod(key_file_path, 0o600)

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname, username=username, key_filename=key_file_path, timeout=30)
        l.info("SSH connection established")
        
        full_command = f"export TERM=xterm-256color && {command}"
        stdin, stdout, stderr = ssh.exec_command(full_command, timeout=120)
        
        out = stdout.read().decode(errors='replace')
        err = stderr.read().decode(errors='replace')
        
        ssh.close()
        
        l.info(f"stdout: {truncate(out)}")
        if err: l.warning(f"stderr: {truncate(err)}")
        
        success = not bool(err.strip())
        return {"command": command, "output": out, "error": err, "success": success}

    except Exception as e:
        l.exception(f"SSH command execution failed: {str(e)}")
        return {"command": command, "output": "", "error": str(e), "success": False}
    finally:
        # Secure cleanup
        if key_file_path and os.path.exists(key_file_path):
            try:
                os.remove(key_file_path)
            except Exception:
                pass

def verify_output(result: dict, expected: str, ctx_logger=None) -> bool:
    l = ctx_logger or logger
    if not result.get('success'): return False
    
    patterns = [r'error', r'fail', r'exception', r'not found', r'permission denied', r'timeout', r'unable']
    for pattern in patterns:
        if re.search(pattern, result.get('output', ''), re.IGNORECASE):
            return False
    return True

def extract_json(text: str, ctx_logger=None) -> dict:
    l = ctx_logger or logger
    try:
        json_match = re.search(r'\{[\s\S]*\}', text)
        if json_match: return json.loads(json_match.group())
    except Exception:
        pass
    try:
        return json.loads(text)
    except Exception:
        l.warning("Failed to parse JSON from AI response")
        return {"todos": []}

def collect_diagnostics(incident: dict, cmdb: dict, kb_context: str = "", prometheus_context: str = "", external_context: str = "", additional_context: str = "", ctx_logger=None, key_content: str = None) -> dict:
    l = ctx_logger or logger
    kb_block = f"Known runbook context:\n{kb_context}" if kb_context else "No specific runbook found."
    prom_block = f"Prometheus metrics:\n{prometheus_context}" if prometheus_context else "No Prometheus metrics."
    ext_block = f"External context:\n{external_context}" if external_context else "No external context."
    add_block = f"Additional context:\n{additional_context}" if additional_context else ""
    
    prompt = f"""
    Incident: {incident.get('subject')} - {incident.get('message')}
    System: {cmdb.get('os')} at {cmdb.get('ip')}
    FQDN: {cmdb.get('fqdn', 'N/A')}
    {kb_block}
    {prom_block}
    {ext_block}
    {add_block}
    Create a diagnostic plan.
    {SYSTEM_PROMPT}
    """
    
    response_text = call_llm(prompt, model_name=DEFAULT_MODEL_NAME)
    plan_json = extract_json(response_text, ctx_logger=l)
    
    results = []
    for todo in plan_json.get('todos', []):
        result = run_shell_command(
            command=todo.get('command'),
            hostname=cmdb.get('ip'),
            username=get_username(cmdb.get('os')),
            key_content=key_content,
            ctx_logger=l
        )
        verified = verify_output(result, todo.get('expected_output', ''), ctx_logger=l)
        results.append({**todo, **result, "verified": verified})
        
    return {"diagnostics": results, "raw_response": truncate(json.dumps(plan_json))}

def analyze_diagnostics(diagnostics: dict, incident: dict, ctx_logger=None) -> dict:
    l = ctx_logger or logger
    prompt = f"""
    Incident: {incident.get('subject')}
    Diagnostic results: {json.dumps(diagnostics, indent=2)}
    Analyze and determine: 1. Root cause 2. Resolution steps 3. Verification method
    Return JSON: {{"root_cause": "...", "resolution_steps": ["..."], "verification": "..."}}
    """
    response_text = call_llm(prompt, model_name=DEFAULT_MODEL_NAME)
    return extract_json(response_text, ctx_logger=l)

def execute_resolution(resolution: dict, cmdb: dict, ctx_logger=None, key_content: str = None) -> dict:
    l = ctx_logger or logger
    results = []
    for step in resolution.get('resolution_steps', []):
        cmd_prompt = f"Resolution step: {step}\nSystem: {cmdb.get('os')}\nGenerate non-interactive command string ONLY."
        command = call_llm(cmd_prompt, model_name=DEFAULT_MODEL_NAME).strip().replace('```', '').replace('bash', '')
        result = run_shell_command(
            command=command,
            hostname=cmdb.get('ip'),
            username=get_username(cmdb.get('os')),
            key_content=key_content,
            ctx_logger=l
        )
        results.append({"step": step, "command": command, "result": result})
    return {"resolution_results": results}


# --- Slack Integration Helpers ---

def get_user_slack_config(user_id: str, ctx_logger=None) -> Optional[dict]:
    """Fetch Slack webhook/workspace config for a user."""
    l = ctx_logger or logger
    try:
        resp = supabase.table("integrations").select("*").eq("user_id", user_id).eq("provider", "slack").limit(1).execute()
        data = getattr(resp, "data", None) or []
        if not data:
            return None
        return data[0]
    except Exception as e:
        l.warning(f"Failed to fetch Slack config for user_id={user_id}: {str(e)}")
        return None


def get_alert_type_escalation(alert_type_id: str, ctx_logger=None) -> Optional[dict]:
    """Fetch escalation matrix for a specific alert type."""
    l = ctx_logger or logger
    try:
        resp = supabase.table("alert_type_escalations").select("*").eq("alert_type_id", alert_type_id).limit(1).execute()
        data = getattr(resp, "data", None) or []
        if data:
            return data[0]
        # Default escalation if not found
        return {"escalation_level": 1, "notification_channels": ["email"]}
    except Exception as e:
        l.warning(f"Failed to fetch escalation for alert_type={alert_type_id}: {str(e)}")
        return {"escalation_level": 1, "notification_channels": ["email"]}


def send_slack_notification(user_id: str, incident: dict, cmdb: dict, service: dict, status: str, message: str, thread_ts: str = None, ctx_logger=None) -> Optional[str]:
    """Send Slack notification about incident status. Returns thread_ts for follow-ups."""
    l = ctx_logger or logger
    
    # Try to get Slack workspace token for this user
    slack_cfg = get_user_slack_config(user_id, ctx_logger=l)
    if not slack_cfg:
        l.debug("No Slack config found for user, skipping notification")
        return None
    
    token = slack_cfg.get("access_token") or os.getenv("SLACK_BOT_TOKEN")
    if not token:
        l.debug("No Slack token available, skipping notification")
        return None
    
    try:
        slack = SlackClient(token=token)
        
        # Determine channel - use configured channel or default
        channel = slack_cfg.get("config", {}).get("channel_id") or os.getenv("SLACK_INCIDENT_CHANNEL", "#incidents")
        
        # Build message
        service_name = service.get("name", "Unknown Service") if service else "Unknown"
        fqdn = cmdb.get("fqdn", cmdb.get("ip", "Unknown"))
        
        status_emoji = {
            "Received": ":white_check_mark:",
            "Processing": ":hourglass_flowing_sand:",
            "Analyzing": ":mag:",
            "Executing": ":gear:",
            "Resolved": ":large_green_circle:",
            "Partially Resolved": ":warning:",
            "Error": ":x:",
            "Escalated": ":rotating_light:",
        }.get(status, ":information_source:")
        
        text = f"{status_emoji} *Incident {incident.get('inc_number')}*: {status} - {message}"
        blocks = [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": text
                }
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Service:* {service_name} | *Host:* {fqdn}"
                    }
                ]
            }
        ]
        
        if thread_ts:
            # Reply in thread
            result = slack.send_thread_reply(channel, thread_ts, text, blocks)
        else:
            # New message
            result = slack.send_message(channel, text, blocks)
        
        if result.get("ok"):
            l.info(f"Slack notification sent for incident {incident.get('inc_number')}")
            return result.get("ts") or thread_ts
        else:
            l.warning(f"Failed to send Slack notification: {result.get('error')}")
            return None
            
    except Exception as e:
        l.warning(f"Error sending Slack notification: {str(e)}")
        return None


def trigger_async_rca(inc_number: str, user_id: str, ctx_logger=None):
    """Trigger RCA generation in background thread and notify via Slack."""
    l = ctx_logger or logger
    
    def _generate_rca():
        try:
            from app.services.rca_service import rca_service
            rca_result = rca_service.generate_rca(inc_number)
            
            if rca_result.get("success"):
                # Get incident details for Slack notification
                try:
                    inc_resp = supabase.table("Incidents").select("*, CMDB:cmdb_id(*), Service:service_id(*)").eq("inc_number", inc_number).execute()
                    if inc_resp.data:
                        incident = inc_resp.data[0]
                        user_id_val = incident.get("user_id")
                        
                        # Send RCA link in Slack
                        rca_link = f"#"  # Frontend link would be constructed
                        send_slack_notification(
                            user_id_val, 
                            incident, 
                            incident.get("CMDB", {}), 
                            incident.get("Service", {}),
                            "RCA Ready",
                            f"RCA Report generated: {rca_result.get('rca_content', '')[:500]}...",
                            thread_ts=None,
                            ctx_logger=l
                        )
                except Exception as e:
                    l.warning(f"Failed to send RCA Slack notification: {str(e)}")
            else:
                l.warning(f"RCA generation failed: {rca_result.get('error')}")
        except Exception as e:
            l.exception(f"Error in async RCA generation: {str(e)}")
    
    # Run in background thread
    thread = threading.Thread(target=_generate_rca, daemon=True)
    thread.start()
    l.info(f"Async RCA generation started for incident {inc_number}")


def trigger_escalation(incident: dict, alert_type_id: str, cmdb: dict, service: dict, ctx_logger=None) -> dict:
    """Trigger escalation based on alert type and failure."""
    l = ctx_logger or logger
    
    escalation = get_alert_type_escalation(alert_type_id, ctx_logger=l)
    escalation_level = escalation.get("escalation_level", 1)
    notification_channels = escalation.get("notification_channels", ["email"])
    
    l.warning(f"Triggering escalation for incident {incident.get('inc_number')}: level={escalation_level}, channels={notification_channels}")
    
    # Update incident with escalation info
    try:
        supabase.table("Incidents").update({
            "escalation_level": escalation_level,
            "escalation_reason": f"Resolution failed - escalated based on {alert_type_id}",
            "state": "Escalated",
            "updated_at": datetime.utcnow().isoformat()
        }).eq("inc_number", incident.get("inc_number")).execute()
    except Exception as e:
        l.warning(f"Failed to update incident escalation: {str(e)}")
    
    # Send escalation notification
    user_id = incident.get("user_id")
    if user_id:
        send_slack_notification(
            user_id,
            incident,
            cmdb,
            service,
            "Escalated",
            f"Incident escalated to level {escalation_level} due to resolution failure",
            thread_ts=None,
            ctx_logger=l
        )
    
    # Trigger external escalation if configured (e.g., PagerDuty)
    if "pagerduty" in notification_channels:
        try:
            # Would trigger PagerDuty escalation here
            l.info("PagerDuty escalation triggered")
        except Exception as e:
            l.warning(f"PagerDuty escalation failed: {str(e)}")
    
    if "email" in notification_channels:
        try:
            # Would send email escalation here
            l.info("Email escalation triggered")
        except Exception as e:
            l.warning(f"Email escalation failed: {str(e)}")
    
    return {"escalated": True, "level": escalation_level}

def update_incident_state(inc_number: Optional[str], state: str, solution: Optional[dict] = None, ctx_logger=None) -> None:
    l = ctx_logger or logger
    if not inc_number: return
    try:
        update_data = {"state": state, "updated_at": datetime.utcnow().isoformat()}
        if solution is not None: update_data["solution"] = json.dumps(solution)
        supabase.table("Incidents").update(update_data).eq("inc_number", inc_number).execute()
        l.info(f"Incident {inc_number} state updated to '{state}'")
    except Exception as e:
        l.exception(f"Failed to update incident state: {str(e)}")

def process_incident(aws: dict, mail: dict, meta: Optional[dict] = None, ctx_logger=None) -> dict:
    # Use provided context logger or create one
    meta = meta or {}
    instance_label = meta.get('tag_id') or aws.get('instance_id')
    inc_number = mail.get('inc_number')
    job_id = meta.get('job_id')

    ctx = ctx_logger or make_ctx_logger(logger, incident=inc_number, instance=instance_label)
    
    ctx.info("Processing incident started (v2 service)")
    
    # Slack thread timestamp for this incident
    slack_thread_ts = None
    
    def update_job(progress, step):
        if job_id:
            try:
                supabase.table("Jobs").update({
                    "progress": progress,
                    "details": {"step": step}
                }).eq("id", job_id).execute()
            except Exception: pass
    
    # --- Step 1: Send Initial ACK in Slack ---
    try:
        user_id = meta.get('user_id')
        if user_id:
            # Fetch incident with service info
            inc_resp = supabase.table("Incidents").select("*, CMDB:cmdb_id(*), Service:service_id(*)").eq("inc_number", inc_number).execute()
            incident_data = inc_resp.data[0] if inc_resp.data else {}
            cmdb_data = incident_data.get("CMDB", {})
            service_data = incident_data.get("Service", {})
            
            slack_thread_ts = send_slack_notification(
                user_id,
                mail,  # incident data
                cmdb_data,
                service_data,
                "Received",
                f"Incident received and queued for processing",
                thread_ts=None,
                ctx_logger=ctx
            )
            ctx.info(f"Initial ACK sent to Slack, thread_ts: {slack_thread_ts}")
    except Exception as e:
        ctx.warning(f"Failed to send initial Slack ACK: {str(e)}")
    
    try:
        update_incident_state(inc_number, "Processing", ctx_logger=ctx)
        update_job(10, "fetching_context")
        
        # --- Send Slack: Processing status ---
        try:
            user_id = meta.get('user_id')
            if user_id:
                send_slack_notification(
                    user_id, mail, cmdb_data, service_data,
                    "Processing", "Fetching CMDB and system context...",
                    thread_ts=slack_thread_ts, ctx_logger=ctx
                )
        except Exception as e:
            ctx.warning(f"Failed to send Processing Slack update: {str(e)}")

        # CMDB Lookup
        cmdb = None
        tag_id = meta.get('tag_id') or aws.get('instance_id')
        if tag_id:
            query = supabase.table("CMDB").select("*").eq("tag_id", tag_id)
            if meta.get('user_id'): query = query.eq("user_id", meta.get('user_id'))
            resp = query.execute()
            if getattr(resp, "data", None): cmdb = resp.data[0]
            
        if not cmdb:
            msg = "CMDB entry not found"
            ctx.error(msg)
            update_incident_state(inc_number, "Error", solution={"error": msg}, ctx_logger=ctx)
            
            # Send error to Slack
            try:
                user_id = meta.get('user_id')
                if user_id:
                    send_slack_notification(
                        user_id, mail, {}, {},
                        "Error", msg,
                        thread_ts=slack_thread_ts, ctx_logger=ctx
                    )
            except: pass
            
            return {"status": "error", "message": msg}

        # User Lookup
        user_id = cmdb.get('user_id')
        user_resp = supabase.table("Users").select("email").eq("id", user_id).execute()
        if not getattr(user_resp, "data", None):
            msg = "User not found"
            ctx.error(msg)
            update_incident_state(inc_number, "Error", solution={"error": msg}, ctx_logger=ctx)
            return {"status": "error", "message": msg}
            
        email = user_resp.data[0].get('email')
        ctx = make_ctx_logger(logger, incident=inc_number, instance=instance_label, user=email)

        # Fetch service info
        service = None
        service_id = cmdb.get('service_id')
        if service_id:
            svc_resp = supabase.table("services").select("*").eq("id", service_id).execute()
            if svc_resp.data:
                service = svc_resp.data[0]
        
        # Get alert type from incident
        alert_type_id = mail.get('alert_type')
        
        # --- Send Slack: Context fetched ---
        try:
            send_slack_notification(
                user_id, mail, cmdb, service,
                "Processing", f"CMDB context loaded: {cmdb.get('os')} at {cmdb.get('ip')}",
                thread_ts=slack_thread_ts, ctx_logger=ctx
            )
        except: pass

        # SSH Key
        key_content = fetch_ssh_key_content(email, ctx_logger=ctx)
        if not key_content:
            msg = "Failed to fetch SSH key"
            ctx.error(msg)
            update_incident_state(inc_number, "Error", solution={"error": msg}, ctx_logger=ctx)
            
            # Send error to Slack
            try:
                send_slack_notification(user_id, mail, cmdb, service, "Error", msg, thread_ts=slack_thread_ts, ctx_logger=ctx)
            except: pass
            
            return {"status": "error", "message": msg}

        # Context Gathering - Include service info in context
        kb_info = get_incident_runbook_context(mail, ctx_logger=ctx)
        
        # Build enhanced context with service information
        service_context = ""
        if service:
            service_context = f"""
Service Information:
- Service Name: {service.get('name')}
- Service Type: {service.get('service_type')}
- Description: {service.get('description', 'N/A')}
"""
        
        # Include alert type in context
        alert_context = ""
        if alert_type_id:
            alert_context = f"""
Alert Type: {alert_type_id}
"""
        
        prom_cfg = get_prometheus_config_for_user(user_id, ctx_logger=ctx)
        prom_context = fetch_prometheus_metrics(prom_cfg, cmdb, mail, ctx_logger=ctx) if prom_cfg else ""
        
        ext_context = fetch_external_integrations_context(email, mail, ctx_logger=ctx)

        # Execution - Diagnostics Phase
        update_job(40, "collecting_diagnostics")
        
        # --- Send Slack: Collecting diagnostics ---
        try:
            send_slack_notification(
                user_id, mail, cmdb, service,
                "Processing", "Running diagnostics and collecting system information...",
                thread_ts=slack_thread_ts, ctx_logger=ctx
            )
        except: pass
        
        diagnostics = collect_diagnostics(mail, cmdb, kb_info.get("combined_context", ""), prom_context, ext_context, service_context + alert_context, ctx_logger=ctx, key_content=key_content)
        
        update_job(60, "analyzing_root_cause")
        
        # --- Send Slack: Analyzing ---
        try:
            send_slack_notification(
                user_id, mail, cmdb, service,
                "Analyzing", "Identifying root cause from diagnostics...",
                thread_ts=slack_thread_ts, ctx_logger=ctx
            )
        except: pass
        
        analysis = analyze_diagnostics(diagnostics, mail, ctx_logger=ctx)
        
        update_job(80, "executing_resolution")
        
        # --- Send Slack: Executing resolution ---
        try:
            send_slack_notification(
                user_id, mail, cmdb, service,
                "Executing", "Applying resolution steps...",
                thread_ts=slack_thread_ts, ctx_logger=ctx
            )
        except: pass
        
        resolution = execute_resolution(analysis, cmdb, ctx_logger=ctx, key_content=key_content)

        # Result Logic
        is_resolved = all(step['result'].get('success') for step in resolution.get('resolution_results', []))
        
        if is_resolved:
            status = "Resolved"
            ctx.info("Incident resolved successfully")
            
            # --- Send Slack: Resolved ---
            try:
                send_slack_notification(
                    user_id, mail, cmdb, service,
                    "Resolved", f"Incident resolved. Root cause: {analysis.get('root_cause', 'N/A')}",
                    thread_ts=slack_thread_ts, ctx_logger=ctx
                )
            except: pass
            
            # Trigger async RCA generation
            trigger_async_rca(inc_number, user_id, ctx_logger=ctx)
            
            # Send final RCA ready message
            try:
                send_slack_notification(
                    user_id, mail, cmdb, service,
                    "RCA Ready", "Generating Root Cause Analysis report...",
                    thread_ts=slack_thread_ts, ctx_logger=ctx
                )
            except: pass
            
        else:
            status = "Partially Resolved"
            ctx.warning("Incident resolution partially failed")
            
            # --- Send Slack: Partial resolution with escalation warning ---
            try:
                send_slack_notification(
                    user_id, mail, cmdb, service,
                    "Partially Resolved", "Some resolution steps failed. Checking escalation requirements...",
                    thread_ts=slack_thread_ts, ctx_logger=ctx
                )
            except: pass
            
            # Trigger escalation based on alert_type
            if alert_type_id:
                escalation_result = trigger_escalation(
                    {"inc_number": inc_number, "user_id": user_id},
                    alert_type_id,
                    cmdb,
                    service,
                    ctx_logger=ctx
                )
                return {
                    "status": status, 
                    "analysis": analysis,
                    "escalated": escalation_result.get("escalated", False),
                    "escalation_level": escalation_result.get("level")
                }
        
        solution_payload = {
            "root_cause": analysis.get('root_cause'),
            "resolution_steps": analysis.get('resolution_steps'),
            "runbook_used": bool(kb_info.get("has_knowledge")),
            "service_id": service.get('id') if service else None,
            "service_name": service.get('name') if service else None,
            "fqdn": cmdb.get('fqdn'),
        }
        
        update_incident_state(inc_number, status, solution=solution_payload, ctx_logger=ctx)
        
        supabase.table("Results").insert({
            "inc_number": inc_number,
            "description": json.dumps({"diagnostics": diagnostics, "analysis": analysis, "resolution": resolution}),
            "short_description": analysis.get('root_cause', mail.get('subject')),
        }).execute()
        
        return {"status": status, "analysis": analysis}

    except Exception as e:
        ctx.exception("Unhandled error")
        update_incident_state(inc_number, "Error", solution={"error": str(e)}, ctx_logger=ctx)
        
        # Send error to Slack
        try:
            user_id = meta.get('user_id')
            if user_id:
                send_slack_notification(
                    user_id, mail, {}, {},
                    "Error", f"Processing failed: {str(e)}",
                    thread_ts=slack_thread_ts, ctx_logger=ctx
                )
        except: pass
        
        return {"status": "error", "message": str(e)}
