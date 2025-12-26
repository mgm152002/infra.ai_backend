import time
import json
import os
import boto3
import google.generativeai as genai
from supabase import create_client
from dotenv import load_dotenv
import paramiko
import re
import requests
from datetime import datetime
import traceback
import logging
from logging.handlers import RotatingFileHandler
from pinecone import Pinecone
from openai import OpenAI
from typing import List, Optional, Dict, Any
from langchain_openai import ChatOpenAI
from langchain_core.messages import SystemMessage, HumanMessage

# Shared integrations (same code-path as backend API + chat tools)
from integrations.github import (
    get_github_config,
    github_search_issues as github_search_issues_impl,
)
from integrations.jira import (
    get_jira_config,
    jira_search_issues as jira_search_issues_impl,
)
from integrations.confluence import (
    get_confluence_config,
    confluence_search_pages as confluence_search_pages_impl,
)
from integrations.pagerduty import (
    get_pagerduty_config,
    pagerduty_list_incidents as pagerduty_list_incidents_impl,
)

# --- CONFIG ---
LOG_FILE = "infra_worker.log"
LOG_MAX_BYTES = 10 * 1024 * 1024  # 10MB
LOG_BACKUP_COUNT = 5
LOG_TRUNCATE_LEN = 2000  # truncate long text in logs (set None to disable truncation)
REDACT_SENSITIVE = True  # will avoid logging raw SSH private key content
# ---------------

load_dotenv()

# Initialize Supabase
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# Initialize Boto3 session
session = boto3.Session(
    aws_access_key_id=os.getenv('access_key'),
    aws_secret_access_key=os.getenv('secrete_access'),
    region_name='ap-south-1'
)

SQS_QUEUE_NAME = os.getenv("SQS_QUEUE_NAME", "infraaiqueue.fifo")
# Default per-message visibility timeout in seconds. Should be >= max expected processing time.
SQS_VISIBILITY_TIMEOUT = int(os.getenv("SQS_VISIBILITY_TIMEOUT", "900"))

# Initialize Gemini
genai.configure(api_key=os.getenv('Gemini_Api_Key'))

# Knowledge base (Pinecone + OpenRouter embeddings) configuration
PINECONE_KB_INDEX_NAME = os.getenv("PINECONE_KB_INDEX_NAME", "infraai")
KB_TOP_K_DEFAULT = int(os.getenv("KB_TOP_K_DEFAULT", "5"))
KB_SCORE_THRESHOLD_DEFAULT = float(os.getenv("KB_SCORE_THRESHOLD_DEFAULT", "0.7"))

OPENROUTER_API_KEY = os.getenv("openrouter")
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
OPENROUTER_SITE_URL = os.getenv("OPENROUTER_SITE_URL")
OPENROUTER_SITE_NAME = os.getenv("OPENROUTER_SITE_NAME")
DEFAULT_MODEL_NAME = os.getenv("OPENROUTER_MODEL", "anthropic/claude-sonnet-4.5")

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
    pc = None  # handled gracefully during lookup


def get_llm(model_name: Optional[str] = None, **kwargs) -> ChatOpenAI:
    """Return a ChatOpenAI instance configured to talk to OpenRouter for worker tasks."""
    if not OPENROUTER_API_KEY:
        raise ValueError("OpenRouter API key not set. Please define the 'openrouter' environment variable.")
    return ChatOpenAI(
        model=model_name or DEFAULT_MODEL_NAME,
        api_key=OPENROUTER_API_KEY,
        base_url=OPENROUTER_BASE_URL,
        **kwargs,
    )


def call_llm(
    user_content: str,
    *,
    system_content: Optional[str] = None,
    model_name: Optional[str] = None,
) -> str:
    """Single-turn helper that sends a prompt to OpenRouter and returns the response text."""
    messages: List = []
    if system_content:
        messages.append(SystemMessage(content=system_content))
    messages.append(HumanMessage(content=user_content))
    llm = get_llm(model_name=model_name)
    response = llm.invoke(messages)
    return response.content

SYSTEM_PROMPT = '''You are an AI incident resolver agent. When given an incident description, create a structured plan with these steps:
1. Collect diagnostic information (logs, metrics, system state)
2. Analyze root cause
3. Generate resolution steps
4. Execute resolution
5. Verify resolution

For each step, provide specific commands to run. Always:
- Use non-interactive commands
- Include error handling
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

# --- Logging setup ---
def setup_logger():
    logger = logging.getLogger("infra_worker")
    logger.setLevel(logging.DEBUG)

    # Rotating file handler
    fh = RotatingFileHandler(LOG_FILE, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUP_COUNT)
    fh.setLevel(logging.DEBUG)

    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)

    fmt = "%(asctime)s %(levelname)s %(message)s"
    formatter = logging.Formatter(fmt)
    fh.setFormatter(formatter)
    ch.setFormatter(formatter)

    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger

logger = setup_logger()

def truncate(s: str, n: int = LOG_TRUNCATE_LEN) -> str:
    if s is None:
        return ""
    if n is None:
        return s
    s = str(s)
    if len(s) <= n:
        return s
    return s[:n] + f"... [truncated {len(s)-n} chars]"

def make_ctx_logger(base_logger, incident=None, instance=None, user=None):
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
    if not texts:
        return []
    if embedding_client is None:
        l.debug("Embedding client not configured; skipping knowledge base lookups")
        return []
    try:
        extra_headers: Dict[str, str] = {}
        if OPENROUTER_SITE_URL:
            extra_headers["HTTP-Referer"] = OPENROUTER_SITE_URL
        if OPENROUTER_SITE_NAME:
            extra_headers["X-Title"] = OPENROUTER_SITE_NAME

        kwargs: Dict[str, Any] = {
            "model": "openai/text-embedding-ada-002",
            "input": texts,
            "encoding_format": "float",
        }
        if extra_headers:
            kwargs["extra_headers"] = extra_headers

        response = embedding_client.embeddings.create(**kwargs)
        return [item.embedding for item in response.data]
    except Exception as e:
        l.warning(f"Failed to compute embeddings for knowledge base: {str(e)}")
        return []


def query_knowledge_base(
    query: str,
    top_k: int = KB_TOP_K_DEFAULT,
    score_threshold: float = KB_SCORE_THRESHOLD_DEFAULT,
    ctx_logger=None,
) -> List[dict]:
    l = ctx_logger or logger
    if not query or not query.strip():
        return []

    index = _get_kb_index(ctx_logger=l)
    if index is None:
        return []

    embeddings = _embed_texts([query], ctx_logger=l)
    if not embeddings:
        return []

    try:
        res = index.query(
            vector=embeddings[0],
            top_k=top_k,
            include_metadata=True,
        )
    except Exception as e:
        l.warning(f"Failed to query knowledge base: {str(e)}")
        return []

    matches_raw = []
    if isinstance(res, dict):
        matches_raw = res.get("matches", [])
    elif hasattr(res, "to_dict"):
        res_dict = res.to_dict()
        matches_raw = res_dict.get("matches", [])
    elif hasattr(res, "matches"):
        matches_raw = res.matches

    matches: List[dict] = []
    for m in matches_raw or []:
        if isinstance(m, dict):
            score = m.get("score")
            metadata = m.get("metadata") or {}
        else:
            score = getattr(m, "score", None)
            metadata = getattr(m, "metadata", {}) or {}
        if score is None:
            continue
        if score_threshold is not None and float(score) < float(score_threshold):
            continue
        matches.append(
            {
                "score": float(score),
                "text": metadata.get("text", ""),
                "source": metadata.get("source_file_name") or metadata.get("source") or "",
                "doc_id": metadata.get("doc_id") or "",
                "chunk_index": metadata.get("chunk_index"),
            }
        )
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
        return {
            "has_knowledge": True,
            "matches": matches,
            "combined_context": combined,
        }
    except Exception as e:
        l.warning(f"Knowledge base lookup failed; continuing without runbooks: {str(e)}")
        return {"has_knowledge": False, "matches": [], "combined_context": ""}


def get_prometheus_config_for_user(user_id: Any, ctx_logger=None) -> Optional[dict]:
    """Fetch Prometheus datasource configuration for the given user (if any).

    Expects a Supabase table `PrometheusConfigs` with at least:
      - id (PK)
      - user_id (FK to Users.id)
      - base_url
      - auth_type (e.g. 'none' or 'bearer')
      - bearer_token (optional)
    """
    l = ctx_logger or logger
    if user_id is None:
        return None
    try:
        resp = supabase.table("PrometheusConfigs").select("*").eq("user_id", user_id).limit(1).execute()
        data = getattr(resp, "data", None) or []
        if not data:
            l.info(f"No Prometheus configuration found for user_id={user_id}")
            return None
        l.info(f"Prometheus configuration found for user_id={user_id}")
        return data[0]
    except Exception as e:
        l.warning(f"Failed to fetch Prometheus configuration for user_id={user_id}: {str(e)}")
        return None


def fetch_prometheus_metrics(prom_cfg: dict, cmdb: dict, incident: dict, ctx_logger=None) -> str:
    """Query Prometheus for basic host metrics for this incident.

    Returns a JSON string summarizing the queries and results, or an empty
    string if anything fails. This JSON is intended to be passed as context
    into the diagnostic LLM prompt.
    """
    l = ctx_logger or logger
    base_url = (prom_cfg.get("base_url") or "").rstrip("/")
    if not base_url:
        l.warning("Prometheus configuration missing base_url; skipping metrics collection")
        return ""

    instance_ip = cmdb.get("ip")
    if not instance_ip:
        l.warning("CMDB entry missing 'ip'; cannot form Prometheus instance label")
        return ""

    # Common default for node_exporter targets
    instance_label = f"{instance_ip}:9100"

    queries: Dict[str, str] = {
        "up": f'up{{instance="{instance_label}"}}',
        "cpu_5m": f'avg(rate(node_cpu_seconds_total{{mode!="idle",instance="{instance_label}"}}[5m]))',
        "load1": f'avg_over_time(node_load1{{instance="{instance_label}"}}[5m])',
        "mem_used_ratio": (
            f'(1 - (node_memory_MemAvailable_bytes{{instance="{instance_label}"}} '
            f'/ node_memory_MemTotal_bytes{{instance="{instance_label}"}}))'
        ),
    }

    headers: Dict[str, str] = {}
    auth_type = (prom_cfg.get("auth_type") or "none").lower()
    bearer_token = prom_cfg.get("bearer_token")
    if auth_type == "bearer" and bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"

    metrics_results: Dict[str, Any] = {}
    for name, query in queries.items():
        try:
            resp = requests.get(
                f"{base_url}/api/v1/query",
                params={"query": query},
                headers=headers,
                timeout=10,
            )
            resp.raise_for_status()
            body = resp.json()
            if body.get("status") != "success":
                l.warning(f"Prometheus query '{name}' returned non-success status: {body.get('status')}")
                continue
            result = body.get("data", {}).get("result", [])
            metrics_results[name] = result
        except Exception as e:
            l.warning(f"Prometheus query '{name}' failed: {str(e)}")

    if not metrics_results:
        l.info("No Prometheus metrics available for this incident/instance")
        return ""

    try:
        summary = json.dumps(
            {
                "prometheus_base_url": base_url,
                "instance": instance_label,
                "incident_number": incident.get("inc_number"),
                "queries": queries,
                "results": metrics_results,
            },
            indent=2,
        )
        return summary
    except Exception as e:
        l.warning(f"Failed to serialize Prometheus metrics to JSON: {str(e)}")
        return ""


def _sanitize_query_text(text: str, max_len: int = 200) -> str:
    """Make a safe, short query string for external systems (JQL/CQL/GitHub search)."""
    t = (text or "").strip()
    t = re.sub(r"[\r\n\t]+", " ", t)
    # Remove characters that commonly break query syntaxes
    t = re.sub(r"[\"\\]", " ", t)
    t = re.sub(r"\s+", " ", t).strip()
    if len(t) > max_len:
        t = t[:max_len].rstrip()
    return t


def fetch_external_integrations_context(email: str, incident: dict, ctx_logger=None) -> str:
    """Fetch supporting context from configured external systems.

    This allows the worker to use the same integrations as the chat endpoint:
    - GitHub issues/PRs search
    - Jira issues search
    - Confluence page search
    - PagerDuty incidents list

    For each integration we first check whether credentials are configured
    for this user (based on what they entered on the Credentials page).
    We then:
      * log a clear message if the integration is not configured
      * only call the external API when credentials are present
      * return a JSON blob that includes both `credential_status` and
        any fetched `sources`.

    Returns a JSON string suitable for adding into the incident diagnostic prompt.
    """
    l = ctx_logger or logger
    try:
        subj = incident.get("subject") or ""
        msg = incident.get("message") or ""
        q = _sanitize_query_text(f"{subj} {msg}")
        if not q:
            return ""

        out: Dict[str, Any] = {
            "query": q,
            "credential_status": {},
            "sources": {},
        }

        # --- GitHub ---
        try:
            gh_cfg = get_github_config(email)
            gh_configured = bool(gh_cfg.get("token"))
            out["credential_status"]["github"] = {
                "configured": gh_configured,
                "has_default_repo": bool(gh_cfg.get("default_owner") and gh_cfg.get("default_repo")),
            }
            if gh_configured:
                l.info("GitHub integration configured for this user; fetching GitHub context")
                gh = github_search_issues_impl(mail=email, query=q, max_results=5)
                out["sources"]["github"] = gh
            else:
                l.info("GitHub integration not configured for this user; skipping GitHub context")
        except Exception as e:
            l.debug(f"GitHub integration lookup failed: {str(e)}")
            out["credential_status"]["github"] = {
                "configured": False,
                "error": str(e),
            }

        # --- Jira ---
        try:
            jira_cfg = get_jira_config(email)
            jira_configured = bool(
                jira_cfg.get("base_url")
                and jira_cfg.get("api_token")
                and jira_cfg.get("email")
            )
            out["credential_status"]["jira"] = {
                "configured": jira_configured,
            }
            if jira_configured:
                l.info("Jira integration configured for this user; fetching Jira context")
                jql = f'text ~ "{q}" ORDER BY updated DESC'
                ji = jira_search_issues_impl(mail=email, jql=jql, max_results=5)
                out["sources"]["jira"] = ji
            else:
                l.info("Jira integration not configured for this user; skipping Jira context")
        except Exception as e:
            l.debug(f"Jira integration lookup failed: {str(e)}")
            out["credential_status"]["jira"] = {
                "configured": False,
                "error": str(e),
            }

        # --- Confluence ---
        try:
            conf_cfg = get_confluence_config(email)
            conf_configured = bool(
                conf_cfg.get("base_url")
                and conf_cfg.get("api_token")
                and conf_cfg.get("email")
            )
            out["credential_status"]["confluence"] = {
                "configured": conf_configured,
            }
            if conf_configured:
                l.info("Confluence integration configured for this user; fetching Confluence context")
                cql = f'text ~ "{q}" ORDER BY lastmodified DESC'
                cf = confluence_search_pages_impl(mail=email, cql=cql, limit=5)
                out["sources"]["confluence"] = cf
            else:
                l.info("Confluence integration not configured for this user; skipping Confluence context")
        except Exception as e:
            l.debug(f"Confluence integration lookup failed: {str(e)}")
            out["credential_status"]["confluence"] = {
                "configured": False,
                "error": str(e),
            }

        # --- PagerDuty ---
        try:
            pd_cfg = get_pagerduty_config(email)
            pd_configured = bool(pd_cfg.get("api_token"))
            out["credential_status"]["pagerduty"] = {
                "configured": pd_configured,
            }
            if pd_configured:
                l.info("PagerDuty integration configured for this user; fetching PagerDuty context")
                pd = pagerduty_list_incidents_impl(
                    mail=email,
                    statuses=["triggered", "acknowledged"],
                    limit=10,
                )
                out["sources"]["pagerduty"] = pd
            else:
                l.info("PagerDuty integration not configured for this user; skipping PagerDuty context")
        except Exception as e:
            l.debug(f"PagerDuty integration lookup failed: {str(e)}")
            out["credential_status"]["pagerduty"] = {
                "configured": False,
                "error": str(e),
            }

        # If nothing is configured or all lookups failed, avoid adding empty noise
        if not out["sources"]:
            any_configured = any(
                v.get("configured") for v in out["credential_status"].values()
            )
            if not any_configured:
                l.info("No external integrations are configured for this user; skipping external context")
                return ""

        return json.dumps(out, indent=2)
    except Exception as e:
        l.debug(f"External integrations context failed: {str(e)}")
        return ""


# --- Utility functions ---
def get_username(os_type: str) -> str:
    os_type = (os_type or "").lower()
    if 'ubuntu' in os_type:
        return 'ubuntu'
    if 'amazon' in os_type or 'linux' in os_type:
        return 'ec2-user'
    if 'rhel' in os_type or 'centos' in os_type:
        return 'ec2-user'
    if 'debian' in os_type:
        return 'admin'
    if 'suse' in os_type:
        return 'ec2-user'
    return 'admin'

# --- Core functions (instrumented with logging) ---
def run_shell_command(command: str, hostname: str, username: str, key_file: str = 'key.pem', ctx_logger=None) -> dict:
    """Execute command on remote host via SSH and log step-by-step"""
    l = ctx_logger or logger
    l.info(f"Preparing to run remote command on {hostname} as {username}: {truncate(command, 1000)}")
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        l.debug("Creating SSHClient and attempting connection")
        ssh.connect(hostname, username=username, key_filename=key_file, timeout=30)
        l.info("SSH connection established")

        full_command = f"export TERM=xterm-256color && {command}"
        l.debug(f"Executing command: {truncate(full_command, 1000)}")
        stdin, stdout, stderr = ssh.exec_command(full_command, timeout=120)

        out = stdout.read().decode(errors='replace')
        err = stderr.read().decode(errors='replace')

        l.debug(f"Command finished. stdout length={len(out)} stderr length={len(err)}")
        l.info(f"stdout: {truncate(out)}")
        if err:
            l.warning(f"stderr: {truncate(err)}")

        ssh.close()
        l.debug("SSH connection closed")

        # success defined as no stderr *and* exit status 0 (paramiko doesn't expose exit status here easily)
        success = not bool(err.strip())

        return {
            "command": command,
            "output": out,
            "error": err,
            "success": success
        }
    except Exception as e:
        l.exception(f"SSH command execution failed: {str(e)}")
        return {
            "command": command,
            "output": "",
            "error": str(e),
            "success": False
        }

def verify_output(result: dict, expected: str, ctx_logger=None) -> bool:
    l = ctx_logger or logger
    l.debug(f"Verifying output against expected pattern: {truncate(expected)}")
    if not result.get('success'):
        l.debug("verify_output: result indicates failure")
        return False

    patterns = [
        r'error', r'fail', r'exception', r'not found',
        r'permission denied', r'timeout', r'unable'
    ]

    for pattern in patterns:
        if re.search(pattern, result.get('output', ''), re.IGNORECASE):
            l.debug(f"verify_output: detected pattern '{pattern}' in output -> failing verification")
            return False

    l.debug("verify_output: output passed basic checks")
    return True

def extract_json(text: str, ctx_logger=None) -> dict:
    l = ctx_logger or logger
    l.debug("Attempting to extract JSON from AI response")
    try:
        json_match = re.search(r'\{[\s\S]*\}', text)
        if json_match:
            parsed = json.loads(json_match.group())
            l.debug("Successfully extracted JSON using regex wrapper")
            return parsed
    except Exception:
        l.debug("Regex JSON extraction failed; will try direct JSON load", exc_info=True)

    try:
        parsed = json.loads(text)
        l.debug("Successfully parsed JSON directly")
        return parsed
    except Exception:
        l.warning("Failed to parse JSON from AI response. Returning empty todos.")
        return {"todos": []}

def get_ssh_key(mail: str, ctx_logger=None) -> bool:
    l = ctx_logger or logger
    l.info(f"Fetching SSH key for user mailbox: {mail}")
    secret_auth_uri = "https://app.infisical.com/api/v1/auth/universal-auth/login"
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    auth_data = {
        "clientId": os.getenv('clientId'),
        "clientSecret": os.getenv('clientSecret')
    }
    try:
        l.debug("Requesting Infisical access token")
        response = requests.post(url=secret_auth_uri, headers=headers, data=auth_data, timeout=20)
        response.raise_for_status()
        access_token = response.json().get('accessToken')
        if not access_token:
            l.error("No access token returned from Infisical")
            return False
        auth_headers = {'Authorization': f'Bearer {access_token}'}
        base_url = 'https://us.infisical.com/api/v3/secrets/raw'
        l.debug("Requesting SSH key secret value")
        sshkey_resp = requests.get(
            f'{base_url}/SSH_KEY_{mail}?workspaceSlug=infraai-oqb-h&environment=prod',
            headers=auth_headers,
            timeout=20
        )
        sshkey_resp.raise_for_status()
        sshkey = sshkey_resp.json()
        secret_val = sshkey.get('secret', {}).get('secretValue')
        if not secret_val:
            l.error("SSH secret value not found in response")
            return False

        # write key file
        with open("key.pem", "wb") as file:
            if REDACT_SENSITIVE:
                # do not log raw key material
                file.write(secret_val.encode('utf-8'))
                l.info("SSH key written to key.pem (contents redacted in logs)")
            else:
                file.write(secret_val.encode('utf-8'))
                l.info("SSH key written to key.pem (contents may be sensitive)")

        os.chmod("key.pem", 0o600)
        l.info("SSH key saved and file permissions set to 600")
        return True
    except Exception as e:
        l.exception(f"Error fetching SSH key: {str(e)}")
        return False

def collect_diagnostics(
    incident: dict,
    cmdb: dict,
    kb_context: str = "",
    prometheus_context: str = "",
    external_context: str = "",
    ctx_logger=None,
) -> dict:
    l = ctx_logger or logger

    if kb_context:
        kb_block = f"""
Known runbook / SOP context from the internal knowledge base:
{kb_context}

Use the above runbook instructions as your primary guidance when creating the plan.
Where the runbook is incomplete or ambiguous, you may fall back to your own best practices.
"""
    else:
        kb_block = """
No specific runbook or SOP context was found in the internal knowledge base for this incident.
Proceed with your default troubleshooting approach based on the incident details and system information.
"""

    if prometheus_context:
        prom_block = f"""
Additional Prometheus metrics for this incident (JSON from Prometheus HTTP API):

{prometheus_context}

Use this metrics context when deciding what diagnostics to run and how to prioritize checks.
"""
    else:
        prom_block = """
No Prometheus metrics could be retrieved for this incident. Proceed without using Prometheus data.
"""

    if external_context:
        ext_block = f"""
Supporting context from external systems (GitHub/Jira/Confluence/PagerDuty):

{external_context}

Use this to recognize known issues, link relevant tickets/runbooks, and speed up diagnosis.
"""
    else:
        ext_block = """
No additional context could be retrieved from external systems.
"""

    prompt = f"""
Incident: {incident.get('subject')} - {incident.get('message')}
System: {cmdb.get('os')} at {cmdb.get('ip')}

{kb_block}
{prom_block}
{ext_block}
Create a diagnostic plan with specific commands to collect information.
{SYSTEM_PROMPT}
"""
    l.info("Requesting diagnostic plan from AI (OpenRouter)")
    l.debug(f"AI prompt (truncated): {truncate(prompt)}")
    try:
        response_text = call_llm(prompt)
        l.info("AI diagnostic plan received")
        l.debug(f"AI response (truncated): {truncate(response_text)}")
        plan_json = extract_json(response_text, ctx_logger=l)
    except Exception as e:
        l.exception(f"AI call for diagnostics failed: {str(e)}")
        plan_json = {"todos": []}

    results = []
    for idx, todo in enumerate(plan_json.get('todos', []), start=1):
        l.info(f"Running diagnostic step {idx}: {todo.get('step')}")
        l.debug(f"Command: {truncate(todo.get('command'))} Expected: {truncate(todo.get('expected_output'))}")
        result = run_shell_command(
            command=todo.get('command'),
            hostname=cmdb.get('ip'),
            username=get_username(cmdb.get('os')),
            ctx_logger=l
        )
        verified = verify_output(result, todo.get('expected_output', ''), ctx_logger=l)
        l.info(f"Step '{todo.get('step')}' completed. success={result.get('success')} verified={verified}")
        results.append({
            **todo,
            **result,
            "verified": verified
        })

    return {
        "diagnostics": results,
        "raw_response": truncate(plan_json)  # store truncated plan in logs/results
    }

def analyze_diagnostics(diagnostics: dict, incident: dict, ctx_logger=None) -> dict:
    l = ctx_logger or logger
    prompt = f"""
Incident: {incident.get('subject')} - {incident.get('message')}
Diagnostic results:
{json.dumps(diagnostics, indent=2)}

Analyze the diagnostic data and determine:
1. Root cause
2. Resolution steps
3. Verification method

Return in JSON format:
{{
  "root_cause": "description",
  "resolution_steps": ["step1", "step2"],
  "verification": "how to verify"
}}
"""
    l.info("Sending diagnostics to AI for analysis (OpenRouter)")
    l.debug(f"AI analysis prompt (truncated): {truncate(prompt)}")
    try:
        response_text = call_llm(prompt)
        l.info("AI analysis response received")
        l.debug(f"AI response (truncated): {truncate(response_text)}")
        parsed = extract_json(response_text, ctx_logger=l)
        return parsed
    except Exception as e:
        l.exception(f"AI analysis failed: {str(e)}")
        return {
            "root_cause": "analysis_failed",
            "resolution_steps": [],
            "verification": ""
        }

def execute_resolution(resolution: dict, cmdb: dict, ctx_logger=None) -> dict:
    l = ctx_logger or logger
    results = []
    for idx, step in enumerate(resolution.get('resolution_steps', []), start=1):
        l.info(f"Generating command for resolution step {idx}: {step}")
        try:
            cmd_prompt = f"""
For resolution step: {step}
System: {cmdb.get('os')} at {cmdb.get('ip')}

Generate a specific, non-interactive command to execute this step.
Return ONLY the command string.
"""
            l.debug(f"Command-generation prompt (truncated): {truncate(cmd_prompt)}")
            response_text = call_llm(cmd_prompt)
            command = response_text.strip().replace('```', '').replace('bash', '')
            command = truncate(command, 4000)  # command may be long; keep manageable in logs
            l.info(f"Generated command (truncated): {truncate(command)}")
        except Exception as e:
            l.exception(f"Failed to generate command for step '{step}': {str(e)}")
            command = ""

        result = run_shell_command(
            command=command,
            hostname=cmdb.get('ip'),
            username=get_username(cmdb.get('os')),
            ctx_logger=l
        )
        l.info(f"Resolution step '{step}' executed. success={result.get('success')}")
        results.append({
            "step": step,
            "command": command,
            "result": result
        })

    return {"resolution_results": results}


def update_incident_state(inc_number: Optional[str], state: str, solution: Optional[dict] = None, ctx_logger=None) -> None:
    """Safely update incident state (and optional solution) in Supabase.

    This centralizes state transitions so they stay consistent across success,
    validation errors, and unexpected exceptions.
    """
    l = ctx_logger or logger
    if not inc_number:
        l.warning("Cannot update incident state: missing inc_number")
        return
    try:
        update_data: Dict[str, Any] = {
            "state": state,
            "updated_at": datetime.utcnow().isoformat(),
        }
        if solution is not None:
            update_data["solution"] = json.dumps(solution)
        supabase.table("Incidents").update(update_data).eq("inc_number", inc_number).execute()
        l.info(f"Incident {inc_number} state updated to '{state}'")
    except Exception as e:
        l.exception(f"Failed to update incident {inc_number} state to '{state}': {str(e)}")



def process_incident(aws: dict, mail: dict, meta: Optional[dict] = None, ctx_logger=None) -> dict:
    # Create context-aware logger for this incident
    email = None
    meta = meta or {}
    instance_label = meta.get('tag_id') or aws.get('instance_id')
    ctx = ctx_logger or make_ctx_logger(logger, incident=mail.get('inc_number'), instance=instance_label, user=None)
    ctx.info("Processing incident started")
    try:
        inc_number = mail.get('inc_number')
        # Mark incident as actively being processed (was previously just "in queue")
        update_incident_state(inc_number, "Processing", ctx_logger=ctx)

        ctx.info("Fetching CMDB entry from Supabase")

        cmdb = None
        # Primary lookup: use Meta.tag_id (and Meta.user_id if present) from the SQS message
        meta_tag_id = meta.get('tag_id')
        if meta_tag_id:
            ctx.info(f"Attempting CMDB lookup using Meta.tag_id='{meta_tag_id}'")
            cmdb_query = supabase.table("CMDB").select("*").eq("tag_id", meta_tag_id)
            meta_user_id = meta.get('user_id')
            if meta_user_id is not None:
                cmdb_query = cmdb_query.eq("user_id", meta_user_id)
            meta_cmdb_response = cmdb_query.execute()
            if getattr(meta_cmdb_response, "data", None):
                cmdb = meta_cmdb_response.data[0]
                ctx.info(f"CMDB entry found via Meta.tag_id: {truncate(json.dumps(cmdb), 1000)}")

        # Fallback lookup: use Aws.instance_id as tag_id (legacy behaviour)
        if cmdb is None:
            instance_tag = aws.get('instance_id')
            ctx.info(f"Falling back to CMDB lookup using Aws.instance_id as tag_id: '{instance_tag}'")
            if instance_tag:
                cmdb_response = supabase.table("CMDB").select("*").eq("tag_id", instance_tag).execute()

                # SAFE check: APIResponse has .data, do not call .get() on the APIResponse object
                if getattr(cmdb_response, "data", None):
                    cmdb = cmdb_response.data[0]
                    ctx.info(f"CMDB entry found via Aws.instance_id: {truncate(json.dumps(cmdb), 1000)}")

        if cmdb is None:
            ctx.error("CMDB entry not found (checked Meta.tag_id and Aws.instance_id)")
            update_incident_state(
                mail.get('inc_number'),
                "Error",
                solution={
                    "error": "CMDB entry not found",
                    "timestamp": datetime.utcnow().isoformat(),
                },
                ctx_logger=ctx,
            )
            return {"status": "error", "message": "CMDB entry not found"}

        ctx.info("Fetching user email from Supabase Users table")
        user_response = supabase.table("Users").select("email").eq("id", cmdb.get('user_id')).execute()

        # SAFE check for user_response
        if not getattr(user_response, "data", None):
            ctx.error("User not found in Supabase")
            update_incident_state(
                mail.get('inc_number'),
                "Error",
                solution={
                    "error": "User not found in Supabase",
                    "timestamp": datetime.utcnow().isoformat(),
                },
                ctx_logger=ctx,
            )
            return {"status": "error", "message": "User not found"}

        # Extract email from .data
        email = user_response.data[0].get('email')
        ctx = make_ctx_logger(logger, incident=mail.get('inc_number'), instance=aws.get('instance_id'), user=email)
        ctx.info(f"User email found: {email}")

        ctx.info("Fetching SSH key")
        if not get_ssh_key(email, ctx_logger=ctx):
            ctx.error("Failed to fetch SSH key from Infisical")
            update_incident_state(
                mail.get('inc_number'),
                "Error",
                solution={
                    "error": "Failed to fetch SSH key from Infisical",
                    "timestamp": datetime.utcnow().isoformat(),
                },
                ctx_logger=ctx,
            )
            return {"status": "error", "message": "Failed to fetch SSH key"}

        ctx.info("Checking knowledge base for runbooks/SOPs for this incident")
        kb_info = get_incident_runbook_context(mail, ctx_logger=ctx)

        # Optional Prometheus metrics context (if the user has configured a Prometheus data source)
        prometheus_context = ""
        user_id = cmdb.get('user_id')
        if user_id is not None:
            ctx.info("Checking for Prometheus configuration for this user")
            prom_cfg = get_prometheus_config_for_user(user_id, ctx_logger=ctx)
            if prom_cfg:
                ctx.info("Fetching Prometheus metrics for this incident")
                prometheus_context = fetch_prometheus_metrics(prom_cfg, cmdb, mail, ctx_logger=ctx)
            else:
                ctx.info("No Prometheus configuration found; skipping Prometheus metrics")

        # Optional external integrations context (GitHub/Jira/Confluence/PagerDuty)
        external_context = ""
        try:
            ctx.info("Fetching external integrations context")
            external_context = fetch_external_integrations_context(email, mail, ctx_logger=ctx)
        except Exception as e:
            ctx.debug(f"External integrations context collection failed: {str(e)}")
            external_context = ""

        ctx.info("Collecting diagnostics")
        diagnostics = collect_diagnostics(
            mail,
            cmdb,
            kb_context=kb_info.get("combined_context", "") if kb_info else "",
            prometheus_context=prometheus_context,
            external_context=external_context,
            ctx_logger=ctx,
        )

        ctx.info("Analyzing diagnostics")
        analysis = analyze_diagnostics(diagnostics, mail, ctx_logger=ctx)

        ctx.info("Executing resolution steps")
        resolution = execute_resolution(analysis, cmdb, ctx_logger=ctx)

        is_resolved = all(step['result'].get('success') for step in resolution.get('resolution_results', []))
        status = "Resolved" if is_resolved else "Partially Resolved"
        ctx.info(f"Final status determined: {status}")

        solution_payload = {
            "root_cause": analysis.get('root_cause', ''),
            "resolution_steps": analysis.get('resolution_steps', []),
            "runbook_used": bool(kb_info.get("has_knowledge")) if kb_info else False,
        }
        if kb_info and kb_info.get("has_knowledge"):
            # Store lightweight metadata about matched runbooks for traceability
            solution_payload["runbook_matches"] = [
                {
                    "score": m.get("score"),
                    "source": m.get("source"),
                    "doc_id": m.get("doc_id"),
                    "chunk_index": m.get("chunk_index"),
                }
                for m in kb_info.get("matches", [])
            ]

        ctx.info("Updating incident record in Supabase")
        update_incident_state(
            mail.get('inc_number'),
            status,
            solution=solution_payload,
            ctx_logger=ctx,
        )
        ctx.info("Updated Incidents table")

        ctx.info("Inserting result record into Results table")
        supabase.table("Results").insert({
            "inc_number": mail.get('inc_number'),
            "description": json.dumps({
                "diagnostics": diagnostics,
                "analysis": analysis,
                "resolution": resolution,
                "knowledge_base": kb_info,
            }),
            "short_description": analysis.get('root_cause', mail.get('subject')),
            "created_at": datetime.utcnow().isoformat()
        }).execute()
        ctx.info("Inserted Results record")

        return {
            "status": status,
            "diagnostics": diagnostics,
            "analysis": analysis,
            "resolution": resolution,
            "knowledge_base": kb_info,
        }

    except Exception as e:
        ctx.exception("Unhandled error while processing incident")
        error_details = {
            "error_type": type(e).__name__,
            "error_message": str(e),
            "stack_trace": traceback.format_exc(),
            "incident_number": mail.get('inc_number', 'unknown'),
            "instance_id": aws.get('instance_id', 'unknown') if aws else 'unknown',
            "user_email": email or 'unknown'
        }

        ctx.info("Updating incident with error details in Supabase")
        update_incident_state(
            mail.get('inc_number'),
            "Error",
            solution={
                "error": error_details,
                "timestamp": datetime.utcnow().isoformat(),
            },
            ctx_logger=ctx,
        )

        return {"status": "error", "message": json.dumps(error_details)}
    finally:
        # Clean up SSH key file
        try:
            if os.path.exists("key.pem"):
                os.remove("key.pem")
                ctx = ctx_logger or make_ctx_logger(logger, incident=mail.get('inc_number'), instance=aws.get('instance_id'), user=email)
                ctx.info("Removed temporary SSH key file key.pem")
        except Exception:
            logger.exception("Failed to remove key.pem during cleanup")

def worker_loop():
    logger.info("Worker started - monitoring incident queue")
    while True:
        try:
            sqs = session.resource('sqs')
            queue = sqs.get_queue_by_name(QueueName=SQS_QUEUE_NAME)
            messages = queue.receive_messages(
                MessageAttributeNames=['All'],
                MaxNumberOfMessages=1,
                WaitTimeSeconds=20
            )
            if not messages:
                logger.debug("No messages received; continuing")
                continue

            for message in messages:
                try:
                    body = json.loads(message.body)
                    aws_data = body.get("Aws", {})
                    mail_data = body.get("Mail", {})
                    meta_data = body.get("Meta", {})
                    incident_id = mail_data.get('inc_number', 'unknown')
                    instance_id = meta_data.get('tag_id') or aws_data.get('instance_id', 'unknown')
                    user_email = None

                    ctx = make_ctx_logger(logger, incident=incident_id, instance=instance_id, user=None)
                    ctx.info(f"Received SQS message. MessageId={getattr(message, 'message_id', 'unknown')} body(truncated)={truncate(message.body)}")

                    # Ensure the message stays invisible for long-running processing.
                    try:
                        message.change_visibility(VisibilityTimeout=SQS_VISIBILITY_TIMEOUT)
                        ctx.info(f"Extended SQS message visibility timeout to {SQS_VISIBILITY_TIMEOUT} seconds")
                    except Exception:
                        ctx.exception("Failed to extend SQS message visibility timeout; proceeding with default queue setting")

                    result = process_incident(aws_data, mail_data, meta_data, ctx_logger=ctx)

                    if result.get('status') in ['Resolved', 'Partially Resolved']:
                        try:
                            message.delete()
                            ctx.info(f"Incident {incident_id} processed successfully; SQS message deleted")
                        except Exception:
                            ctx.exception("Failed to delete SQS message after successful processing")
                    else:
                        ctx.warning(f"Incident {incident_id} processing returned non-success status: {result.get('status')}")

                except Exception as e:
                    logger.exception(f"Error processing message: {str(e)}")
                    # keep message for retry
        except Exception as e:
            logger.exception(f"Worker loop unexpected error: {str(e)}")
            time.sleep(60)

if __name__ == "__main__":
    worker_loop()