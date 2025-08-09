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

# Initialize Gemini
genai.configure(api_key=os.getenv('Gemini_Api_Key'))

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
        "clientSecret": os.getenv('clientSecret'),
        "clientId": os.getenv('clientId')
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

def collect_diagnostics(incident: dict, cmdb: dict, ctx_logger=None) -> dict:
    l = ctx_logger or logger
    model = genai.GenerativeModel("gemini-2.0-flash-exp")
    prompt = f"""
Incident: {incident.get('subject')} - {incident.get('message')}
System: {cmdb.get('os')} at {cmdb.get('ip')}

Create a diagnostic plan with specific commands to collect information.
{SYSTEM_PROMPT}
"""
    l.info("Requesting diagnostic plan from AI")
    l.debug(f"AI prompt (truncated): {truncate(prompt)}")
    try:
        response = model.generate_content(prompt)
        l.info("AI diagnostic plan received")
        l.debug(f"AI response (truncated): {truncate(response.text)}")
        plan_json = extract_json(response.text, ctx_logger=l)
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
    model = genai.GenerativeModel("gemini-2.0-flash-exp")
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
    l.info("Sending diagnostics to AI for analysis")
    l.debug(f"AI analysis prompt (truncated): {truncate(prompt)}")
    try:
        response = model.generate_content(prompt)
        l.info("AI analysis response received")
        l.debug(f"AI response (truncated): {truncate(response.text)}")
        parsed = extract_json(response.text, ctx_logger=l)
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
            model = genai.GenerativeModel("gemini-2.0-flash-exp")
            cmd_prompt = f"""
For resolution step: {step}
System: {cmdb.get('os')} at {cmdb.get('ip')}

Generate a specific, non-interactive command to execute this step.
Return ONLY the command string.
"""
            l.debug(f"Command-generation prompt (truncated): {truncate(cmd_prompt)}")
            response = model.generate_content(cmd_prompt)
            command = response.text.strip().replace('```', '').replace('bash', '')
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

def process_incident(aws: dict, mail: dict, ctx_logger=None) -> dict:
    # Create context-aware logger for this incident
    email = None
    ctx = ctx_logger or make_ctx_logger(logger, incident=mail.get('inc_number'), instance=aws.get('instance_id'), user=None)
    ctx.info("Processing incident started")
    try:
        ctx.info("Fetching CMDB entry from Supabase")
        cmdb_response = supabase.table("CMDB").select("*").eq("tag_id", aws.get('instance_id')).execute()

        # SAFE check: APIResponse has .data, do not call .get() on the APIResponse object
        if not getattr(cmdb_response, "data", None):
            ctx.error("CMDB entry not found")
            return {"status": "error", "message": "CMDB entry not found"}

        # Use the .data attribute (it's a list of rows)
        cmdb = cmdb_response.data[0]
        ctx.info(f"CMDB entry found: {truncate(json.dumps(cmdb), 1000)}")

        ctx.info("Fetching user email from Supabase Users table")
        user_response = supabase.table("Users").select("email").eq("id", cmdb.get('user_id')).execute()

        # SAFE check for user_response
        if not getattr(user_response, "data", None):
            ctx.error("User not found in Supabase")
            return {"status": "error", "message": "User not found"}

        # Extract email from .data
        email = user_response.data[0].get('email')
        ctx = make_ctx_logger(logger, incident=mail.get('inc_number'), instance=aws.get('instance_id'), user=email)
        ctx.info(f"User email found: {email}")

        ctx.info("Fetching SSH key")
        if not get_ssh_key(email, ctx_logger=ctx):
            ctx.error("Failed to fetch SSH key from Infisical")
            return {"status": "error", "message": "Failed to fetch SSH key"}

        ctx.info("Collecting diagnostics")
        diagnostics = collect_diagnostics(mail, cmdb, ctx_logger=ctx)

        ctx.info("Analyzing diagnostics")
        analysis = analyze_diagnostics(diagnostics, mail, ctx_logger=ctx)

        ctx.info("Executing resolution steps")
        resolution = execute_resolution(analysis, cmdb, ctx_logger=ctx)

        is_resolved = all(step['result'].get('success') for step in resolution.get('resolution_results', []))
        status = "Resolved" if is_resolved else "Partially Resolved"
        ctx.info(f"Final status determined: {status}")

        ctx.info("Updating incident record in Supabase")
        supabase.table("Incidents").update({
            "state": status,
            "solution": json.dumps({
                "root_cause": analysis.get('root_cause', ''),
                "resolution_steps": analysis.get('resolution_steps', [])
            }),
            "updated_at": datetime.utcnow().isoformat()
        }).eq("inc_number", mail.get('inc_number')).execute()
        ctx.info("Updated Incidents table")

        ctx.info("Inserting result record into Results table")
        supabase.table("Results").insert({
            "inc_number": mail.get('inc_number'),
            "description": json.dumps({
                "diagnostics": diagnostics,
                "analysis": analysis,
                "resolution": resolution
            }),
            "short_description": analysis.get('root_cause', mail.get('subject')),
            "created_at": datetime.utcnow().isoformat()
        }).execute()
        ctx.info("Inserted Results record")

        return {
            "status": status,
            "diagnostics": diagnostics,
            "analysis": analysis,
            "resolution": resolution
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
        try:
            supabase.table("Incidents").update({
                "state": "Error",
                "solution": json.dumps({
                    "error": error_details,
                    "timestamp": datetime.utcnow().isoformat()
                })
            }).eq("inc_number", mail.get('inc_number')).execute()
            ctx.info("Supabase incident update succeeded")
        except Exception:
            ctx.exception("Failed to update Supabase with error details")

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
            queue = sqs.get_queue_by_name(QueueName='infraaiqueue.fifo')
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
                    incident_id = mail_data.get('inc_number', 'unknown')
                    instance_id = aws_data.get('instance_id', 'unknown')
                    user_email = None

                    ctx = make_ctx_logger(logger, incident=incident_id, instance=instance_id, user=None)
                    ctx.info(f"Received SQS message. MessageId={getattr(message, 'message_id', 'unknown')} body(truncated)={truncate(message.body)}")

                    result = process_incident(aws_data, mail_data, ctx_logger=ctx)

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