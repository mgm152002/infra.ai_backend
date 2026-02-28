import time
import json
import os
import re
import threading
import boto3
from datetime import datetime
from dotenv import load_dotenv

from app.core.logger import logger, make_ctx_logger
from app.services.incident_service import process_incident, process_incident_streaming, emit_sse_incident_event
from app.core.config import settings
from app.db.session import supabase # Importing supabase for Job updates
from integrations.infisical import get_default_slack_channel
from integrations.slack import SlackIntegration

# --- CONFIG ---
load_dotenv()

# Initialize Boto3 session
session = boto3.Session(
    aws_access_key_id=settings.AWS_ACCESS_KEY_ID or os.getenv('access_key'),
    aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY or os.getenv('secrete_access'),
    region_name=settings.AWS_REGION
)

SQS_QUEUE_NAME = settings.SQS_QUEUE_NAME
SQS_VISIBILITY_TIMEOUT = int(os.getenv("SQS_VISIBILITY_TIMEOUT", "900"))
WORKER_HEARTBEAT_SECONDS = int(os.getenv("WORKER_HEARTBEAT_SECONDS", "30"))

def truncate(s: str, n: int = 2000) -> str:
    if s is None: return ""
    return str(s) if len(str(s)) <= n else str(s)[:n] + f"... [truncated {len(str(s))-n} chars]"


def _queue_metrics(queue):
    """Return approximate queue depth metrics for visibility."""
    try:
        queue.reload()
        attrs = queue.attributes or {}
        return {
            "visible": int(attrs.get("ApproximateNumberOfMessages", 0)),
            "inflight": int(attrs.get("ApproximateNumberOfMessagesNotVisible", 0)),
            "delayed": int(attrs.get("ApproximateNumberOfMessagesDelayed", 0)),
        }
    except Exception:
        return {"visible": -1, "inflight": -1, "delayed": -1}

def send_default_channel_notification(incident_id: str, status: str, message: str, ctx_logger=None):
    """Send Slack notification to the default channel from Infisical."""
    l = ctx_logger or logger
    
    try:
        # Get default channel from Infisical
        default_channel = get_default_slack_channel() or "#incidents"
        
        # Keep Slack channel IDs unchanged (e.g. C0123ABCD), otherwise normalize to #channel.
        is_channel_id = bool(re.match(r"^[CGD][A-Z0-9]{8,}$", default_channel or ""))
        if not is_channel_id and not default_channel.startswith('#'):
            default_channel = '#' + default_channel
        
        # Get Slack token
        from integrations.infisical import get_secret
        slack_token = get_secret("SLACK_BOT_TOKEN") or os.getenv("SLACK_BOT_TOKEN")
        
        if not slack_token:
            l.debug("No Slack token available, skipping default channel notification")
            return None
        
        slack = SlackIntegration(token=slack_token)
        
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
        
        text = f"{status_emoji} *Incident {incident_id}*: {status} - {message}"
        
        result = slack.send_message(default_channel, text)
        
        if result.get("ok"):
            l.info(f"Slack notification sent to default channel {default_channel} for incident {incident_id}")
            return result.get("ts")
        else:
            error_msg = result.get('error', '')
            if 'channel_not_found' in error_msg:
                l.warning(f"Slack channel '{default_channel}' not found. Trying fallback #general")
                # Try #general as fallback
                result = slack.send_message("#general", text)
                if result.get("ok"):
                    l.info(f"Slack notification sent to #general for incident {incident_id}")
                    return result.get("ts")
                l.warning(
                    "Slack fallback failed. Ensure the bot is invited to the target channel "
                    "or set a valid channel/channel_id in secrets."
                )
            l.warning(f"Failed to send Slack notification to default channel: {error_msg}")
            return None
            
    except Exception as e:
        l.warning(f"Error sending Slack notification to default channel: {str(e)}")
        return None

def worker_loop():
    logger.info(
        f"Worker started - monitoring SQS queue '{SQS_QUEUE_NAME}' "
        f"(region={settings.AWS_REGION}, thread={threading.current_thread().name})"
    )
    last_heartbeat = 0.0
    empty_polls = 0

    while True:
        try:
            sqs = session.resource('sqs')
            queue = sqs.get_queue_by_name(QueueName=SQS_QUEUE_NAME)

            now = time.time()
            if now - last_heartbeat >= WORKER_HEARTBEAT_SECONDS:
                metrics = _queue_metrics(queue)
                heartbeat_msg = (
                    "[worker-heartbeat] "
                    f"queue={SQS_QUEUE_NAME} visible={metrics['visible']} "
                    f"inflight={metrics['inflight']} delayed={metrics['delayed']} "
                    f"thread={threading.current_thread().name}"
                )
                if metrics["visible"] == 0 and metrics["inflight"] > 0:
                    heartbeat_msg += (
                        f" | inflight messages are invisible/leased. "
                        f"If no active worker is processing them, they will reappear "
                        f"after visibility timeout ({SQS_VISIBILITY_TIMEOUT}s)."
                    )
                logger.info(heartbeat_msg)
                last_heartbeat = now

            messages = queue.receive_messages(
                MessageAttributeNames=['All'],
                MaxNumberOfMessages=1,
                WaitTimeSeconds=20
            )
            if not messages:
                empty_polls += 1
                if empty_polls % 3 == 0:
                    metrics = _queue_metrics(queue)
                    logger.info(
                        "[worker-poll] no messages received "
                        f"(queue={SQS_QUEUE_NAME}, visible={metrics['visible']}, "
                        f"inflight={metrics['inflight']})"
                    )
                continue
            empty_polls = 0
            logger.info(
                f"[worker-poll] received {len(messages)} message(s) from queue={SQS_QUEUE_NAME}"
            )

            for message in messages:
                try:
                    body = json.loads(message.body)
                    aws_data = body.get("Aws", {})
                    mail_data = body.get("Mail", {})
                    meta_data = body.get("Meta", {})
                    incident_id = mail_data.get('inc_number', 'unknown')
                    instance_id = meta_data.get('tag_id') or aws_data.get('instance_id', 'unknown')

                    job_id = meta_data.get('job_id')
                    
                    ctx = make_ctx_logger(logger, incident=incident_id, instance=instance_id)
                    ctx.info(
                        "🚀 Worker picked up incident from SQS "
                        f"(queue={SQS_QUEUE_NAME}, message_id={getattr(message, 'message_id', 'unknown')}, "
                        f"incident={incident_id}, job_id={job_id}, user_id={meta_data.get('user_id')})"
                    )

                    # Immediately reflect that the worker has started processing.
                    try:
                        supabase.table("Incidents").update({
                            "state": "Processing",
                            "updated_at": datetime.utcnow().isoformat(),
                        }).eq("inc_number", incident_id).execute()
                    except Exception as e:
                        ctx.warning(f"Failed to set incident state=Processing at pickup: {e}")

                    # --- Resolve user_id FIRST before any notifications/SSE ---
                    user_id = meta_data.get('user_id')
                    if not user_id:
                        try:
                            inc_resp = supabase.table("Incidents").select("user_id").eq("inc_number", incident_id).execute()
                            if inc_resp.data:
                                user_id = inc_resp.data[0].get("user_id")
                        except Exception:
                            pass

                    # If user context is unavailable, keep a fallback notification.
                    # Otherwise, process_incident_streaming will own threaded Slack updates.
                    if not user_id:
                        send_default_channel_notification(
                            incident_id,
                            "Received",
                            f"New incident received from SQS - {mail_data.get('subject', 'No subject')}",
                            ctx_logger=ctx
                        )

                    # Emit SSE event for new incident (user_id now safely assigned)
                    try:
                        emit_sse_incident_event(
                            incident_id,
                            "incident_received",
                            {
                                "incident_number": incident_id,
                                "subject": mail_data.get('subject', ''),
                                "instance_id": instance_id,
                                "status": "Received",
                                "user_id": user_id
                            },
                            ctx_logger=ctx,
                            user_id=user_id
                        )
                        emit_sse_incident_event(
                            incident_id,
                            "status_update",
                            {
                                "incident_number": incident_id,
                                "status": "Processing",
                                "message": "Worker picked incident from SQS and started processing",
                            },
                            ctx_logger=ctx,
                            user_id=user_id
                        )
                    except Exception as e:
                        ctx.warning(f"Failed to emit SSE event: {str(e)}")

                    # Ensure the message stays invisible for long-running processing.
                    try:
                        message.change_visibility(VisibilityTimeout=SQS_VISIBILITY_TIMEOUT)
                        ctx.info(f"Extended SQS message visibility timeout to {SQS_VISIBILITY_TIMEOUT} seconds")
                    except Exception:
                        ctx.exception("Failed to extend SQS message visibility timeout; proceeding with default queue setting")

                    # Update Job Status - Running
                    if job_id:
                        try:
                            supabase.table("Jobs").update({
                                "status": "running", 
                                "progress": 0,
                                "details": {"stage": "worker_processing_started"}
                            }).eq("id", job_id).execute()
                        except Exception as e:
                            ctx.warning(f"Failed to update Job {job_id} status: {e}")
                    
                    # Use the streaming incident processor so tool usage, results,
                    # status updates, and RCA generation are all persisted consistently.
                    if user_id:
                        result = process_incident_streaming(
                            inc_number=incident_id,
                            user_id=user_id,
                            ctx_logger=ctx
                        )
                    else:
                        # Fallback to old process_incident if no user_id
                        result = process_incident(aws_data, mail_data, meta_data, ctx_logger=ctx)

                    if result.get('status') in ['Resolved', 'Partially Resolved']:
                        try:
                            message.delete()
                            ctx.info(f"Incident {incident_id} processed successfully; SQS message deleted")
                            
                            # Update Job - Completed
                            if job_id:
                                try:
                                    supabase.table("Jobs").update({
                                        "status": "completed", 
                                        "progress": 100,
                                        "details": {"result": result}
                                    }).eq("id", job_id).execute()
                                except Exception: 
                                    pass

                        except Exception:
                            ctx.exception("Failed to delete SQS message after successful processing")
                    else:
                        ctx.warning(f"Incident {incident_id} processing returned non-success status: {result.get('status')}")
                        try:
                            retry_visibility = min(60, SQS_VISIBILITY_TIMEOUT)
                            message.change_visibility(VisibilityTimeout=retry_visibility)
                            ctx.info(
                                f"Set quick retry visibility timeout to {retry_visibility}s "
                                f"for incident {incident_id}"
                            )
                        except Exception as vis_err:
                            ctx.warning(f"Failed to adjust retry visibility timeout: {vis_err}")
                        # Update Job - Failed (or keep running if retry?) 
                        # If SQS retries, we might want to fail the job if max retries reached, but here we just leave it.
                        if job_id and result.get('status') == 'error':
                             try:
                                supabase.table("Jobs").update({
                                    "status": "failed", 
                                    "details": {"error": result.get('message')}
                                }).eq("id", job_id).execute()
                             except Exception: 
                                pass

                except Exception as e:
                    logger.exception(f"Error processing message: {str(e)}")
                    # keep message for retry
        except Exception as e:
            logger.exception(f"Worker loop unexpected error: {str(e)}")
            time.sleep(60)

if __name__ == "__main__":
    worker_loop()
