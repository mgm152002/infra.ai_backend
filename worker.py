import time
import json
import os
import boto3
from dotenv import load_dotenv

from app.core.logger import logger, make_ctx_logger
from app.services.incident_service import process_incident
from app.core.config import settings
from app.db.session import supabase # Importing supabase for Job updates

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

def truncate(s: str, n: int = 2000) -> str:
    if s is None: return ""
    return str(s) if len(str(s)) <= n else str(s)[:n] + f"... [truncated {len(str(s))-n} chars]"

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

                    job_id = meta_data.get('job_id')
                    
                    ctx = make_ctx_logger(logger, incident=incident_id, instance=instance_id)
                    ctx.info(f"Received SQS message. MessageId={getattr(message, 'message_id', 'unknown')} body(truncated)={truncate(message.body)}")

                    # Ensure the message stays invisible for long-running processing.
                    try:
                        message.change_visibility(VisibilityTimeout=SQS_VISIBILITY_TIMEOUT)
                        ctx.info(f"Extended SQS message visibility timeout to {SQS_VISIBILITY_TIMEOUT} seconds")
                    except Exception:
                        ctx.exception("Failed to extend SQS message visibility timeout; proceeding with default queue setting")

                    # Update Job Status - Running
                    if job_id:
                        try:
                            from app.db.session import supabase # Ensure we have access
                            supabase.table("Jobs").update({
                                "status": "running", 
                                "progress": 0,
                                "details": {"stage": "worker_processing_started"}
                            }).eq("id", job_id).execute()
                        except Exception as e:
                            ctx.warning(f"Failed to update Job {job_id} status: {e}")

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