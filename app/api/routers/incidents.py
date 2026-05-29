"""Incident management API router.

Extracts incident-related endpoints from the monolithic main.py.
"""
import uuid
import json
import hashlib
import threading
import queue
import asyncio
from datetime import datetime
from typing import Optional

import boto3
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
import jwt

from app.core.database import supabase
from app.core.security import verify_token, has_permission
from app.core.logger import logger
from app.core.config import settings
from app.core.supabase_timeout import run_supabase_with_timeout, SupabaseTimeoutError
from app.services.notification_service import NotificationService
from app.schemas.models import Incident

router = APIRouter()

# Reuse the boto3 session pattern from main
import os
from dotenv import load_dotenv
load_dotenv()

session = boto3.Session(
    aws_access_key_id=os.getenv('access_key'),
    aws_secret_access_key=os.getenv('secrete_access'),
    region_name='ap-south-1'
)


@router.post("/incidentAdd")
def incidentAdd(Req: Incident, background_tasks: BackgroundTasks, user_data: dict = Depends(verify_token)):
    user_id = user_data.get("user_id")
    inc_number = (Req.inc_number or "").strip() if Req.inc_number is not None else ""

    allowed_sources = {"manual", "servicenow", "pagerduty"}
    raw_source = (Req.source or "").strip().lower() if Req.source else ""
    source = raw_source if raw_source in allowed_sources else None

    if not inc_number:
        if source == "pagerduty":
            if Req.external_id:
                inc_number = f"PD-{Req.external_id}".strip()
            elif Req.external_number:
                inc_number = f"PD-{Req.external_number}".strip()
        if not inc_number:
            inc_number = f"INC-{uuid.uuid4().hex[:12].upper()}"

    state = Req.state or "Queued"
    tag_id = Req.tag_id

    external_created_at = Req.external_created_at.isoformat() if Req.external_created_at else None
    external_updated_at = Req.external_updated_at.isoformat() if Req.external_updated_at else None
    external_payload = Req.external_payload or None

    resolved_service_id = Req.service_id
    resolved_fqdn = Req.fqdn

    if tag_id and not resolved_service_id:
        cmdb_response = supabase.table("CMDB").select("service_id, fqdn").eq("tag_id", tag_id).execute()
        if cmdb_response.data:
            resolved_service_id = cmdb_response.data[0].get("service_id")
            resolved_fqdn = cmdb_response.data[0].get("fqdn")

    insert_payload = {
        "id": Req.id,
        "short_description": Req.short_description,
        "tag_id": tag_id,
        "state": state,
        "inc_number": inc_number,
        "user_id": user_id,
        "source": source,
        "external_id": Req.external_id,
        "external_number": Req.external_number,
        "external_url": Req.external_url,
        "external_status": Req.external_status,
        "external_urgency": Req.external_urgency,
        "external_service": Req.external_service,
        "external_created_at": external_created_at,
        "external_updated_at": external_updated_at,
        "external_payload": external_payload,
        "alert_type_id": Req.alert_type_id,
        "service_id": resolved_service_id,
        "fqdn": resolved_fqdn,
    }
    insert_payload = {k: v for k, v in insert_payload.items() if v is not None}
    supabase.table("Incidents").insert(insert_payload).execute()

    try:
        background_tasks.add_task(NotificationService.notify_incident_created, user_id, insert_payload)
    except Exception as e:
        logger.error(f"Failed to queue notification task: {e}")

    queue_name = settings.SQS_QUEUE_NAME or "Chatqueue"
    sqsqueue = session.resource("sqs").get_queue_by_name(QueueName=queue_name)

    message_parts = [f"Incident {inc_number}: {Req.short_description}"]
    if source:
        message_parts.append(f"source={source}")
    if Req.external_status:
        message_parts.append(f"status={Req.external_status}")
    if Req.external_service:
        message_parts.append(f"service={Req.external_service}")
    if Req.external_url:
        message_parts.append(f"url={Req.external_url}")
    if resolved_service_id:
        message_parts.append(f"service_id={resolved_service_id}")
    if resolved_fqdn:
        message_parts.append(f"fqdn={resolved_fqdn}")
    message_text = " | ".join(message_parts)

    message_body = json.dumps({
        "Aws": {
            "access_key": "",
            "secrete_access": "",
            "region": "",
            "instance_id": tag_id or "",
        },
        "Mail": {
            "inc_number": inc_number,
            "subject": Req.short_description,
            "message": message_text,
        },
        "Meta": {
            "user_id": user_id,
            "tag_id": tag_id,
            "service_id": resolved_service_id,
            "fqdn": resolved_fqdn,
        },
    })

    try:
        send_resp = sqsqueue.send_message(MessageBody=message_body)
        logger.info(
            "[incident-enqueued] "
            f"endpoint=/incidentAdd queue={queue_name} "
            f"incident={inc_number} user_id={user_id} "
            f"message_id={send_resp.get('MessageId')}"
        )
    except Exception as e:
        logger.exception(
            "[incident-enqueue-failed] "
            f"endpoint=/incidentAdd queue={queue_name} incident={inc_number} "
            f"user_id={user_id} error={str(e)}"
        )
        try:
            supabase.table("Incidents").update({
                "state": "Error",
                "updated_at": datetime.utcnow().isoformat(),
            }).eq("inc_number", inc_number).execute()
        except Exception:
            pass
        raise HTTPException(status_code=500, detail=f"Failed to enqueue incident to SQS queue '{queue_name}'")

    return {"response": {"user_id": user_id, "inc_number": inc_number}}


@router.post("/incidents/add")
def add_incident_v3(Req: Incident, user_data: dict = Depends(verify_token), _: bool = Depends(has_permission("incidents", "write"))):
    user_id = user_data.get("user_id")
    inc_number = (Req.inc_number or "").strip()
    if not inc_number:
        inc_number = f"INC-{uuid.uuid4().hex[:12].upper()}"

    state = Req.state or "Queued"
    resolved_service_id = Req.service_id
    resolved_fqdn = Req.fqdn

    if Req.tag_id and not resolved_service_id:
        cmdb_response = supabase.table("CMDB").select("service_id, fqdn").eq("tag_id", Req.tag_id).execute()
        if cmdb_response.data:
            resolved_service_id = cmdb_response.data[0].get("service_id")
            resolved_fqdn = cmdb_response.data[0].get("fqdn")

    insert_payload = {
        "short_description": Req.short_description,
        "tag_id": Req.tag_id,
        "state": state,
        "inc_number": inc_number,
        "user_id": user_id,
        "source": Req.source or "manual",
        "alert_type_id": Req.alert_type_id,
        "service_id": resolved_service_id,
        "fqdn": resolved_fqdn,
    }
    supabase.table("Incidents").insert(insert_payload).execute()

    job_id = str(uuid.uuid4())
    supabase.table("Jobs").insert({
        "id": job_id,
        "user_id": user_id,
        "task_type": "incident_process",
        "status": "pending",
        "progress": 0,
        "details": {"inc_number": inc_number}
    }).execute()

    message_parts = [f"Incident {inc_number}: {Req.short_description}"]
    if Req.source:
        message_parts.append(f"source={Req.source}")
    if resolved_service_id:
        message_parts.append(f"service_id={resolved_service_id}")
    if resolved_fqdn:
        message_parts.append(f"fqdn={resolved_fqdn}")
    message_text = " | ".join(message_parts)

    queue_name = settings.SQS_QUEUE_NAME or "Chatqueue"
    sqsqueue = session.resource("sqs").get_queue_by_name(QueueName=queue_name)
    try:
        send_resp = sqsqueue.send_message(
            MessageBody=json.dumps({
                "Aws": {
                    "access_key": "",
                    "secrete_access": "",
                    "region": "",
                    "instance_id": Req.tag_id or "",
                },
                "Mail": {
                    "inc_number": inc_number,
                    "subject": Req.short_description,
                    "message": message_text,
                },
                "Meta": {
                    "job_id": job_id,
                    "user_id": user_id,
                    "tag_id": Req.tag_id,
                    "service_id": resolved_service_id,
                    "fqdn": resolved_fqdn,
                    "alert_type": Req.alert_type_id,
                },
            })
        )
        logger.info(
            "[incident-enqueued] "
            f"endpoint=/incidents/add queue={queue_name} incident={inc_number} "
            f"job_id={job_id} user_id={user_id} message_id={send_resp.get('MessageId')}"
        )
    except Exception as e:
        logger.exception(
            "[incident-enqueue-failed] "
            f"endpoint=/incidents/add queue={queue_name} incident={inc_number} "
            f"job_id={job_id} user_id={user_id} error={str(e)}"
        )
        try:
            supabase.table("Incidents").update({
                "state": "Error",
                "updated_at": datetime.utcnow().isoformat(),
            }).eq("inc_number", inc_number).execute()
        except Exception:
            pass
        try:
            supabase.table("Jobs").update({
                "status": "failed",
                "details": {
                    "inc_number": inc_number,
                    "stage": "enqueue_failed",
                    "queue_name": queue_name,
                    "error": str(e),
                }
            }).eq("id", job_id).execute()
        except Exception:
            pass
        raise HTTPException(status_code=500, detail=f"Failed to enqueue incident to SQS queue '{queue_name}'")

    try:
        supabase.table("Jobs").update({
            "details": {
                "inc_number": inc_number,
                "stage": "queued_in_sqs",
                "queue_name": queue_name,
                "queue_message_id": send_resp.get("MessageId"),
            }
        }).eq("id", job_id).execute()
    except Exception as e:
        logger.warning(f"Failed to annotate Job {job_id} with queue metadata: {e}")

    return {"response": {"user_id": user_id, "inc_number": inc_number, "job_id": job_id}}


@router.get("/incidents/all")
def get_all_incidents_v3(user_data: dict = Depends(verify_token), _: bool = Depends(has_permission("incidents", "read"))):
    user_id = user_data['user_id']
    response = supabase.table("Incidents").select("*, Users(*)").eq("user_id", user_id).execute()
    return {"response": response}


@router.get("/incidents/{inc_number}")
def get_incident_details_v3(inc_number: str, _: bool = Depends(has_permission("incidents", "read"))):
    response = supabase.from_("Incidents").select("*").eq("inc_number", inc_number).execute()
    if not response.data:
        raise HTTPException(status_code=404, detail="Incident not found")
    return {"response": response.data[0]}


@router.post("/incidents/{inc_number}/analyze")
def analyze_incident_v3(inc_number: str, background_tasks: BackgroundTasks, user_data: dict = Depends(verify_token), _: bool = Depends(has_permission("incidents", "read"))):
    from app.core.llm import get_llm
    from langchain_core.prompts import ChatPromptTemplate
    from langchain_core.output_parsers import JsonOutputParser

    response = supabase.from_("Incidents").select("short_description").eq("inc_number", inc_number).execute()
    if not response.data:
        raise HTTPException(status_code=404, detail="Incident not found")

    short_desc = response.data[0]["short_description"]
    user_id = user_data['user_id']
    job_id = str(uuid.uuid4())

    supabase.table("Jobs").insert({
        "id": job_id,
        "user_id": user_id,
        "task_type": "incident_analysis",
        "status": "pending",
        "progress": 0,
        "details": {"inc_number": inc_number}
    }).execute()

    def background_analyze_incident(inc_number: str, short_desc: str, job_id: str):
        try:
            supabase.table("Jobs").update({
                "status": "running",
                "progress": 10,
                "details": {"step": "analyzing"}
            }).eq("id", job_id).execute()

            llm = get_llm()
            prompt = ChatPromptTemplate.from_messages([
                ("system", "You are an expert incident responder."),
                ("user",
                """Given the following incident short description, determine:
                1. potential_cause
                2. potential_solution

                Respond only in JSON format like this:
                {{"potential_cause": "...", "potential_solution": "..."}}

                Short description: {short_description}
                {format_instructions}
                """)
            ])
            parser = JsonOutputParser()
            chain = prompt | llm | parser
            result = chain.invoke({
                "short_description": short_desc,
                "format_instructions": parser.get_format_instructions()
            })
            result['description'] = short_desc

            supabase.table("Jobs").update({
                "status": "completed",
                "progress": 100,
                "details": {"result": result}
            }).eq("id", job_id).execute()
        except Exception as e:
            print(f"Background analysis failed: {e}")
            supabase.table("Jobs").update({
                "status": "failed",
                "details": {"error": str(e)}
            }).eq("id", job_id).execute()

    background_tasks.add_task(background_analyze_incident, inc_number, short_desc, job_id)
    return {"status": "success", "job_id": job_id}


@router.get("/allIncidents")
def allIncidents(user_data: dict = Depends(verify_token)):
    user_id = user_data.get("user_id")
    mail = user_data.get("email")
    try:
        if user_id is None and mail:
            user_response = run_supabase_with_timeout(
                lambda: supabase.table("Users").select("id").eq("email", mail).limit(1).execute(),
                timeout_s=60,
                operation_name="allIncidents_user_lookup",
            )
            if not user_response.data:
                return {"response": {"data": []}}
            user_id = user_response.data[0]["id"]

        if user_id is None:
            return {"response": {"data": []}}

        response = run_supabase_with_timeout(
            lambda: supabase.table("Incidents").select(
                "id,inc_number,short_description,state,created_at,updated_at,alert_type_id,external_urgency,external_payload"
            ).eq("user_id", user_id).order("created_at", desc=True).limit(500).execute(),
            timeout_s=120,
            operation_name="allIncidents_query",
        )
        return {"response": response}
    except SupabaseTimeoutError:
        return {"response": {"data": []}, "warning": "Incidents query timed out; please retry"}


@router.get("/getIncidentsDetails/{inc_number}")
def getIncidentsDetails(inc_number: str, user_data: dict = Depends(verify_token)):
    user_id = user_data.get("user_id")
    if not user_id:
        raise HTTPException(status_code=401, detail="Unauthorized")

    inc_resp = (
        supabase.from_("Incidents")
        .select("*")
        .eq("inc_number", inc_number)
        .eq("user_id", user_id)
        .limit(1)
        .execute()
    )
    if not inc_resp.data:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident = inc_resp.data[0]
    potential_cause = ""
    potential_solution = ""

    raw_solution = incident.get("solution")
    if isinstance(raw_solution, str):
        try:
            raw_solution = json.loads(raw_solution)
        except Exception:
            raw_solution = {}
    if isinstance(raw_solution, dict):
        potential_cause = raw_solution.get("root_cause") or ""
        steps = raw_solution.get("resolution_steps")
        if isinstance(steps, list):
            potential_solution = "\n".join(str(s) for s in steps[:5])
        elif isinstance(steps, str):
            potential_solution = steps

    if not potential_cause or not potential_solution:
        res_resp = (
            supabase.table("Results")
            .select("description")
            .eq("inc_number", inc_number)
            .eq("user_id", user_id)
            .order("created_at", desc=True)
            .limit(1)
            .execute()
        )
        if res_resp.data:
            desc = res_resp.data[0].get("description")
            if isinstance(desc, str):
                try:
                    desc = json.loads(desc)
                except Exception:
                    desc = {}
            if isinstance(desc, dict):
                analysis = desc.get("analysis", {}) if isinstance(desc.get("analysis"), dict) else {}
                potential_cause = potential_cause or analysis.get("root_cause", "")
                potential_solution = potential_solution or analysis.get("resolution_steps", "")

    incident["potential_cause"] = potential_cause or "No cause found."
    incident["potential_solution"] = potential_solution or "No solution found."
    incident["description"] = incident.get("description") or incident.get("short_description") or "No description available."

    return {"response": incident}


class IncidentProcessRequest(BaseModel):
    inc_number: str


@router.post("/incident/stream")
async def process_incident_stream(
    request: IncidentProcessRequest,
    user_data: dict = Depends(verify_token),
):
    from app.services.incident_service import process_incident_streaming
    import queue as queue_module

    user_id = user_data.get("user_id")
    mail = user_data.get("email")
    inc_number = request.inc_number

    async def generate():
        event_queue = queue_module.Queue()

        def event_callback(event):
            try:
                event_queue.put_nowait(event)
            except queue_module.Full:
                pass

        def process_in_thread():
            try:
                process_incident_streaming(
                    inc_number=inc_number,
                    user_id=user_id,
                    event_callback=event_callback,
                    ctx_logger=None
                )
            except Exception as e:
                print(f"Error processing incident: {e}")
            finally:
                try:
                    event_queue.put_nowait({"type": "done", "status": "completed"})
                except queue_module.Full:
                    pass

        thread = threading.Thread(target=process_in_thread, daemon=True)
        thread.start()

        while True:
            try:
                event = event_queue.get(timeout=30)
                if event.get("type") == "done":
                    yield f"data: {json.dumps({'type': 'done', 'status': event.get('status', 'completed')})}\n\n"
                    break
                yield f"data: {json.dumps(event)}\n\n"
            except queue_module.Empty:
                yield f"data: {json.dumps({'type': 'keepalive'})}\n\n"
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"Error streaming event: {e}")
                break

    return StreamingResponse(generate(), media_type="text/event-stream")
