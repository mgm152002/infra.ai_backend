"""Operational, result, CMDB-import, and legacy admin API routes."""

import asyncio
import csv
import hashlib
import io
import json
import os
import uuid
from datetime import datetime
from typing import Annotated

import boto3
import jwt
from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, UploadFile, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from langchain_core.output_parsers import JsonOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.runnables import Runnable
from tavily import TavilyClient

from app.core.config import settings
from app.core.database import supabase
from app.core.llm import call_llm, get_llm
from app.core.logger import logger
from app.core.security import RoleChecker, has_permission, verify_token
from app.core.supabase_timeout import SupabaseTimeoutError, run_supabase_with_timeout
from app.schemas.models import Aws, Mesage, RequestBody
from app.services.infrastructure_automation import execute_command, power_status_tool, selfHealing
from app.services.knowledge_service import query_knowledge_base
from app.services.notification_service import NotificationService
from app.services.rca_service import rca_service


router = APIRouter()
security = HTTPBearer()
clerk_public_key = settings.CLERK_PUBLIC_KEY
allow_admin = RoleChecker(["admin"])
lock = 0
session = boto3.Session(
    aws_access_key_id=os.getenv("access_key"),
    aws_secret_access_key=os.getenv("secrete_access"),
    region_name="ap-south-1",
)


@router.post("/queueAdd")
def queueAdd(Req: RequestBody):
    sqsqueue = session.resource("sqs").get_queue_by_name(QueueName="infraaiqueue.fifo")
    message_body = json.dumps({"Aws": Req.Aws.dict(), "Mail": Req.Mail.dict()})
    content_hash = hashlib.sha256(message_body.encode()).hexdigest()
    unique_id = f"{content_hash}-{uuid.uuid4().hex}"
    sqsqueue.send_message(MessageBody=message_body)


@router.post("/queueRemove")
def queueRemove():
    sqsqueue = session.resource("sqs").get_queue_by_name(QueueName="infraaiqueue.fifo")
    sqsmess = sqsqueue.receive_messages(MessageAttributeNames=["All"], MaxNumberOfMessages=1)
    print(json.loads(sqsmess[0].body))
    queueici = json.loads(sqsmess[0].body)
    res = (
        supabase.table("Incidents")
        .update({"state": "InProgress"})
        .eq("inc_number", queueici["Mail"]["inc_number"])
        .execute()
    )
    # return{"Aws": queueici['Aws'], "Mail": queueici['Mail']}

    if lock == 0:
        res = selfHealing(queueici["Aws"], queueici["Mail"])

        return {"response": res}
    else:
        return {"response": "worker in progress"}


@router.post("/testecodeexec/{hostname}/{username}")
def testecodeexec(hostname: str, username: str):
    res = execute_command(
        "top -bn1 | grep -v PID | sort -k9 -r | head -n 1 | awk '{print $1}' | xargs kill -9",
        hostname,
        username,
        "cpu usage is high",
    )
    return {"response": res}


@router.post("/testAws")
def testAws(Aws: Aws):
    res = power_status_tool(Aws)
    return {"response": res}


@router.post("/websearch")
async def web_search(message: str, user_data: dict = Depends(verify_token)):
    """this function is used to search the web for the given message"""
    try:
        # Limit to top 3 most relevant results to reduce processing time
        client = TavilyClient(os.getenv("tavali_api_key"))
        search_response = client.search(
            query=message,
            max_results=3,  # Limit results to top 3
        )

        # Process results
        async def extract_content(result):
            try:
                # Use requests directly instead of read_url_content
                import requests

                response = requests.get(result["url"], timeout=10)

                # Check if request was successful
                if response.status_code == 200:
                    # Use BeautifulSoup for better content extraction
                    from bs4 import BeautifulSoup

                    soup = BeautifulSoup(response.text, "html.parser")

                    # Extract text content
                    text_content = soup.get_text(separator=" ", strip=True)

                    return {
                        "url": result["url"],
                        "content": text_content[:500],  # Limit content to first 500 characters
                    }
                else:
                    return {"url": result["url"], "content": f"Error: HTTP {response.status_code}"}
            except Exception as e:
                return {"url": result["url"], "content": f"Error extracting content: {str(e)}"}

        # Gather results
        contexts = await asyncio.gather(
            *[extract_content(result) for result in search_response["results"]]
        )

        # Prepare context for Gemini
        context_str = " ".join([ctx["content"] for ctx in contexts if ctx["content"]])

        # Generate response using the shared OpenRouter LLM
        answer = call_llm(
            f" you are an helpful web search assistant. Context from web search: {context_str}\n\nQuestion: {message}\n\nGenerate a comprehensive response based on the context, addressing the question directly dont add things like from  the snippet or other unnecessary details."
        )

        return {"response": answer}

    except Exception as e:
        return {
            "response": f"Unable to retrieve web search results. Error: {str(e)}. Please try a different query or check your internet connection."
        }


@router.post("/plan")
def getPlan(message: Mesage, user_data: dict = Depends(verify_token)):
    llm = get_llm()

    # Try to enrich the plan with internal KB context first; if anything fails,
    # we silently fall back to the previous behavior.
    try:
        kb_matches = query_knowledge_base(message.content)
    except Exception:
        kb_matches = []

    kb_context = ""
    if kb_matches:
        kb_context = "Relevant internal knowledge base entries:\n" + "\n\n".join(
            m["text"] for m in kb_matches if m.get("text")
        )

    # 🧾 JSON parser
    parser = JsonOutputParser()

    # 🧱 Prompt template
    prompt = ChatPromptTemplate.from_messages(
        [
            (
                "system",
                """
You are an assistant that extracts infrastructure change plans from user input. Given a user message, return a JSON object with the key "plan" and the value as a list of bullet points. Each bullet point should describe a specific action to be taken, including:
- The action (created, updated, deleted)
- The type of resource
- The name of the resource
- software asked to be installed or
- any other relevant details.
- always include the name of the resource and the ip adress if any in the all points

When generating plans involving EC2 instances, remember common default usernames:
- Amazon Linux (2 or AMI): ec2-user
- CentOS: centos or ec2-user
- Debian: admin
- Fedora: fedora or ec2-user
- RHEL: ec2-user or root
- SUSE: ec2-user or root
- Ubuntu: ubuntu

Example format:
{{
  "plan": [
    "Create the EC2 instance named web-server",
    "Delete the S3 bucket named old-logs",
    "Update the IAM role named read-only-access",
    "Install software named apache"
  ]
}}

Output only the JSON object. Do not add any extra text, markdown, or newlines before or after. Your response must start with '{{' and end with '}}' with no characters outside. Do not include markdown.
""",
            ),
            ("user", "{user_input}\n\n{kb_context}\n\n{format_instructions}"),
        ]
    )

    # 🔗 Chain
    chain: Runnable = prompt | llm | parser

    # 🚀 Function to run inference

    try:
        result = chain.invoke(
            {
                "user_input": f"The user's request is: {message.content}",
                "kb_context": kb_context,
                "format_instructions": parser.get_format_instructions(),
            }
        )
        return {"response": result}

    except Exception as e:
        return {
            "error": "Failed to parse JSON",
            "message": str(e),
        }


@router.post("/storeResult")
async def store_result(
    inc_number: str,
    result: str,
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)],
    background_tasks: BackgroundTasks,
):
    try:
        token = credentials.credentials
        res = jwt.decode(token, key=clerk_public_key, algorithms=["RS256"])
        mail = res["email"]

        # Get user_id from Users table
        user_response = supabase.table("Users").select("id").eq("email", mail).execute()
        if not user_response.data:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        user_id = user_response.data[0]["id"]

        # Store result in Results table
        response = (
            supabase.table("Results")
            .insert(
                {
                    "inc_number": inc_number,
                    "description": result,
                    "short_description": result,
                    "user_id": user_id,
                    "created_at": datetime.utcnow().isoformat(),
                }
            )
            .execute()
        )

        # Trigger notification
        try:
            background_tasks.add_task(
                NotificationService.notify_incident_update, user_id, inc_number, result
            )
        except Exception as e:
            logger.error(f"Failed to queue notification task: {e}")

        return {"response": "Result stored successfully", "data": response.data}

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to store result: {str(e)}",
        )


@router.get("/getResults/{inc_number}")
async def get_results(
    inc_number: str, credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)]
):
    try:
        token = credentials.credentials
        res = jwt.decode(token, key=clerk_public_key, algorithms=["RS256"])
        mail = res["email"]

        # Get user_id from Users table
        user_response = supabase.table("Users").select("id").eq("email", mail).execute()
        if not user_response.data:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        user_id = user_response.data[0]["id"]

        # Get results from Results table, ordered by creation date
        response = (
            supabase.table("Results")
            .select("description, created_at")
            .eq("inc_number", inc_number)
            .eq("user_id", user_id)
            .order("created_at", desc=True)
            .execute()
        )

        return {"response": response}

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get results: {str(e)}",
        )


@router.get("/getRCA/{inc_number}")
def get_rca(inc_number: str, user_data: dict = Depends(verify_token)):
    try:
        result = rca_service.get_rca(inc_number)
        return {"response": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/generateRCA/{inc_number}")
def generate_rca(inc_number: str, user_data: dict = Depends(verify_token)):
    try:
        # Trigger generation (this could be async/background task for better UX in future)
        result = rca_service.generate_rca(inc_number)
        if "error" in result:
            raise HTTPException(status_code=500, detail=result["error"])
        return {"response": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/jobs/active")
def get_active_jobs(user_data: dict = Depends(verify_token)):
    user_id = user_data["user_id"]
    try:
        response = run_supabase_with_timeout(
            lambda: (
                supabase.table("Jobs")
                .select("*")
                .eq("user_id", user_id)
                .or_("status.eq.pending,status.eq.running")
                .execute()
            ),
            timeout_s=60,
            operation_name="jobs_active_query",
        )
        return {"response": response.data}
    except SupabaseTimeoutError:
        return {"response": [], "warning": "Active jobs query timed out; please retry"}


@router.get("/jobs/{job_id}")
def get_job_status(job_id: str, user_data: dict = Depends(verify_token)):
    response = supabase.table("Jobs").select("*").eq("id", job_id).execute()
    if not response.data:
        raise HTTPException(status_code=404, detail="Job not found")
    return response.data[0]


@router.post("/uploadCMDB")
async def upload_cmdb(
    file: UploadFile = File(...),
    user_data: dict = Depends(verify_token),
    _: bool = Depends(has_permission("cmdb", "write")),
):
    """
    Upload a CSV file to bulk import/update CMDB items.
    CSV must have a 'tag_id' column.
    """
    if not file.filename.endswith(".csv"):
        raise HTTPException(status_code=400, detail="Invalid file type. Please upload a CSV file.")

    try:
        # Read file content
        content = await file.read()
        # Decode bytes to string
        decoded_content = content.decode("utf-8-sig")  # Handle BOM if present

        csv_reader = csv.DictReader(io.StringIO(decoded_content))

        # Validate headers
        if "tag_id" not in csv_reader.fieldnames:
            raise HTTPException(status_code=400, detail="CSV must contain a 'tag_id' column.")

        items_to_upsert = []
        user_id = user_data["user_id"]

        stats = {"added": 0, "updated": 0, "failed": 0, "errors": []}

        for row in csv_reader:
            try:
                tag_id = row.get("tag_id", "").strip()
                if not tag_id:
                    continue

                item_data = {
                    "user_id": user_id,
                    "tag_id": tag_id,
                    "ip": row.get("ip", "0.0.0.0"),
                    "addr": row.get("location") or row.get("addr") or "Unknown",
                    "type": row.get("type", "other").lower(),
                    "os": row.get("os", "Unknown"),
                    "description": row.get("description", f"Imported CI {tag_id}"),
                    "source": "csv_import",
                    "last_sync": datetime.utcnow().isoformat(),
                }

                # Perform upsert immediately or batch. For simplicity/safety, we do one by one or small batches.
                # Supabase upsert can handle lists. Let's batch all.
                items_to_upsert.append(item_data)

            except Exception as e:
                stats["failed"] += 1
                stats["errors"].append(f"Row error: {str(e)}")

        if items_to_upsert:
            try:
                # Upsert in batches of 100 to avoid request size limits if large
                batch_size = 100
                for i in range(0, len(items_to_upsert), batch_size):
                    batch = items_to_upsert[i : i + batch_size]
                    supabase.table("CMDB").upsert(batch, on_conflict="user_id,tag_id").execute()

                stats["added"] = len(items_to_upsert)  # Approximate, as upsert could update
                # Refinement: To distinguish added/updated, we'd need to check existence first, which is slower.
                # For now, reporting count of processed valid rows.

            except Exception as e:
                # If batch fails, the whole batch fails.
                raise HTTPException(
                    status_code=500, detail=f"Database batch upsert failed: {str(e)}"
                )

        return {
            "status": "success",
            "stats": stats,
            "message": f"Processed {len(items_to_upsert)} items successfully.",
        }

    except HTTPException as he:
        raise he
    except Exception as e:
        logger.error(f"CSV Upload failed: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to process CSV: {str(e)}")


@router.get("/admin/users")
def list_users(user_data: dict = Depends(verify_token), _: bool = Depends(allow_admin)):
    """
    List all users. Requires 'admin' role.
    """
    try:
        response = supabase.table("Users").select("*").execute()
        return response.data
    except Exception as e:
        print(f"Error listing users: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch users")


@router.get("/admin/health")
def system_health(user_data: dict = Depends(verify_token), _: bool = Depends(allow_admin)):
    """
    Get system health status.
    """
    return {"status": "healthy", "services": {"database": "connected", "workers": "active"}}


@router.get("/worker/queue-health")
def worker_queue_health(user_data: dict = Depends(verify_token)):
    """
    Quick visibility endpoint to verify worker queue depth and connectivity.
    """
    queue_name = settings.SQS_QUEUE_NAME or "Chatqueue"
    try:
        sqs = session.resource("sqs")
        queue = sqs.get_queue_by_name(QueueName=queue_name)
        queue.reload()
        attrs = queue.attributes or {}

        return {
            "queue_name": queue_name,
            "region": settings.AWS_REGION,
            "checked_at": datetime.utcnow().isoformat(),
            "metrics": {
                "visible": int(attrs.get("ApproximateNumberOfMessages", 0)),
                "inflight": int(attrs.get("ApproximateNumberOfMessagesNotVisible", 0)),
                "delayed": int(attrs.get("ApproximateNumberOfMessagesDelayed", 0)),
            },
        }
    except Exception as e:
        logger.exception(f"Failed to read queue health for {queue_name}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to read queue health: {str(e)}")
