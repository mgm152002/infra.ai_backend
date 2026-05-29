"""Chat API router.

Extracts chat-related endpoints from the monolithic main.py.
Note: This router depends on chat tools and LLM configuration from main.py.
For now, it imports from main where needed - a future refactor could move
the chat tool definitions here as well.
"""
import json
import hashlib
import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any, Annotated

import redis
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import jwt

from app.core.database import supabase
from app.core.security import verify_token
from app.core.logger import logger

router = APIRouter()
security = HTTPBearer()

# Redis connection for async chat jobs
import os
r = redis.Redis(host='localhost', port=6379, db=0)
CHAT_JOB_TTL_SECONDS = 60 * 60  # 1 hour


class Mesage(BaseModel):
    content: str
    session_id: Optional[str] = None


class CreateChatSession(BaseModel):
    title: Optional[str] = None


# Clerk public key for JWT verification (same as main.py)
CLERK_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxFwlegGWXS3gVaKyX/Ck
pwRENl+blwEkCtqfnjjHSV5TScDHwum4uQFcAW6VgyESbeA6tDI5VF72ZRcJ58yE
m1uJLLDQNDrG0BAa2jYAgcRZeQcJklXp+E5C7kv+wQh/19/24/ze09l9N2jIvhKk
OCICAoJ/AtnsvsYRhi74z+HVzEZZmVtofeHxZBlBU3XX0v0u9gYnqsm550Ndk/K3
fHY1QOV8mAYKMrqhrpbC4dsGDn9WGta0h003zrHrMauA9mvnGBgIdHMXZiYWjC7M
mkew+iKms63o1+K6p16OGX3DR+WYnjCWOf6SxsTWOxTCBzxow+m693Afg3stBLR3
ZQIDAQAB
-----END PUBLIC KEY-----"""


def _verify_clerk_token(credentials: HTTPAuthorizationCredentials) -> dict:
    """Verify Clerk JWT and return decoded token."""
    token = credentials.credentials
    return jwt.decode(token, key=CLERK_PUBLIC_KEY, algorithms=['RS256'])


def _chat_job_redis_key(job_id: str) -> str:
    return f"chat:job:{job_id}"


def _store_chat_history(
    mail: str,
    message_content: str,
    result_text: str,
    tool_calls: List[Dict[str, Any]],
    *,
    is_async: bool = False,
    job_id: Optional[str] = None,
    session_id: Optional[str] = None,
) -> None:
    try:
        user_id = None
        try:
            user_response = supabase.table("Users").select("id").eq("email", mail).limit(1).execute()
            if user_response.data:
                user_id = user_response.data[0]["id"]
        except Exception as e:
            print(f"Chat history: failed to look up user for email {mail}: {str(e)}")

        payload = {
            "email": mail,
            "message_content": message_content,
            "response_text": result_text,
            "raw_result": {"tool_calls": tool_calls},
            "is_async": is_async,
            "job_id": job_id,
            "session_id": session_id,
        }
        if user_id is not None:
            payload["user_id"] = user_id

        supabase.table("ChatHistory").insert(payload).execute()
    except Exception as e:
        print(f"Chat history: failed to insert record: {str(e)}")


@router.post("/chat")
def chat(message: Mesage, credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)]):
    try:
        res = _verify_clerk_token(credentials)
        mail = res['email']
    except jwt.DecodeError as e:
        print(e)
        return {"error": e}

    from main import process_chat_request
    return process_chat_request(mail=mail, message_content=message.content, session_id=message.session_id)


@router.post("/chat/stream")
async def chat_stream(message: Mesage, credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)]):
    try:
        res = _verify_clerk_token(credentials)
        mail = res['email']
    except jwt.DecodeError as e:
        print(e)
        return {"error": e}

    from main import (
        CHAT_SYSTEM_PROMPT, llm_with_tools, tool_mapping,
        TOOLS_REQUIRING_MAIL, call_llm, _store_chat_history as store_hist
    )
    from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage

    async def generate():
        system_message = SystemMessage(content=CHAT_SYSTEM_PROMPT)
        previous_data = getattr(message, 'previous_data', None)
        format_request = getattr(message, 'format_request', None)
        previous_data_type = getattr(message, 'previous_data_type', None)

        context_instruction = ""
        if previous_data is not None and format_request:
            context_instruction = f"\n\nUSER CONTEXT FOR RE-FORMATTING:\nThe user is asking to re-format previous data. Previous data type: {previous_data_type or 'unknown'}.\nUser's re-format request: {format_request}\nPrevious data: {json.dumps(previous_data, indent=2)}\n\nPlease format this data as requested by the user (e.g., table, list, etc.)."

        messages = [system_message, HumanMessage(content=message.content + context_instruction)]
        all_tool_calls = []
        final_model_message = None

        for _ in range(5):
            res = llm_with_tools.invoke(messages)
            final_model_message = res
            messages.append(res)

            tool_calls = getattr(res, "tool_calls", []) or []
            if not tool_calls:
                break

            for tool_call in tool_calls:
                tool_name = (tool_call.get("name") or "").lower()
                tool = tool_mapping.get(tool_name)
                tool_args = dict(tool_call.get("args") or {}) if isinstance(tool_call.get("args"), dict) else {}

                if tool_name in TOOLS_REQUIRING_MAIL:
                    tool_args["mail"] = mail

                if tool is None:
                    tool_output = {"status": "error", "message": f"Unknown tool: {tool_name}"}
                else:
                    tool_output = tool.invoke(tool_args)

                all_tool_calls.append({
                    "name": tool_name,
                    "args": tool_args,
                    "output": tool_output,
                })

                yield f"data: {json.dumps({'type': 'tool_call', 'tool': {'name': tool_name, 'args': tool_args, 'output': str(tool_output)}})}\n\n"

                tool_output_str = tool_output if isinstance(tool_output, str) else json.dumps(tool_output)
                messages.append(ToolMessage(content=tool_output_str, tool_call_id=tool_call["id"]))

        ex2 = final_model_message if final_model_message is not None else ""
        reformat_context = ""
        if previous_data is not None and format_request:
            reformat_context = f"\n\nThe user specifically asked to format the data as: {format_request}.\nHere is the raw data that should be formatted: {json.dumps(previous_data, indent=2)}"

        result_text = call_llm(
            f'''generate a response for the given context {ex2} make it short and give only important details related to {message.content} in sentences dont add unnecessary , or symbols or extra spaces use the {ex2} to provide details and if it failed give details why it failed'''
            + reformat_context
        )

        import re
        incident_match = re.search(r'incident\s+(\w+)', message.content, re.IGNORECASE)
        if incident_match:
            inc_number = incident_match.group(1)
            try:
                incident_response = supabase.table("Incidents").select("id").eq("inc_number", inc_number).execute()
                if incident_response.data:
                    supabase.table("Incidents").update({"state": "completed"}).eq("inc_number", inc_number).execute()
            except Exception as e:
                print(f"Error updating incident status: {str(e)}")

        _store_chat_history(
            mail=mail,
            message_content=message.content,
            result_text=result_text,
            tool_calls=all_tool_calls,
            is_async=False,
            job_id=None,
            session_id=message.session_id,
        )

        chunk_size = 20
        for i in range(0, len(result_text), chunk_size):
            chunk = result_text[i:i + chunk_size]
            yield f"data: {json.dumps({'type': 'chunk', 'content': chunk})}\n\n"

        yield f"data: {json.dumps({'type': 'done'})}\n\n"

    return StreamingResponse(generate(), media_type="text/event-stream")


@router.post("/chat/async")
def enqueue_chat(
    message: Mesage,
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)],
):
    import boto3

    try:
        res = _verify_clerk_token(credentials)
        mail = res['email']
    except jwt.DecodeError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials - invalid token",
        )

    job_id = str(uuid.uuid4())
    body = {
        "job_id": job_id,
        "mail": mail,
        "content": message.content,
        "session_id": message.session_id,
        "created_at": datetime.utcnow().isoformat(),
    }
    message_body = json.dumps(body)

    session = boto3.Session(
        aws_access_key_id=os.getenv('access_key'),
        aws_secret_access_key=os.getenv('secrete_access'),
        region_name='ap-south-1'
    )
    chat_queue_name = os.getenv("CHAT_QUEUE_NAME", "ChatqueueAsync")

    try:
        sqsqueue = session.resource('sqs').get_queue_by_name(QueueName=chat_queue_name)
        sqsqueue.send_message(MessageBody=message_body)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to enqueue chat request: {str(e)}",
        )

    job_key = _chat_job_redis_key(job_id)
    r.set(job_key, json.dumps({"status": "queued"}), ex=CHAT_JOB_TTL_SECONDS)

    return {"job_id": job_id, "status": "queued"}


@router.get("/chat/async/{job_id}")
def get_chat_job_status(job_id: str):
    job_key = _chat_job_redis_key(job_id)
    raw = r.get(job_key)
    if not raw:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Job not found or has expired",
        )
    data = json.loads(raw)
    data["job_id"] = job_id
    return data


@router.get("/chat/history")
async def get_chat_history(
    limit: int = 50,
    offset: int = 0,
    user_data: dict = Depends(verify_token),
):
    try:
        if limit < 1:
            limit = 1
        if limit > 200:
            limit = 200

        user_id = user_data["user_id"]
        start = offset
        end = offset + limit - 1

        response = (
            supabase.table("ChatHistory")
            .select("id, email, message_content, response_text, is_async, job_id, created_at, raw_result")
            .eq("user_id", user_id)
            .order("created_at", desc=True)
            .range(start, end)
            .execute()
        )
        return {"response": response}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/chat/sessions")
async def create_chat_session(
    session_data: CreateChatSession,
    user_data: dict = Depends(verify_token),
):
    try:
        user_id = user_data["user_id"]
        title = session_data.title or "New Chat"
        response = supabase.table("ChatSessions").insert({
            "user_id": user_id,
            "title": title,
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat(),
        }).execute()
        return {"response": response.data[0]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/chat/sessions")
async def list_chat_sessions(
    limit: int = 50,
    offset: int = 0,
    user_data: dict = Depends(verify_token),
):
    try:
        user_id = user_data["user_id"]
        response = (
            supabase.table("ChatSessions")
            .select("*")
            .eq("user_id", user_id)
            .order("updated_at", desc=True)
            .range(offset, offset + limit - 1)
            .execute()
        )
        return {"response": response.data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/chat/sessions/{session_id}")
async def update_chat_session(
    session_id: str,
    update_data: CreateChatSession,
    user_data: dict = Depends(verify_token),
):
    try:
        if not update_data.title:
            return {"message": "No changes"}
        response = supabase.table("ChatSessions").update({
            "title": update_data.title,
            "updated_at": datetime.utcnow().isoformat()
        }).eq("id", session_id).eq("user_id", user_data["user_id"]).execute()
        if not response.data:
            raise HTTPException(status_code=404, detail="Session not found")
        return {"response": response.data[0]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/chat/history/{session_id}")
async def get_session_history(
    session_id: str,
    user_data: dict = Depends(verify_token),
):
    try:
        response = (
            supabase.table("ChatHistory")
            .select("id, email, message_content, response_text, is_async, job_id, created_at, raw_result")
            .eq("session_id", session_id)
            .order("created_at")
            .execute()
        )
        return {"response": response}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch chat history: {str(e)}",
        )


@router.delete("/chat/sessions/{session_id}")
async def delete_chat_session(
    session_id: str,
    user_data: dict = Depends(verify_token),
):
    try:
        user_id = user_data["user_id"]
        supabase.table("ChatHistory").delete().eq("session_id", session_id).eq("user_id", user_id).execute()
        response = supabase.table("ChatSessions").delete().eq("id", session_id).eq("user_id", user_id).execute()
        if not response.data:
            raise HTTPException(status_code=404, detail="Session not found")
        return {"status": "ok", "message": "Session deleted successfully"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
