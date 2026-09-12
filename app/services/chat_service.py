"""Chat request processing and asynchronous worker services."""

import json
import os
import re
import time
from typing import Any, Dict, List, Optional

import boto3
import redis
from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage

from app.core.database import supabase
from app.core.llm import call_llm
from app.core.logger import logger
from app.services.agent_tools import (
    CHAT_SYSTEM_PROMPT,
    TOOLS_REQUIRING_MAIL,
    llm_with_tools,
    tool_mapping,
)


session = boto3.Session(
    aws_access_key_id=os.getenv("access_key"),
    aws_secret_access_key=os.getenv("secrete_access"),
    region_name="ap-south-1",
)
CHAT_QUEUE_NAME = os.getenv("CHAT_QUEUE_NAME", "ChatqueueAsync")
CHAT_JOB_TTL_SECONDS = 60 * 60
r = redis.Redis(host="localhost", port=6379, db=0)


def _chat_job_redis_key(job_id: str) -> str:
    """Build Redis key for storing async chat job state."""
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
    """Persist a single chat interaction in the Supabase `ChatHistory` table.

    Expected Supabase table schema (must be created separately):

        create table "ChatHistory" (
            id uuid primary key default gen_random_uuid(),
            user_id uuid references "Users"(id) on delete cascade,
            email text,
            message_content text not null,
            response_text text,
            raw_result jsonb,
            is_async boolean default false,
            job_id text,
            created_at timestamptz default now()
        );

        create index "ChatHistory_user_id_created_at_idx"
            on "ChatHistory"(user_id, created_at desc);
    """
    try:
        user_id = None
        try:
            user_response = (
                supabase.table("Users").select("id").eq("email", mail).limit(1).execute()
            )
            if user_response.data:
                user_id = user_response.data[0]["id"]
        except Exception as e:
            # Log but do not break the chat flow if user lookup fails
            print(f"Chat history: failed to look up user for email {mail}: {str(e)}")

        payload: Dict[str, Any] = {
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
        # Chat should not fail just because history persistence failed
        print(f"Chat history: failed to insert record: {str(e)}")


def process_chat_request(
    mail: str,
    message_content: str,
    *,
    is_async: bool = False,
    job_id: Optional[str] = None,
    session_id: Optional[str] = None,
) -> dict:
    """Core chat logic shared by sync and async endpoints.

    This function lets the LLM decide which tools to call and in what order
    (e.g., call ask_knowledge_base first, then infra_automation_ai), by
    iteratively executing tool calls until the model returns a final answer
    with no further tool invocations.

    It also persists each interaction in the `ChatHistory` Supabase table.
    """
    system_message = SystemMessage(content=CHAT_SYSTEM_PROMPT)
    messages = [system_message, HumanMessage(content=message_content)]

    all_tool_calls: List[Dict[str, Any]] = []
    final_model_message: Optional[Any] = None

    # Allow the model multiple rounds of tool usage (e.g. KB first, then infra_automation_ai)
    for _ in range(5):  # safety limit to avoid infinite loops
        res = llm_with_tools.invoke(messages)
        final_model_message = res
        messages.append(res)

        tool_calls = getattr(res, "tool_calls", []) or []
        if not tool_calls:
            break

        for tool_call in tool_calls:
            tool_name = (tool_call.get("name") or "").lower()
            tool = tool_mapping.get(tool_name)
            tool_args = (
                dict(tool_call.get("args") or {}) if isinstance(tool_call.get("args"), dict) else {}
            )

            # Inject backend-managed email for tools that require `mail`
            if tool_name in TOOLS_REQUIRING_MAIL:
                tool_args["mail"] = mail

            if tool is None:
                tool_output: Any = {"status": "error", "message": f"Unknown tool: {tool_name}"}
            else:
                tool_output = tool.invoke(tool_args)

            all_tool_calls.append(
                {
                    "name": tool_name,
                    "args": tool_args,
                    "output": tool_output,
                }
            )

            tool_output_str = (
                tool_output if isinstance(tool_output, str) else json.dumps(tool_output)
            )
            messages.append(ToolMessage(content=tool_output_str, tool_call_id=tool_call["id"]))

    # Use a separate summarization call for the final natural-language answer
    ex2 = final_model_message if final_model_message is not None else ""
    result_text = call_llm(
        f"""generate a response for the given context {ex2} make it short and give only important details related to {message_content} in sentences dont add unnecessary , or symbols or extra spaces use the {ex2} to provide details and if it failed give details why it failed
                                   - dont mention the word playbook and word shell commands and word python error  and dont mention this sentence
                                   - A warning was generated regarding the Python interpreter path potentially changing in the future. Galaxy collections installation indicated that all requested collections are already installed. No shell errors were reported and
                                   - dont mention automation or any such word
                                   - dont mention The platform is using Python interpreter at /usr/bin/python3.12 and future installations might change this path. 5 tasks were completed and 2 were changed. No tasks failed or were unreachable or any similar sentences
                                   - dont mention sentences like tasks executed or 5 tasks run etc
                                   - if anything other than ansible you can mention the entire output of {ex2}"""
    )

    # Extract incident number from the message if it exists
    incident_match = re.search(r"incident\s+(\w+)", message_content, re.IGNORECASE)
    if incident_match:
        inc_number = incident_match.group(1)
        try:
            incident_response = (
                supabase.table("Incidents").select("id").eq("inc_number", inc_number).execute()
            )
            if incident_response.data:
                supabase.table("Incidents").update({"state": "completed"}).eq(
                    "inc_number", inc_number
                ).execute()
        except Exception as e:
            print(f"Error updating incident status: {str(e)}")
            # Continue with the response even if update fails

    # Persist chat history (best-effort, non-blocking on failure)
    _store_chat_history(
        mail=mail,
        message_content=message_content,
        result_text=result_text,
        tool_calls=all_tool_calls,
        is_async=is_async,
        job_id=job_id,
        session_id=session_id,
    )

    return {"result": all_tool_calls, "successorfail": result_text}


def chat_worker_loop():
    """
    Background worker that consumes chat jobs from SQS Chatqueue
    and stores results in Redis keyed by job_id.
    """
    try:
        sqs = session.resource("sqs")
        queue = sqs.get_queue_by_name(QueueName=CHAT_QUEUE_NAME)
    except Exception as e:
        print(f"Chat worker failed to initialize SQS queue {CHAT_QUEUE_NAME}: {e}")
        return

    while True:
        try:
            messages = queue.receive_messages(
                MessageAttributeNames=["All"],
                MaxNumberOfMessages=1,
                WaitTimeSeconds=20,
            )
            if not messages:
                continue

            for message in messages:
                job_id = None
                try:
                    body = json.loads(message.body)
                    job_id = body.get("job_id")
                    mail = body.get("mail")
                    content = body.get("content", "")
                    session_id = body.get("session_id")
                    # session_id = body.get("session_id") # This line was duplicated

                    if not job_id or not mail or not content:
                        # If this looks like an incident worker message, release it back
                        # so the incident worker can process it.
                        if isinstance(body.get("Mail"), dict) and body.get("Mail", {}).get(
                            "inc_number"
                        ):
                            logger.warning(
                                "Chat worker received a non-chat message. "
                                f"Releasing it back to queue '{CHAT_QUEUE_NAME}'."
                            )
                            try:
                                message.change_visibility(VisibilityTimeout=0)
                            except Exception:
                                pass
                            continue
                        # Truly malformed chat message; drop it.
                        message.delete()
                        continue

                    job_key = _chat_job_redis_key(job_id)
                    r.set(job_key, json.dumps({"status": "processing"}), ex=CHAT_JOB_TTL_SECONDS)

                    result = process_chat_request(
                        mail=mail,
                        message_content=content,
                        is_async=True,
                        job_id=job_id,
                        session_id=session_id,
                    )  # Removed duplicated `session_id=session_id,` and extra closing parenthesis

                    r.set(
                        job_key,
                        json.dumps({"status": "completed", "result": result}),
                        ex=CHAT_JOB_TTL_SECONDS,
                    )

                    message.delete()
                except Exception as e:
                    print(f"Error processing chat job from SQS: {e}")
                    if job_id:
                        job_key = _chat_job_redis_key(job_id)
                        r.set(
                            job_key,
                            json.dumps({"status": "error", "error": str(e)}),
                            ex=CHAT_JOB_TTL_SECONDS,
                        )
                    # Always delete the message so it is not retried on failure
                    try:
                        message.delete()
                    except Exception as delete_err:
                        print(f"Failed to delete SQS message after error: {delete_err}")
        except Exception as outer_e:
            print(f"Chat worker loop error: {outer_e}")
            time.sleep(5)
