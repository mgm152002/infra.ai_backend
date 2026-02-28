"""
SSE (Server-Sent Events) endpoint for real-time incident updates.
"""
import json
import asyncio
from typing import Optional
from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse

from app.core.sse_manager import sse_manager, format_sse_event
from app.core.security import verify_token

router = APIRouter()


@router.get("/incidents/stream")
async def stream_incident_events(
    request: Request,
    user_data: dict = Depends(verify_token)
):
    """
    SSE endpoint for real-time incident updates.
    Clients connect to this endpoint to receive live updates about:
    - New incidents received
    - Incident status changes
    - Tool usage during resolution
    - Resolution progress
    """
    
    async def event_generator():
        """
        Generator that yields SSE events to connected clients.
        """
        user_id = user_data.get("user_id")
        queue = asyncio.Queue()
        
        # Register callback for this client
        def sse_callback(event):
            try:
                # Only send events relevant to this user or all incidents
                data = event.get("data", {})
                incident_user = data.get("user_id")
                
                # Send if it's a broadcast or for this user
                if incident_user is None or incident_user == user_id:
                    queue.put_nowait(event)
            except Exception:
                pass
        
        client_id = f"user_{user_id}"
        sse_manager.connect(client_id, sse_callback)
        
        try:
            # Send initial connection message
            yield format_sse_event("connected", {
                "type": "connected",
                "data": {"message": "Connected to incident streaming"}
            })
            
            while True:
                # Check if client disconnected
                if await request.is_disconnected():
                    break
                
                # Wait for events with timeout to allow checking disconnection
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=1.0)
                    event_type = event.get("type", "message")
                    event_data = event.get("data", {})
                    yield format_sse_event(event_type, {
                        "type": event_type,
                        "data": event_data
                    })
                except asyncio.TimeoutError:
                    # Send keep-alive comment
                    yield ": keep-alive\n\n"
                    continue
                    
        except asyncio.CancelledError:
            # Client disconnected or server shutdown while streaming.
            pass
        except Exception:
            pass
        finally:
            # Cleanup: disconnect client
            sse_manager.disconnect(client_id, sse_callback)
    
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        }
    )


@router.get("/incidents/stream/{incident_number}")
async def stream_specific_incident(
    request: Request,
    incident_number: str,
    user_data: dict = Depends(verify_token)
):
    """
    SSE endpoint for a specific incident's real-time updates.
    """
    
    async def event_generator():
        user_id = user_data.get("user_id")
        queue = asyncio.Queue()
        
        # Register callback for this specific incident
        def sse_callback(event):
            try:
                data = event.get("data", {})
                incident_user = data.get("user_id")
                if data.get("incident_id") == incident_number and (incident_user is None or incident_user == user_id):
                    queue.put_nowait(event)
            except Exception:
                pass
        
        client_id = f"incident_{incident_number}_{user_id}"
        sse_manager.connect(client_id, sse_callback)
        
        try:
            yield format_sse_event("connected", {
                "type": "connected",
                "data": {
                    "message": f"Connected to incident {incident_number} streaming"
                }
            })

            # Replay recent events so page refreshes can resume context.
            for event in sse_manager.get_recent_incident_events(incident_number, limit=200):
                event_data = event.get("data", {})
                incident_user = event_data.get("user_id")
                if incident_user is not None and incident_user != user_id:
                    continue
                event_type = event.get("type", "message")
                yield format_sse_event(event_type, {
                    "type": event_type,
                    "data": event_data,
                })
            
            while True:
                if await request.is_disconnected():
                    break
                
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=1.0)
                    event_type = event.get("type", "message")
                    event_data = event.get("data", {})
                    yield format_sse_event(event_type, {
                        "type": event_type,
                        "data": event_data
                    })
                except asyncio.TimeoutError:
                    yield ": keep-alive\n\n"
                    continue
                    
        except asyncio.CancelledError:
            # Client disconnected or server shutdown while streaming.
            pass
        except Exception:
            pass
        finally:
            sse_manager.disconnect(client_id, sse_callback)
    
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        }
    )
