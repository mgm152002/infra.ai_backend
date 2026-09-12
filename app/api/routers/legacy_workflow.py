"""Unprefixed workflow routes retained for API compatibility."""

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status

from app.core.database import supabase
from app.core.logger import logger
from app.core.security import RoleChecker, has_permission, verify_token
from app.schemas.models import (
    AlertTypeEscalation,
    AlertTypeEscalationUpdate,
    CreateAlertType,
    CreateEscalationRule,
    CreatePendingAction,
    UpdateAlertType,
    UpdateEscalationRule,
)


router = APIRouter()
allow_admin = RoleChecker(["admin"])


@router.get("/alert-types")
def get_alert_types(user_data: dict = Depends(verify_token)):
    try:
        response = supabase.table("alert_types").select("*").order("id").execute()
        return {"response": response.data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/alert-types")
def create_alert_type(
    alert: CreateAlertType,
    user_data: dict = Depends(verify_token),
    _: bool = Depends(has_permission("settings", "write")),
):
    try:
        # Check if name exists
        existing = supabase.table("alert_types").select("id").eq("name", alert.name).execute()
        if existing.data:
            raise HTTPException(
                status_code=400, detail=f"Alert type '{alert.name}' already exists."
            )

        payload = alert.dict()
        response = supabase.table("alert_types").insert(payload).execute()
        return {"response": response.data[0]}
    except HTTPException as he:
        raise he
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/alert-types/{alert_id}")
def update_alert_type(
    alert_id: int,
    alert: UpdateAlertType,
    user_data: dict = Depends(verify_token),
    _: bool = Depends(has_permission("settings", "write")),
):
    try:
        payload = {k: v for k, v in alert.dict().items() if v is not None}
        payload["updated_at"] = datetime.utcnow().isoformat()

        response = supabase.table("alert_types").update(payload).eq("id", alert_id).execute()
        if not response.data:
            raise HTTPException(status_code=404, detail="Alert type not found")
        return {"response": response.data[0]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/alert-types/{alert_id}")
def delete_alert_type(
    alert_id: int,
    user_data: dict = Depends(verify_token),
    _: bool = Depends(has_permission("settings", "write")),
):
    try:
        # Verify it exists
        response = supabase.table("alert_types").delete().eq("id", alert_id).execute()
        if not response.data:
            raise HTTPException(status_code=404, detail="Alert type not found")
        return {"message": "Alert type deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/escalation-rules")
def get_escalation_rules(
    alert_type_id: Optional[int] = None, user_data: dict = Depends(verify_token)
):
    try:
        query = supabase.table("escalation_rules").select("*").order("level")
        if alert_type_id:
            query = query.eq("alert_type_id", alert_type_id)

        response = query.execute()
        return {"response": response.data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/escalation-rules")
def create_escalation_rule(
    rule: CreateEscalationRule,
    user_data: dict = Depends(verify_token),
    _: bool = Depends(has_permission("settings", "write")),
):
    try:
        # Validate alert_type_id exists
        alert = supabase.table("alert_types").select("id").eq("id", rule.alert_type_id).execute()
        if not alert.data:
            raise HTTPException(status_code=404, detail="Alert Type not found")

        payload = rule.dict()
        response = supabase.table("escalation_rules").insert(payload).execute()
        return {"response": response.data[0]}
    except HTTPException as he:
        raise he
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/escalation-rules/{rule_id}")
def update_escalation_rule(
    rule_id: int,
    rule: UpdateEscalationRule,
    user_data: dict = Depends(verify_token),
    _: bool = Depends(has_permission("settings", "write")),
):
    try:
        payload = {k: v for k, v in rule.dict().items() if v is not None}
        payload["updated_at"] = datetime.utcnow().isoformat()

        response = supabase.table("escalation_rules").update(payload).eq("id", rule_id).execute()
        if not response.data:
            raise HTTPException(status_code=404, detail="Escalation rule not found")
        return {"response": response.data[0]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/escalation-rules/{rule_id}")
def delete_escalation_rule(
    rule_id: int,
    user_data: dict = Depends(verify_token),
    _: bool = Depends(has_permission("settings", "write")),
):
    try:
        response = supabase.table("escalation_rules").delete().eq("id", rule_id).execute()
        if not response.data:
            raise HTTPException(status_code=404, detail="Escalation rule not found")
        return {"message": "Escalation rule deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/alert-type-escalations", response_model=dict)
def get_alert_type_escalations(user_data: dict = Depends(verify_token)):
    """Get all alert type escalation configurations"""
    try:
        response = (
            supabase.table("alert_type_escalations")
            .select("*")
            .order("escalation_level", desc=True)
            .execute()
        )
        return {"response": response.data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/alert-type-escalations/{alert_type_id}", response_model=dict)
def get_alert_type_escalation(alert_type_id: str, user_data: dict = Depends(verify_token)):
    """Get escalation config for a specific alert type"""
    try:
        response = (
            supabase.table("alert_type_escalations")
            .select("*")
            .eq("alert_type_id", alert_type_id)
            .limit(1)
            .execute()
        )
        if not response.data:
            raise HTTPException(
                status_code=404, detail=f"Alert type escalation for '{alert_type_id}' not found"
            )
        return {"response": response.data[0]}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/alert-type-escalations", response_model=dict, status_code=status.HTTP_201_CREATED)
def create_alert_type_escalation(
    escalation: AlertTypeEscalation,
    user_data: dict = Depends(verify_token),
    _: bool = Depends(has_permission("settings", "write")),
):
    """Create a new alert type escalation configuration"""
    try:
        # Check if alert_type_id already exists
        existing = (
            supabase.table("alert_type_escalations")
            .select("id")
            .eq("alert_type_id", escalation.alert_type_id)
            .execute()
        )
        if existing.data:
            raise HTTPException(
                status_code=409,
                detail=f"Alert type escalation for '{escalation.alert_type_id}' already exists",
            )

        response = (
            supabase.table("alert_type_escalations")
            .insert(
                {
                    "alert_type_id": escalation.alert_type_id,
                    "alert_type_name": escalation.alert_type_name,
                    "escalation_level": escalation.escalation_level,
                    "notification_channels": escalation.notification_channels,
                    "notification_destination": escalation.notification_destination,
                    "escalation_timeout_minutes": escalation.escalation_timeout_minutes,
                    "auto_escalate": escalation.auto_escalate,
                    "created_at": datetime.utcnow().isoformat(),
                    "updated_at": datetime.utcnow().isoformat(),
                }
            )
            .execute()
        )

        return {"response": response.data[0]}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/alert-type-escalations/{alert_type_id}", response_model=dict)
def update_alert_type_escalation(
    alert_type_id: str,
    escalation: AlertTypeEscalationUpdate,
    user_data: dict = Depends(verify_token),
    _: bool = Depends(has_permission("settings", "write")),
):
    """Update an alert type escalation configuration"""
    try:
        # Check if exists
        existing = (
            supabase.table("alert_type_escalations")
            .select("*")
            .eq("alert_type_id", alert_type_id)
            .execute()
        )
        if not existing.data:
            raise HTTPException(
                status_code=404, detail=f"Alert type escalation for '{alert_type_id}' not found"
            )

        # Build update dict
        update_data = {"updated_at": datetime.utcnow().isoformat()}
        if escalation.alert_type_name is not None:
            update_data["alert_type_name"] = escalation.alert_type_name
        if escalation.escalation_level is not None:
            update_data["escalation_level"] = escalation.escalation_level
        if escalation.notification_channels is not None:
            update_data["notification_channels"] = escalation.notification_channels
        if escalation.notification_destination is not None:
            update_data["notification_destination"] = escalation.notification_destination
        if escalation.escalation_timeout_minutes is not None:
            update_data["escalation_timeout_minutes"] = escalation.escalation_timeout_minutes
        if escalation.auto_escalate is not None:
            update_data["auto_escalate"] = escalation.auto_escalate

        response = (
            supabase.table("alert_type_escalations")
            .update(update_data)
            .eq("alert_type_id", alert_type_id)
            .execute()
        )

        return {"response": response.data[0]}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/alert-type-escalations/{alert_type_id}", response_model=dict)
def delete_alert_type_escalation(
    alert_type_id: str,
    user_data: dict = Depends(verify_token),
    _: bool = Depends(has_permission("settings", "write")),
):
    """Delete an alert type escalation configuration"""
    try:
        response = (
            supabase.table("alert_type_escalations")
            .delete()
            .eq("alert_type_id", alert_type_id)
            .execute()
        )
        if not response.data:
            raise HTTPException(
                status_code=404, detail=f"Alert type escalation for '{alert_type_id}' not found"
            )
        return {"message": "Alert type escalation deleted successfully"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/pending-actions")
def create_pending_action(action: CreatePendingAction, user_data: dict = Depends(verify_token)):
    try:
        # Check permissions - usually only system or specific roles can queue actions
        # For now allowing authenticated users for demo
        payload = action.dict()
        response = supabase.table("pending_actions").insert(payload).execute()
        return {"response": response.data[0]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/pending-actions")
def get_pending_actions(user_data: dict = Depends(verify_token), status: Optional[str] = "pending"):
    try:
        query = supabase.table("pending_actions").select("*").order("created_at", desc=True)
        if status:
            query = query.eq("status", status)

        response = query.execute()
        return {"response": response.data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/pending-actions/{action_id}/approve")
def approve_pending_action(
    action_id: int, user_data: dict = Depends(verify_token), _: bool = Depends(allow_admin)
):
    try:
        user_id = user_data.get("sub")

        # 1. Update status to approved
        update_response = (
            supabase.table("pending_actions")
            .update(
                {
                    "status": "approved",
                    "approved_by": user_id,
                    "updated_at": datetime.utcnow().isoformat(),
                }
            )
            .eq("id", action_id)
            .execute()
        )

        if not update_response.data:
            raise HTTPException(status_code=404, detail="Pending action not found")

        action = update_response.data[0]

        # 2. Execute the Logic based on action_type
        action_type = action.get("action_type", "").upper()
        payload = action.get("payload", {})

        logger.info(f"EXECUTING ACTION: {action_type} with payload {payload} for User {user_id}")

        execution_result = {"status": "success", "executed_at": datetime.utcnow().isoformat()}

        if action_type == "RESTART_SERVICE":
            service_name = payload.get("service_name")
            host = payload.get("host")
            # In a real scenario, this would trigger an Ansible job or SSH command
            # For now, we simulate success and maybe notify
            logger.info(f"Simulating service restart: {service_name} on {host}")
            execution_result["details"] = f"Service {service_name} restarted successfully on {host}"

        elif action_type == "DELETE_RESOURCE":
            resource_id = payload.get("resource_id")
            logger.info(f"Simulating resource deletion: {resource_id}")
            execution_result["details"] = f"Resource {resource_id} deleted successfully"

        else:
            logger.warning(f"Unknown action type: {action_type}")
            execution_result["details"] = (
                f"Action {action_type} marked as executed (no specific logic)"
            )

        # 3. Mark as completed
        final_response = (
            supabase.table("pending_actions")
            .update(
                {
                    "status": "completed",
                    "updated_at": datetime.utcnow().isoformat(),
                    "payload": {
                        **payload,
                        "execution_result": execution_result,
                    },  # Append result to payload or separate column? Schema has payload jsonb.
                }
            )
            .eq("id", action_id)
            .execute()
        )

        return {"message": "Action approved and executed", "response": final_response.data[0]}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/pending-actions/{action_id}/reject")
def reject_pending_action(
    action_id: int, user_data: dict = Depends(verify_token), _: bool = Depends(allow_admin)
):
    try:
        user_id = user_data.get("sub")

        response = (
            supabase.table("pending_actions")
            .update(
                {
                    "status": "rejected",
                    "approved_by": user_id,  # Rejected by
                    "updated_at": datetime.utcnow().isoformat(),
                }
            )
            .eq("id", action_id)
            .execute()
        )

        if not response.data:
            raise HTTPException(status_code=404, detail="Pending action not found")

        return {"message": "Action rejected", "response": response.data[0]}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
