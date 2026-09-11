"""Background escalation monitoring."""

import time
from datetime import datetime, timezone

from app.core.database import supabase
from app.core.logger import logger
from app.core.supabase_timeout import run_supabase_with_timeout
from app.services.notification_service import NotificationService

class EscalationService:
    @staticmethod
    def check_escalations():
        """
        Background task to check for incidents that need escalation.
        """
        logger.info("Escalation Monitor started")
        while True:
            try:
                # 1. Fetch open incidents
                # We fetch incidents that are NOT Resolved or Closed
                # Use a more efficient approach: query for known open states instead of excluding
                # This is faster because it uses IN which is more efficient than NOT IN
                response = run_supabase_with_timeout(
                    lambda: supabase.table("Incidents")
                    .select("id,inc_number,external_urgency,alert_type_id,external_payload,updated_at,created_at,user_id")
                    .in_("state", ["New", "Queued", "InProgress", "Assigned", "Open", "On Hold"])
                    .order("updated_at", desc=True)
                    .limit(100)  # Reduced from 300 to 100 for faster processing
                    .execute(),
                    timeout_s=120,  # Increased timeout for this query
                    operation_name="escalation_open_incidents_query",
                )
                incidents = response.data or []

                for inc in incidents:
                    try:
                        inc_id = inc['id']
                        inc_number = inc.get('inc_number')
                        # Default priority/urgency if not set
                        urgency = inc.get("external_urgency") or "medium"

                        # Use alert_type_id if available (Preferred)
                        alert_type_id = inc.get("alert_type_id")

                        if alert_type_id:
                            # Fetch directly using ID
                            at_resp = run_supabase_with_timeout(
                                lambda: supabase.table("alert_types").select("*").eq("id", alert_type_id).limit(1).execute(),
                                timeout_s=30,
                                operation_name="escalation_alert_type_by_id",
                            )
                        else:
                            # Fallback: Find matching Alert Type for this urgency
                            at_resp = run_supabase_with_timeout(
                                lambda: supabase.table("alert_types").select("*").eq("priority", urgency).limit(1).execute(),
                                timeout_s=30,
                                operation_name="escalation_alert_type_by_priority",
                            )

                        if not at_resp.data:
                            continue

                        alert_type = at_resp.data[0]

                        # Fetch Rules based on Alert Type ID
                        rules_resp = run_supabase_with_timeout(
                            lambda: supabase.table("escalation_rules").select("*").eq("alert_type_id", alert_type['id']).order("level").execute(),
                            timeout_s=30,
                            operation_name="escalation_rules_query",
                        )
                        rules = rules_resp.data or []

                        if not rules:
                            continue

                        # Determine current level
                        # stored in external_payload as specific field to avoid schema change
                        ext_payload = inc.get("external_payload") or {}
                        # external_payload might be None in DB
                        if ext_payload is None:
                            ext_payload = {}

                        current_level = ext_payload.get("escalation_level", 0)

                        # Check timing
                        # Use updated_at (last activity) or created_at
                        last_activity_str = inc.get("updated_at") or inc.get("created_at")
                        if not last_activity_str:
                            continue

                        # Handle Postgres timestamp format (may or may not have Z or timezone)
                        try:
                            last_activity = datetime.fromisoformat(last_activity_str.replace('Z', '+00:00'))
                            # Ensure last_activity is timezone-aware (make it UTC if naive)
                            if last_activity.tzinfo is None:
                                last_activity = last_activity.replace(tzinfo=timezone.utc)
                        except ValueError:
                            # Fallback if format is different
                            continue

                        now = datetime.now(timezone.utc)
                        diff_minutes = (now - last_activity).total_seconds() / 60

                        # Check rules strictly greater than current level
                        for rule in rules:
                            rule_level = rule['level']
                            wait_time = rule['wait_time_minutes']

                            if rule_level > current_level and diff_minutes >= wait_time:
                                # ESCALATE!
                                logger.info(f"Escalating Incident {inc_number} to Level {rule_level}")

                                # 1. Notify
                                contact_type = rule['contact_type']
                                _destination = rule['contact_destination']
                                message = f"🔥 ESCALATION (Level {rule_level}): Incident {inc_number} has been inactive for {int(diff_minutes)} mins. Please investigate immediately."

                                user_id = inc.get('user_id')

                                if contact_type == 'slack':
                                    # We can try to use NotificationService if we have user credentials
                                    # Or just log if we don't have a direct way to send to 'destination' channel dynamic logic
                                    # For now, let's use the NotificationService generic method but override message?
                                    # Actually, NotificationService sends to specific channel in creds.
                                    # Rule has 'destination'. We might need ad-hoc sending.
                                    # Let's try NotificationService.notify_incident_update with a prefix
                                    NotificationService.notify_incident_update(user_id, inc_number, message)

                                elif contact_type == 'email':
                                    # similar logic
                                    pass

                                # 2. Update Incident
                                ext_payload['escalation_level'] = rule_level
                                run_supabase_with_timeout(
                                    lambda: supabase.table("Incidents").update({
                                        "external_payload": ext_payload,
                                        "updated_at": datetime.utcnow().isoformat()
                                    }).eq("id", inc_id).execute(),
                                    timeout_s=30,
                                    operation_name="escalation_incident_update",
                                )

                                # Break after triggering one level (step-by-step escalation)
                                break

                    except Exception as loop_e:
                        logger.error(f"Error processing incident {inc.get('inc_number')}: {loop_e}")
                        continue

            except Exception as e:
                logger.error(f"Escalation monitor cycle failed: {e}")

            time.sleep(60) # Interval

    @staticmethod
    def start_monitoring():
        import threading
        t = threading.Thread(target=EscalationService.check_escalations, daemon=True, name="EscalationMonitor")
        t.start()
