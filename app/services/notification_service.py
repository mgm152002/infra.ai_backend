import logging
from app.core.database import supabase
from app.integrations.slack import SlackIntegration
from app.integrations.email import EmailIntegration

logger = logging.getLogger(__name__)

class NotificationService:
    @staticmethod
    def _get_credentials(user_id: str, provider: str):
        """
        Fetches credentials for a specific provider and user from Infisical.
        """
        try:
            # We need the user's email to fetch from Infisical as per the new pattern
            user_resp = supabase.table("Users").select("email").eq("id", user_id).execute()
            if not user_resp.data:
                 logger.error(f"User {user_id} not found for credential lookup")
                 return None
            
            email = user_resp.data[0]['email']
            
            from integrations.infisical import get_many
            
            if provider == "slack":
                secrets = get_many(email, ("SLACK_BOT_TOKEN", "SLACK_CHANNEL"))
                if secrets.get("SLACK_BOT_TOKEN"):
                     return {"slack_bot_token": secrets["SLACK_BOT_TOKEN"], "slack_channel": secrets.get("SLACK_CHANNEL")}
            
            elif provider == "email":
                secrets = get_many(email, ("SMTP_SERVER", "SMTP_PORT", "SENDER_EMAIL", "SENDER_PASSWORD"))
                if secrets.get("SENDER_EMAIL"):
                     return {
                        "smtp_server": secrets.get("SMTP_SERVER", "smtp.gmail.com"),
                        "smtp_port": int(secrets.get("SMTP_PORT", 587)),
                        "sender_email": secrets["SENDER_EMAIL"],
                        "sender_password": secrets["SENDER_PASSWORD"]
                     }
            
            return None
        except Exception as e:
            logger.error(f"Failed to fetch {provider} credentials for user {user_id}: {e}")
            return None

    @classmethod
    def notify_incident_created(cls, user_id: str, incident_data: dict):
        """
        Sends notifications when an incident is created.
        """
        # 1. Slack Notification
        slack_creds = cls._get_credentials(user_id, "slack")
        if slack_creds:
            try:
                slack = SlackIntegration(token=slack_creds.get("slack_bot_token"))
                channel = slack_creds.get("slack_channel")
                if channel:
                    message = (
                        f"🚨 *New Incident Created*\n"
                        f"*ID:* {incident_data.get('inc_number', 'N/A')}\n"
                        f"*Description:* {incident_data.get('short_description', 'No description')}\n"
                        f"*Priority:* {incident_data.get('priority', 'N/A')}\n"
                        f"*State:* {incident_data.get('state', 'New')}"
                    )
                    slack.send_message(channel=channel, text=message)
                    logger.info(f"Slack notification sent for incident {incident_data.get('inc_number')}")
            except Exception as e:
                logger.error(f"Failed to send Slack notification: {e}")

        # 2. Email Notification (Optional/TBD - sending to user's email if available in credentials or generic)
        # For now, we only send if we have email credentials.
        # We need a recipient. We'll use the sender_email as the recipient for self-notification 
        # or later we can look up the user's email from the Users table.
        email_creds = cls._get_credentials(user_id, "email")
        if email_creds:
            try:
                email_service = EmailIntegration(
                    smtp_server=email_creds.get("smtp_server"),
                    smtp_port=email_creds.get("smtp_port"),
                    sender_email=email_creds.get("sender_email"),
                    sender_password=email_creds.get("sender_password")
                )
                recipient = email_creds.get("sender_email") # Self-notification for now
                subject = f"New Incident Created: {incident_data.get('inc_number', 'N/A')}"
                body = (
                    f"A new incident has been created.\n\n"
                    f"ID: {incident_data.get('inc_number', 'N/A')}\n"
                    f"Description: {incident_data.get('short_description', 'No description')}\n"
                    f"Priority: {incident_data.get('priority', 'N/A')}\n"
                    f"State: {incident_data.get('state', 'New')}\n"
                )
                email_service.send_email(recipient=recipient, subject=subject, body=body)
                logger.info(f"Email notification sent for incident {incident_data.get('inc_number')}")
            except Exception as e:
                logger.error(f"Failed to send Email notification: {e}")

    @classmethod
    def notify_incident_update(cls, user_id: str, inc_number: str, update_message: str):
        """
        Sends notifications when an incident is updated (e.g. resolution/action).
        """
        # 1. Slack
        slack_creds = cls._get_credentials(user_id, "slack")
        if slack_creds:
            try:
                slack = SlackIntegration(token=slack_creds.get("slack_bot_token"))
                channel = slack_creds.get("slack_channel")
                if channel:
                    message = (
                        f"ℹ️ *Incident Update*\n"
                        f"*ID:* {inc_number}\n"
                        f"*Update:* {update_message}"
                    )
                    slack.send_message(channel=channel, text=message)
            except Exception as e:
                logger.error(f"Failed to send Slack update for {inc_number}: {e}")

notification_service = NotificationService()
