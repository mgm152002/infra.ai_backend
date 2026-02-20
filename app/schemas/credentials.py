from pydantic import BaseModel
from typing import Optional

class SlackConfig(BaseModel):
    slack_bot_token: str
    slack_channel: Optional[str] = None

class EmailConfig(BaseModel):
    smtp_server: str = "smtp.gmail.com"
    smtp_port: int = 587
    sender_email: str
    sender_password: str
