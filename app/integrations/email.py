import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os

class EmailIntegration:
    def __init__(self, smtp_server=None, smtp_port=587, sender_email=None, sender_password=None):
        self.smtp_server = smtp_server or os.environ.get("SMTP_SERVER", "smtp.gmail.com")
        self.smtp_port = smtp_port or int(os.environ.get("SMTP_PORT", 587))
        self.sender_email = sender_email or os.environ.get("SENDER_EMAIL")
        self.sender_password = sender_password or os.environ.get("SENDER_PASSWORD")

    def check_auth(self):
        """
        Verifies email credentials.
        """
        if not self.sender_email or not self.sender_password:
            return False
        try:
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.sender_email, self.sender_password)
            return True
        except Exception:
            return False

    def send_email(self, recipient: str, subject: str, body: str, html: bool = False):
        """
        Sends an email.
        """
        if not self.sender_email or not self.sender_password:
            return {"error": "Email credentials missing"}

        try:
            msg = MIMEMultipart()
            msg["From"] = self.sender_email
            msg["To"] = recipient
            msg["Subject"] = subject

            if html:
                msg.attach(MIMEText(body, "html"))
            else:
                msg.attach(MIMEText(body, "plain"))

            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.sender_email, self.sender_password)
                server.sendmail(self.sender_email, recipient, msg.as_string())
            
            return {"ok": True, "message": "Email sent successfully"}
        except Exception as e:
            return {"ok": False, "error": str(e)}

# Singleton instance
email_client = EmailIntegration()
