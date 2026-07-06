"""Email delivery for password-reset links.

Security decisions
------------------
* Provider-agnostic. In development, EMAIL_TRANSPORT=console prints the message so
  no secrets or real mail are needed. In production, SMTP over STARTTLS with
  credentials pulled from the environment.
* The reset URL is built from a configured FRONTEND_RESET_URL (an allow-listed
  base), never from client-supplied input — this prevents the reset flow from
  being turned into an open-redirect / token-leak vector.
"""
import smtplib
from email.message import EmailMessage
from urllib.parse import urlencode

from app.config import get_settings

settings = get_settings()


def _reset_link(token: str) -> str:
    return f"{settings.frontend_reset_url}?{urlencode({'token': token})}"


def send_password_reset(to_email: str, token: str) -> None:
    link = _reset_link(token)
    subject = f"{settings.app_name}: password reset"
    body = (
        "We received a request to reset your password.\n\n"
        f"Reset link (valid for {settings.password_reset_ttl_seconds // 60} minutes):\n{link}\n\n"
        "If you did not request this, you can safely ignore this email."
    )

    if settings.email_transport == "console":
        print("\n=== [DEV EMAIL] password reset ===")
        print(f"To: {to_email}\nSubject: {subject}\n\n{body}\n==================================\n")
        return

    msg = EmailMessage()
    msg["From"] = settings.email_from
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(body)

    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as smtp:
        smtp.starttls()
        if settings.smtp_username:
            smtp.login(settings.smtp_username, settings.smtp_password)
        smtp.send_message(msg)
