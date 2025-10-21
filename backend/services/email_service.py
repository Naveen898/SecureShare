"""Simple email service for password reset links.

Environment variables used:
 SMTP_HOST (required)
 SMTP_PORT (default 587)
 SMTP_USER (optional if server allows anonymous)
 SMTP_PASS (optional)
 SMTP_STARTTLS ("1" to use STARTTLS, default 1)
 FROM_EMAIL (fallback: SMTP_USER)
 FRONTEND_BASE_URL (e.g. https://yourdomain or http://localhost:5173)

No external dependency (uses smtplib from stdlib).
"""
from __future__ import annotations

import os
import smtplib
from email.message import EmailMessage
import boto3
from utils.logger import logger


def _smtp_config():
    """Return SMTP config tuple or None if missing mandatory host.

    We treat absence of SMTP_HOST as "email disabled" instead of raising.
    """
    host = os.getenv("SMTP_HOST")
    if not host:
        return None
    port = int(os.getenv("SMTP_PORT", "587"))
    user = os.getenv("SMTP_USER")
    password = os.getenv("SMTP_PASS")
    starttls = os.getenv("SMTP_STARTTLS", "1") == "1"
    from_email = os.getenv("FROM_EMAIL") or user
    if not from_email:
        logger.warning("Email disabled: FROM_EMAIL / SMTP_USER not set")
        return None
    return host, port, user, password, starttls, from_email


def _ses_client():
    if os.getenv("SES_ENABLED", "0") != "1":
        return None
    region = os.getenv("AWS_REGION")
    if not region:
        return None
    try:
        return boto3.client("ses", region_name=region)
    except Exception:
        return None


def send_reset_email(to_email: str, username: str, token: str):
    ses = _ses_client()
    if ses:
        try:
            base = os.getenv("FRONTEND_BASE_URL", "http://localhost:5173")
            reset_link = f"{base.rstrip('/')}/reset?token={token}"
            from_email = os.getenv("FROM_EMAIL")
            ses.send_email(
                Source=from_email,
                Destination={"ToAddresses": [to_email]},
                Message={
                    "Subject": {"Data": "SecureShare Password Reset"},
                    "Body": {"Text": {"Data": f"Hello {username},\n\nUse this link within 20 minutes:\n{reset_link}\n\n— SecureShare"}},
                },
            )
            logger.info(f"Reset email sent via SES to {to_email}")
            return
        except Exception:
            logger.warning("SES send failed; falling back to SMTP if configured")
    cfg = _smtp_config()
    if not cfg:
        logger.info("Skipping reset email send (SMTP not configured)")
        return
    try:
        host, port, user, password, starttls, from_email = cfg
        base = os.getenv("FRONTEND_BASE_URL", "http://localhost:5173")
        reset_link = f"{base.rstrip('/')}/reset?token={token}"
        msg = EmailMessage()
        msg["Subject"] = "SecureShare Password Reset"
        msg["From"] = from_email
        msg["To"] = to_email
        msg.set_content(
            f"Hello {username},\n\nA password reset was requested for your SecureShare account.\n"
            f"If you initiated this request, open the link below (valid 20 minutes):\n\n{reset_link}\n\n"
            "If you did not request this, you can ignore this email.\n\n— SecureShare"
        )
        with smtplib.SMTP(host, port, timeout=15) as smtp:
            if starttls:
                try:
                    smtp.starttls()
                except Exception:
                    logger.warning("STARTTLS failed; attempting to continue without encryption")
            if user and password:
                smtp.login(user, password)
            smtp.send_message(msg)
        logger.info(f"Reset email sent to {to_email}")
    except Exception as e:
        logger.exception(f"Failed to send reset email to {to_email}: {e}")


def send_reset_code_email(to_email: str, username: str, code: str):
    ses = _ses_client()
    subject = "SecureShare Password Reset Code"
    body = f"Hello {username},\n\nYour password reset code (valid 20 minutes): {code}\n\n— SecureShare"
    if ses:
        try:
            from_email = os.getenv("FROM_EMAIL")
            ses.send_email(
                Source=from_email,
                Destination={"ToAddresses": [to_email]},
                Message={
                    "Subject": {"Data": subject},
                    "Body": {"Text": {"Data": body}},
                },
            )
            logger.info(f"Reset code email sent via SES to {to_email}")
            return
        except Exception:
            logger.warning("SES send failed; falling back to SMTP if configured")
    cfg = _smtp_config()
    if not cfg:
        logger.info("Skipping reset code email send (SMTP not configured)")
        return
    try:
        host, port, user, password, starttls, from_email = cfg
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = from_email
        msg["To"] = to_email
        msg.set_content(body)
        with smtplib.SMTP(host, port, timeout=15) as smtp:
            if starttls:
                try:
                    smtp.starttls()
                except Exception:
                    logger.warning("STARTTLS failed; attempting to continue without encryption")
            if user and password:
                smtp.login(user, password)
            smtp.send_message(msg)
        logger.info(f"Reset code email sent to {to_email}")
    except Exception as e:
        logger.exception(f"Failed to send reset code email to {to_email}: {e}")


def send_mfa_code_email(to_email: str, username: str, code: str):
    ses = _ses_client()
    if ses:
        try:
            from_email = os.getenv("FROM_EMAIL")
            ses.send_email(
                Source=from_email,
                Destination={"ToAddresses": [to_email]},
                Message={
                    "Subject": {"Data": "SecureShare Admin MFA Code"},
                    "Body": {"Text": {"Data": f"Hello {username},\n\nYour MFA code (valid 5 minutes): {code}\n\n— SecureShare"}},
                },
            )
            logger.info(f"MFA email sent via SES to {to_email}")
            return
        except Exception:
            logger.warning("SES send failed; falling back to SMTP if configured")
    cfg = _smtp_config()
    if not cfg:
        logger.info("Skipping MFA email send (SMTP not configured)")
        return
    try:
        host, port, user, password, starttls, from_email = cfg
        msg = EmailMessage()
        msg["Subject"] = "SecureShare Admin MFA Code"
        msg["From"] = from_email
        msg["To"] = to_email
        msg.set_content(
            f"Hello {username},\n\nYour SecureShare admin login requires MFA. Use the code below within 5 minutes:\n\n"
            f"Code: {code}\n\nIf this wasn't you, please secure your account.\n\n— SecureShare"
        )
        with smtplib.SMTP(host, port, timeout=15) as smtp:
            if starttls:
                try:
                    smtp.starttls()
                except Exception:
                    logger.warning("STARTTLS failed; attempting to continue without encryption")
            if user and password:
                smtp.login(user, password)
            smtp.send_message(msg)
        logger.info(f"MFA email sent to {to_email}")
    except Exception as e:
        logger.exception(f"Failed to send MFA email to {to_email}: {e}")


def send_share_notification(to_email: str, username: str, file_name: str, link: str):
    ses = _ses_client()
    subject = "SecureShare: A file has been shared with you"
    body = f"Hello {username},\n\nA file '{file_name}' has been shared with you. Access it here:\n{link}\n\n— SecureShare"
    if ses:
        try:
            from_email = os.getenv("FROM_EMAIL")
            ses.send_email(Source=from_email, Destination={"ToAddresses": [to_email]}, Message={"Subject": {"Data": subject}, "Body": {"Text": {"Data": body}}})
            logger.info(f"Share email sent via SES to {to_email}")
            return
        except Exception:
            logger.warning("SES send failed; falling back to SMTP if configured")
    cfg = _smtp_config()
    if not cfg:
        logger.info("Skipping share email send (SMTP not configured)")
        return
    try:
        host, port, user, password, starttls, from_email = cfg
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = from_email
        msg["To"] = to_email
        msg.set_content(body)
        with smtplib.SMTP(host, port, timeout=15) as smtp:
            if starttls:
                try:
                    smtp.starttls()
                except Exception:
                    logger.warning("STARTTLS failed; attempting to continue without encryption")
            if user and password:
                smtp.login(user, password)
            smtp.send_message(msg)
        logger.info(f"Share email sent to {to_email}")
    except Exception as e:
        logger.exception(f"Failed to send share email to {to_email}: {e}")


def _send_simple_email(subject: str, body: str, to_email: str) -> None:
    ses = _ses_client()
    if ses:
        try:
            from_email = os.getenv("FROM_EMAIL")
            ses.send_email(Source=from_email, Destination={"ToAddresses": [to_email]}, Message={"Subject": {"Data": subject}, "Body": {"Text": {"Data": body}}})
            logger.info(f"Email '{subject}' sent via SES to {to_email}")
            return
        except Exception:
            logger.warning("SES send failed; falling back to SMTP if configured")
    cfg = _smtp_config()
    if not cfg:
        logger.info("Skipping email send (SMTP not configured)")
        return
    try:
        host, port, user, password, starttls, from_email = cfg
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = from_email
        msg["To"] = to_email
        msg.set_content(body)
        with smtplib.SMTP(host, port, timeout=15) as smtp:
            if starttls:
                try:
                    smtp.starttls()
                except Exception:
                    logger.warning("STARTTLS failed; attempting to continue without encryption")
            if user and password:
                smtp.login(user, password)
            smtp.send_message(msg)
        logger.info(f"Email '{subject}' sent to {to_email}")
    except Exception as e:
        logger.exception(f"Failed to send email '{subject}' to {to_email}: {e}")


def send_transfer_request_email_admin(to_email: str, file_name: str, from_dept: str | None, to_dept: str | None, requester_username: str):
    subject = "SecureShare: Transfer request pending approval"
    body = (
        f"A transfer has been requested for file '{file_name}'.\n"
        f"From Department: {from_dept}\nTo Department: {to_dept}\n"
        f"Requested by: {requester_username}\n\n"
        "Please review the pending requests in the admin panel."
    )
    _send_simple_email(subject, body, to_email)


def send_transfer_decision_email(to_email: str, file_name: str, approved: bool, to_dept: str | None):
    subject = "SecureShare: Transfer request decision"
    status = "APPROVED" if approved else "REJECTED"
    body = (
        f"Your transfer request for file '{file_name}' has been {status}.\n"
        + (f"New Department: {to_dept}\n" if approved else "")
    )
    _send_simple_email(subject, body, to_email)


def send_download_notification(to_email: str, file_name: str):
    if os.getenv("NOTIFY_ON_DOWNLOAD", "0") != "1":
        return
    subject = "SecureShare: Your file was downloaded"
    body = f"Your file '{file_name}' was downloaded. If this was unexpected, please review your shares."
    _send_simple_email(subject, body, to_email)


def send_transfer_approved_owner(to_email: str, file_name: str, to_dept: str | None):
    if os.getenv("NOTIFY_OWNER_ON_TRANSFER", "1") != "1":
        return
    subject = "SecureShare: File transfer approved"
    body = f"Your file '{file_name}' has been transferred to department: {to_dept}."
    _send_simple_email(subject, body, to_email)
