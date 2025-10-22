
from fastapi import APIRouter, UploadFile, File, HTTPException, Body, Depends, Request, Form, Query
from pydantic import BaseModel
from fastapi.responses import JSONResponse, StreamingResponse
import boto3
from botocore.exceptions import ClientError
from utils.logger import logger
from utils.security_utils import hash_password, verify_password
from services.jwt_service import generate_share_token, decode_share_token
from urllib.parse import urlencode
from services.email_service import (
    send_share_notification,
    send_transfer_request_email_admin,
    send_transfer_decision_email,
    send_download_notification,
    send_transfer_approved_owner,
)
from services.scan_service import scan_file
from datetime import datetime, timedelta, timezone
import os
from typing import List, Optional
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from db import get_session
from utils.auth_deps import get_current_user, require_roles
from models import FileMetadata, User, Department, FileRecipient, TransferRequest, FileAccessLog
import uuid
from pathlib import Path

# Local storage constants (fallback)
# STORAGE_BACKEND env var:
#   - 's3'    -> force S3
#   - 'local' -> force local filesystem under backend/local_uploads
#   - 'auto'  -> default; use S3 if credentials & bucket present, else local
UPLOAD_DIR = os.getenv("LOCAL_UPLOAD_DIR", os.path.join(os.path.dirname(os.path.dirname(__file__)), "local_uploads"))
Path(UPLOAD_DIR).mkdir(parents=True, exist_ok=True)

router = APIRouter()

MAX_FILE_SIZE = 250 * 1024 * 1024  # 250 MB
S3_BUCKET_NAME = os.getenv("AWS_S3_BUCKET", "your-s3-bucket")
AWS_REGION = os.getenv("AWS_REGION")
s3 = boto3.client("s3", region_name=AWS_REGION) if AWS_REGION else boto3.client("s3")

def _s3_bucket_accessible() -> bool:
    # Ignore placeholder bucket names
    if not S3_BUCKET_NAME or S3_BUCKET_NAME in {"your-s3-bucket", "<your-bucket>", "changeme"}:
        return False
    try:
        s3.head_bucket(Bucket=S3_BUCKET_NAME)
        return True
    except Exception:
        return False

def _storage_mode() -> str:
    """Return storage mode based on env and actual S3 accessibility when on 'auto'."""
    mode = os.getenv("STORAGE_BACKEND", "auto").lower()
    if mode in {"s3", "local"}:
        return mode
    # auto: only use S3 if bucket name is valid and reachable
    return "s3" if _s3_bucket_accessible() else "local"

MAX_SECRET_ATTEMPTS = 2

def _ensure_aware(dt: datetime) -> datetime:
    """Convert naive datetime (assumed UTC) to timezone-aware UTC."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt

IST_OFFSET = timezone(timedelta(hours=5, minutes=30))

def _format_ist(dt: datetime) -> str:
    try:
        aware = _ensure_aware(dt)  # treat naive as UTC
        return aware.astimezone(IST_OFFSET).strftime('%d-%m-%Y %H:%M:%S IST')
    except Exception:
        try:
            return dt.isoformat()
        except Exception:
            return str(dt)

@router.post("/upload")
async def upload_file(
    file: UploadFile = File(...),
    expiry_hours: int = 24,
    secret_word: Optional[str] = Form(default=None),
    session: AsyncSession = Depends(get_session),
    request: Request = None,
    ctx=Depends(get_current_user),
    comments: Optional[str] = Form(default=None),
    department_id: Optional[int] = Form(default=None),
    recipient_employee_ids: Optional[str] = Form(default=None),
):
    """Upload a file, optional secret, set expiry, virus scan, store metadata."""
    if expiry_hours < 1 or expiry_hours > 24:
        raise HTTPException(status_code=400, detail="expiry_hours must be between 1 and 24")
    try:
        # Read & size-check
        size = 0
        chunks: List[bytes] = []
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_FILE_SIZE:
                logger.warning(f"Upload rejected (too large): {file.filename} size={size}")
                raise HTTPException(status_code=413, detail="File too large (max 250MB)")
            chunks.append(chunk)
        data = b"".join(chunks)

        # Scan
        scan_result = scan_file(file.filename, data)
        if not scan_result.get("is_clean", False):
            # Deny without audit file link (no metadata row yet)
            raise HTTPException(status_code=400, detail=f"Virus scan failed: {scan_result.get('reason','unknown')}")

        # Store in S3 or local
        file_id = f"{uuid.uuid4()}_{file.filename}"
        storage = _storage_mode()
        if storage == "s3":
            try:
                s3.put_object(
                    Bucket=S3_BUCKET_NAME,
                    Key=file_id,
                    Body=data,
                    ContentType=file.content_type or "application/octet-stream",
                )
            except Exception as e:
                logger.exception("S3 upload failed")
                raise HTTPException(status_code=500, detail=f"Storage failed: {str(e)}")
        else:
            try:
                dest = os.path.join(UPLOAD_DIR, file_id)
                with open(dest, 'wb') as f:
                    f.write(data)
            except Exception as e:
                logger.exception("Local upload failed")
                raise HTTPException(status_code=500, detail=f"Local storage failed: {str(e)}")

        # DB metadata
        expires_at = datetime.utcnow().replace(tzinfo=timezone.utc) + timedelta(hours=expiry_hours)
        uploader = ctx["user"]
        # Always start file in uploader's current department; cross-department targets go through approval
        initial_department_id = uploader.department_id
        db_obj = FileMetadata(
            file_id=file_id,
            orig_name=file.filename,
            size=size,
            content_type=file.content_type or "application/octet-stream",
            secret_hash=hash_password(secret_word) if secret_word else None,
            expires_at=expires_at,
            owner_user_id=uploader.id,
            department_id=initial_department_id,
            comments=comments,
            scan_status='CLEAN',
            scanned_at=datetime.utcnow().replace(tzinfo=timezone.utc),
            scan_details=scan_result.get('details') if isinstance(scan_result, dict) else None,
        )
        session.add(db_obj)
        await session.flush()

        # Audit log for successful upload
        session.add(FileAccessLog(
            file_id=file_id,
            actor_user_id=uploader.id,
            action='upload',
            ip=request.client.host if request else None,
            meta={"size": size}
        ))
        await session.commit()
        await session.refresh(db_obj)
        logger.info(f"Uploaded file {file_id} metadata stored (db)")

        # If a different department was selected, raise a transfer request automatically
        if department_id and initial_department_id and department_id != initial_department_id:
            try:
                tr = TransferRequest(
                    file_id=file_id,
                    from_department_id=initial_department_id,
                    to_department_id=department_id,
                    requester_user_id=uploader.id,
                    reason=comments,
                )
                session.add(tr)
                await session.commit()
                # Notify admins
                from_dept = (await session.execute(select(Department.name).where(Department.id == initial_department_id))).scalar_one_or_none()
                to_dept = (await session.execute(select(Department.name).where(Department.id == department_id))).scalar_one_or_none()
                from models import Role, UserRole
                res_admins = await session.execute(
                    select(User).join(UserRole, User.id == UserRole.user_id).join(Role, Role.id == UserRole.role_id).where(Role.name == 'admin')
                )
                admins = res_admins.scalars().all()
                for adm in admins:
                    if adm.email:
                        send_transfer_request_email_admin(adm.email, db_obj.orig_name, from_dept, to_dept, uploader.username)
            except Exception:
                logger.warning("Failed to create or notify transfer request for cross-department upload")

        # Response assembly
        expires_ist_str = _format_ist(db_obj.expires_at)
        # Add recipients by employee_id if provided (comma-separated)
        added_recipients = []
        if recipient_employee_ids:
            ids = [i.strip() for i in recipient_employee_ids.split(',') if i.strip()]
            if ids:
                res = await session.execute(select(User).where(User.employee_id.in_(ids)))
                users = res.scalars().all()
                for u in users:
                    session.add(FileRecipient(file_id=file_id, user_id=u.id))
                    added_recipients.append({"user_id": u.id, "employee_id": u.employee_id, "username": u.username})
                await session.commit()
                # optionally notify via email if SES/SMTP is configured and user has email
                for u in users:
                    if u.email:
                        try:
                            # Optional notification of a file available (generic, no tokenized link)
                            send_share_notification(u.email, u.username or (u.employee_id or "user"), file.filename, "")
                        except Exception:
                            logger.warning("share email send failed for user %s", u.id)

        # Resolve readable department names
        origin_dept_id = initial_department_id
        origin_dept_name = None
        if origin_dept_id:
            origin_dept_name = (await session.execute(select(Department.name).where(Department.id == origin_dept_id))).scalar_one_or_none()
        target_dept_id = department_id or origin_dept_id
        target_dept_name = None
        if target_dept_id:
            target_dept_name = (await session.execute(select(Department.name).where(Department.id == target_dept_id))).scalar_one_or_none()
        return {
            "message": "File uploaded",
            "file_id": file_id,
            "metadata": {
                "file_id": db_obj.file_id,
                "orig_name": db_obj.orig_name,
                "size": db_obj.size,
                "expires_at": db_obj.expires_at.isoformat(),
                "expires_at_ist": expires_ist_str,
                "requires_secret": False,
                "created_at": db_obj.created_at.isoformat() if db_obj.created_at else None,
                "comments": db_obj.comments,
                # Current/owner department (origin)
                "department_id": db_obj.department_id,
                "origin_department_name": origin_dept_name,
                # Selected target (receiver) for this upload (may equal origin)
                "target_department_id": target_dept_id,
                "target_department_name": target_dept_name,
                # For backward compatibility, department_name reflects the selected target
                "department_name": target_dept_name,
                "recipients_added": added_recipients,
            },
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Upload failed")
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")

@router.get("")
async def list_files(session: AsyncSession = Depends(get_session), ctx=Depends(get_current_user)):
    try:
        now = datetime.now(timezone.utc)
        # Only show files owned by the current user (owner isolation)
        current_user = ctx["user"]
        stmt = select(FileMetadata).where(
            FileMetadata.deleted == False,  # noqa
            FileMetadata.expires_at > now,
            FileMetadata.owner_user_id == current_user.id,
        )
        result = await session.execute(stmt)
        files = result.scalars().all()
        # Resolve department names for display
        dept_ids = {f.department_id for f in files if f.department_id is not None}
        owner_dept_id = current_user.department_id
        if owner_dept_id:
            dept_ids.add(owner_dept_id)
        dept_map = {}
        if dept_ids:
            dept_rows = (await session.execute(select(Department).where(Department.id.in_(list(dept_ids))))).scalars().all()
            dept_map = {d.id: d.name for d in dept_rows}
        owner_dept_name = dept_map.get(owner_dept_id) if owner_dept_id else None
        rows = []
        for f in files:
            rows.append({
                "name": f.orig_name,
                "file_id": f.file_id,
                "size": f.size,
                "expires_at": f.expires_at.isoformat(),  # UTC ISO
                "expires_at_ist": _format_ist(f.expires_at),
                "downloadUrl": f"/api/uploads/download/{f.file_id}",
                "requires_secret": bool(f.secret_hash),
                "orig_name": f.orig_name,
                "department_id": f.department_id,
                "from_department": owner_dept_name,
                "to_department": dept_map.get(f.department_id),
            })
        return {"files": rows}
    except Exception as e:
        logger.exception("List files failed")
        raise HTTPException(status_code=500, detail=f"List failed: {str(e)}")

@router.get("/share/{file_id}")
async def generate_share(file_id: str, session: AsyncSession = Depends(get_session)):
    stmt = select(FileMetadata).where(FileMetadata.file_id == file_id, FileMetadata.deleted == False)  # noqa
    result = await session.execute(stmt)
    meta = result.scalar_one_or_none()
    if not meta:
        raise HTTPException(status_code=404, detail="File not found")
    exp = _ensure_aware(meta.expires_at)
    if exp < datetime.now(timezone.utc):
        raise HTTPException(status_code=410, detail="File expired")
    share_token = generate_share_token(file_id, exp)
    return {"share_token": share_token, "expires_at": exp.isoformat(), "expires_at_ist": _format_ist(exp), "requires_secret": bool(meta.secret_hash)}

@router.post("/access/{file_id}")
async def access_file(file_id: str, token: str = Body(...), secret_word: Optional[str] = Body(default=None), session: AsyncSession = Depends(get_session), request: Request = None):
    stmt = select(FileMetadata).where(FileMetadata.file_id == file_id, FileMetadata.deleted == False)  # noqa
    result = await session.execute(stmt)
    meta = result.scalar_one_or_none()
    if not meta:
        raise HTTPException(status_code=404, detail="File not found")
    exp = _ensure_aware(meta.expires_at)
    if exp < datetime.now(timezone.utc):
        raise HTTPException(status_code=410, detail="File expired")
    try:
        payload = decode_share_token(token)
        if payload.get("sid") != file_id:
            raise HTTPException(status_code=401, detail="Invalid token")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")
    if meta.secret_hash:
        # Provide clearer feedback before counting attempts
        if not secret_word:
            raise HTTPException(status_code=400, detail="Secret required")
        if meta.secret_attempts >= MAX_SECRET_ATTEMPTS:
            raise HTTPException(status_code=429, detail="Too many attempts")
        if not verify_password(meta.secret_hash, secret_word):
            await session.execute(update(FileMetadata).where(FileMetadata.file_id == file_id).values(secret_attempts=FileMetadata.secret_attempts + 1))  # type: ignore
            await session.commit()
            raise HTTPException(status_code=401, detail="Invalid secret")
        # reset attempts on success
        await session.execute(update(FileMetadata).where(FileMetadata.file_id == file_id).values(secret_attempts=0))
        await session.commit()
    # Stream from storage
    storage = _storage_mode()
    if storage == "s3":
        try:
            s3.head_object(Bucket=S3_BUCKET_NAME, Key=file_id)
        except ClientError as ce:
            if ce.response.get("ResponseMetadata", {}).get("HTTPStatusCode") == 404 or ce.response.get("Error", {}).get("Code") in {"404", "NotFound", "NoSuchKey"}:
                raise HTTPException(status_code=404, detail="File not found")
            logger.exception("S3 head_object failed")
            raise HTTPException(status_code=500, detail="Storage error")
        obj = s3.get_object(Bucket=S3_BUCKET_NAME, Key=file_id)
        body = obj["Body"]
    else:
        local_path = os.path.join(UPLOAD_DIR, file_id)
        if not os.path.exists(local_path):
            raise HTTPException(status_code=404, detail="File not found")
        body = open(local_path, 'rb')
    # Audit log & notify owner on download if enabled
    try:
        session.add(FileAccessLog(
            file_id=file_id,
            actor_user_id=None,
            action='download',
            ip=request.client.host if request else None
        ))
        await session.commit()
        if meta.owner_user_id:
            owner = (await session.execute(select(User).where(User.id == meta.owner_user_id))).scalar_one_or_none()
            if owner and owner.email:
                send_download_notification(owner.email, meta.orig_name)
    except Exception:
        logger.warning("Failed to send download notification")
    return StreamingResponse(body, media_type="application/octet-stream", headers={"Content-Disposition": f"attachment; filename={meta.orig_name}"})

@router.post("/public/metadata")
async def public_metadata(request: Request, session: AsyncSession = Depends(get_session), ctx=Depends(get_current_user)):
    data = await request.json()
    file_id = data.get('file_id')
    employee_id = data.get('employee_id')  # optional intended recipient claim
    department_id = data.get('department_id')  # receiver department
    if not file_id:
        raise HTTPException(status_code=400, detail="file_id required")
    meta = (await session.execute(select(FileMetadata).where(FileMetadata.file_id == file_id, FileMetadata.deleted == False))).scalar_one_or_none()  # noqa
    if not meta:
        raise HTTPException(status_code=404, detail="Not found")
    exp = _ensure_aware(meta.expires_at)
    if exp < datetime.now(timezone.utc):
        raise HTTPException(status_code=410, detail="Expired")
    # Resolve sender and departments
    owner = (await session.execute(select(User).where(User.id == meta.owner_user_id))).scalar_one_or_none()
    sender_name = owner.username if owner else None
    # Enforce that when department_id is provided for dept-wide lookup, it matches the logged-in user's department (unless admin)
    if department_id is not None:
        try:
            department_id_int = int(department_id)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid department_id")
        roles = set(ctx.get("roles") or [])
        user_dept = ctx.get("user").department_id if ctx.get("user") else None
        if 'admin' not in roles and user_dept != department_id_int:
            raise HTTPException(status_code=403, detail="Not authorized for this department")
    # Check if receiver is intended: either direct recipient match or department match
    intended = False
    pending = False
    # If file has explicit recipients, department-wide access is not allowed
    has_recipient = (await session.execute(select(FileRecipient).where(FileRecipient.file_id == file_id))).scalar_one_or_none() is not None
    # direct user match; employee_id must match the logged-in user
    if employee_id:
        if ctx.get("user") and ctx.get("user").employee_id and employee_id != ctx.get("user").employee_id:
            # Do not allow claiming another employee's identity
            raise HTTPException(status_code=403, detail="Not authorized")
        u = (await session.execute(select(User).where(User.employee_id == employee_id))).scalar_one_or_none()
        if u:
            rec = (await session.execute(select(FileRecipient).where(FileRecipient.file_id == file_id, FileRecipient.user_id == u.id))).scalar_one_or_none()
            if rec:
                intended = True
                # For cross-dept before approval, allow viewing metadata but mark pending
                if meta.department_id and u.department_id and meta.department_id != u.department_id:
                    # Check if there's a pending transfer to receiver's department
                    tr = (await session.execute(select(TransferRequest).where(TransferRequest.file_id == file_id, TransferRequest.to_department_id == u.department_id, TransferRequest.status == 'PENDING'))).scalar_one_or_none()
                    if tr:
                        pending = True
    # department match (dept-wide share) only if there are no explicit recipients
    if not intended and department_id and not has_recipient:
        try:
            department_id_int = int(department_id)
        except Exception:
            department_id_int = None
        if department_id_int and meta.department_id == department_id_int:
            intended = True
    status = 'PENDING_APPROVAL' if pending else ('OK' if intended else 'NOT_ALLOWED')
    if status == 'NOT_ALLOWED':
        # Do not reveal details
        raise HTTPException(status_code=404, detail="Not found")
    # Names for origin and (if provided) receiver department
    dept_name = (await session.execute(select(Department.name).where(Department.id == meta.department_id))).scalar_one_or_none()
    receiver_dept_name = None
    if department_id is not None:
        try:
            did = int(department_id)
            receiver_dept_name = (await session.execute(select(Department.name).where(Department.id == did))).scalar_one_or_none()
        except Exception:
            receiver_dept_name = None
    return {
        "status": status,
        "file": {
            "file_id": meta.file_id,
            "name": meta.orig_name,
            "size": meta.size,
            "expires_at": meta.expires_at.isoformat(),
            "expires_at_ist": _format_ist(meta.expires_at),
            "sender": sender_name,
            "department": dept_name,
            "sender_department": dept_name,
            "receiver_department": receiver_dept_name,
            "comments": meta.comments,
        }
    }

@router.post("/public/download")
async def public_download(request: Request, session: AsyncSession = Depends(get_session), ctx=Depends(get_current_user)):
    data = await request.json()
    file_id = data.get('file_id')
    department_id = data.get('department_id')
    department_pin = data.get('department_pin')
    employee_id = data.get('employee_id')  # optional
    if not file_id or not department_id or not department_pin:
        raise HTTPException(status_code=400, detail="file_id, department_id, department_pin required")
    try:
        department_id_int = int(department_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid department_id")
    meta = (await session.execute(select(FileMetadata).where(FileMetadata.file_id == file_id, FileMetadata.deleted == False))).scalar_one_or_none()  # noqa
    if not meta:
        raise HTTPException(status_code=404, detail="Not found")
    exp = _ensure_aware(meta.expires_at)
    if exp < datetime.now(timezone.utc):
        raise HTTPException(status_code=410, detail="Expired")
    # Verify PIN for provided department
    dept = (await session.execute(select(Department).where(Department.id == department_id_int))).scalar_one_or_none()
    if not dept or not dept.pin_hash:
        raise HTTPException(status_code=403, detail="Department PIN not set")
    if not verify_password(dept.pin_hash, department_pin):
        raise HTTPException(status_code=401, detail="Invalid PIN")
    # Authorization: department-based download must be for the user's own department (unless admin)
    roles = set(ctx.get("roles") or [])
    user_dept = ctx.get("user").department_id if ctx.get("user") else None
    if 'admin' not in roles and user_dept != department_id_int:
        raise HTTPException(status_code=403, detail="Not authorized for this department")

    # Verify intended receiver
    intended = False
    # If file has explicit recipients, department-wide access is not allowed
    has_recipient = (await session.execute(select(FileRecipient).where(FileRecipient.file_id == file_id))).scalar_one_or_none() is not None
    if employee_id:
        # employee_id must match logged-in user to prevent impersonation
        if ctx.get("user") and ctx.get("user").employee_id and employee_id != ctx.get("user").employee_id:
            raise HTTPException(status_code=403, detail="Not authorized")
        u = (await session.execute(select(User).where(User.employee_id == employee_id))).scalar_one_or_none()
        if u:
            rec = (await session.execute(select(FileRecipient).where(FileRecipient.file_id == file_id, FileRecipient.user_id == u.id))).scalar_one_or_none()
            if rec:
                # If cross-dept, ensure approved
                if meta.department_id and u.department_id and meta.department_id != u.department_id:
                    tr = (await session.execute(select(TransferRequest).where(TransferRequest.file_id == file_id, TransferRequest.to_department_id == u.department_id, TransferRequest.status == 'APPROVED'))).scalar_one_or_none()
                    if tr:
                        intended = True
                else:
                    intended = True
    # dept-wide access only if there are no explicit recipients: allow within current file department, or if an approved transfer to requested department exists
    if not intended and not has_recipient:
        if meta.department_id == department_id_int:
            intended = True
        else:
            tr_ok = (await session.execute(select(TransferRequest).where(TransferRequest.file_id == file_id, TransferRequest.to_department_id == department_id_int, TransferRequest.status == 'APPROVED'))).scalar_one_or_none()
            if tr_ok:
                intended = True
    if not intended:
        raise HTTPException(status_code=404, detail="Not found")
    # Stream from storage
    storage = _storage_mode()
    if storage == "s3":
        try:
            s3.head_object(Bucket=S3_BUCKET_NAME, Key=file_id)
        except ClientError as ce:
            if ce.response.get("ResponseMetadata", {}).get("HTTPStatusCode") == 404 or ce.response.get("Error", {}).get("Code") in {"404", "NotFound", "NoSuchKey"}:
                raise HTTPException(status_code=404, detail="File not found")
            logger.exception("S3 head_object failed")
            raise HTTPException(status_code=500, detail="Storage error")
        obj = s3.get_object(Bucket=S3_BUCKET_NAME, Key=file_id)
        body = obj["Body"]
    else:
        local_path = os.path.join(UPLOAD_DIR, file_id)
        if not os.path.exists(local_path):
            raise HTTPException(status_code=404, detail="File not found")
        body = open(local_path, 'rb')
    # Audit log & notify both parties on download
    try:
        session.add(FileAccessLog(
            file_id=file_id,
            actor_user_id=None,
            action='download',
            ip=request.client.host if request else None
        ))
        await session.commit()
        # Notify owner
        if meta.owner_user_id:
            owner = (await session.execute(select(User).where(User.id == meta.owner_user_id))).scalar_one_or_none()
            if owner and owner.email:
                send_download_notification(owner.email, meta.orig_name)
        # Notify receiver if known
        if employee_id:
            u = (await session.execute(select(User).where(User.employee_id == employee_id))).scalar_one_or_none()
            if u and u.email:
                try:
                    from services.email_service import _send_simple_email
                    _send_simple_email("SecureShare: File downloaded", f"You downloaded file '{meta.orig_name}' from {owner.username if meta.owner_user_id else 'sender'}.", u.email)
                except Exception:
                    logger.warning("Failed to notify receiver of download")
    except Exception:
        logger.warning("Failed to send download notifications (public)")
    return StreamingResponse(body, media_type="application/octet-stream", headers={"Content-Disposition": f"attachment; filename={meta.orig_name}"})

# Removed insecure direct download route; all downloads must go through validated flow

@router.delete("/{file_id}")
async def delete_file(file_id: str, session: AsyncSession = Depends(get_session), ctx=Depends(get_current_user)):
    try:
        stmt = select(FileMetadata).where(FileMetadata.file_id == file_id, FileMetadata.deleted == False)  # noqa
        result = await session.execute(stmt)
        meta = result.scalar_one_or_none()
        if not meta:
            raise HTTPException(status_code=404, detail="File not found")
        # Authorization: admin role or owner can delete
        roles = set(ctx.get("roles") or [])
        user = ctx.get("user")
        is_admin = 'admin' in roles
        is_owner = user and meta.owner_user_id == user.id
        if not (is_admin or is_owner):
            raise HTTPException(status_code=403, detail="Not authorized to delete this file")
        storage = _storage_mode()
        if storage == "s3":
            try:
                s3.delete_object(Bucket=S3_BUCKET_NAME, Key=file_id)
            except Exception:
                # If not found, ignore; else log
                logger.warning(f"S3 delete attempt for missing key: {file_id}")
        else:
            local_path = os.path.join(UPLOAD_DIR, file_id)
            try:
                if os.path.exists(local_path):
                    os.remove(local_path)
            except Exception:
                logger.warning(f"Local delete failed for {file_id}")
        await session.execute(update(FileMetadata).where(FileMetadata.file_id == file_id).values(deleted=True))
        await session.commit()
        logger.info(f"Deleted file {file_id}")
        return {"message": "Deleted", "filename": file_id}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Delete failed")
        raise HTTPException(status_code=500, detail=f"Delete failed: {str(e)}")

@router.post("/internal/access/{file_id}")
async def internal_access(file_id: str, department_pin: str = Body(...), session: AsyncSession = Depends(get_session), ctx=Depends(get_current_user), request: Request = None):
    stmt = select(FileMetadata).where(FileMetadata.file_id == file_id, FileMetadata.deleted == False)  # noqa
    result = await session.execute(stmt)
    meta = result.scalar_one_or_none()
    if not meta:
        raise HTTPException(status_code=404, detail="File not found")
    dept = (await session.execute(select(Department).where(Department.id == meta.department_id))).scalar_one_or_none()
    if not dept or not dept.pin_hash:
        raise HTTPException(status_code=403, detail="Department PIN not set")
    if not verify_password(dept.pin_hash, department_pin):
        raise HTTPException(status_code=401, detail="Invalid department PIN")
    try:
        s3.head_object(Bucket=S3_BUCKET_NAME, Key=file_id)
    except ClientError as ce:
        if ce.response.get("ResponseMetadata", {}).get("HTTPStatusCode") == 404 or ce.response.get("Error", {}).get("Code") in {"404", "NotFound", "NoSuchKey"}:
            raise HTTPException(status_code=404, detail="File not found")
        logger.exception("S3 head_object failed")
        raise HTTPException(status_code=500, detail="Storage error")
    obj = s3.get_object(Bucket=S3_BUCKET_NAME, Key=file_id)
    body = obj["Body"]
    # Audit log & notify owner on download if enabled
    try:
        session.add(FileAccessLog(
            file_id=file_id,
            actor_user_id=ctx["user"].id if ctx and ctx.get("user") else None,
            action='download',
            ip=request.client.host if request else None
        ))
        await session.commit()
        if meta.owner_user_id:
            owner = (await session.execute(select(User).where(User.id == meta.owner_user_id))).scalar_one_or_none()
            if owner and owner.email:
                send_download_notification(owner.email, meta.orig_name)
    except Exception:
        logger.warning("Failed to send download notification (internal)")
    return StreamingResponse(body, media_type="application/octet-stream", headers={"Content-Disposition": f"attachment; filename={meta.orig_name}"})

@router.post("/transfer/request/{file_id}")
async def request_transfer(file_id: str, to_department_id: int = Body(...), reason: Optional[str] = Body(default=None), session: AsyncSession = Depends(get_session), ctx=Depends(get_current_user), request: Request = None):
    stmt = select(FileMetadata).where(FileMetadata.file_id == file_id, FileMetadata.deleted == False)  # noqa
    result = await session.execute(stmt)
    meta = result.scalar_one_or_none()
    if not meta:
        raise HTTPException(status_code=404, detail="File not found")
    tr = TransferRequest(
        file_id=file_id,
        from_department_id=meta.department_id,
        to_department_id=to_department_id,
        requester_user_id=ctx["user"].id,
        reason=reason,
    )
    session.add(tr)
    await session.commit()
    # Audit
    try:
        session.add(FileAccessLog(file_id=file_id, actor_user_id=ctx["user"].id, action='request', ip=request.client.host if request else None, meta={"to_department_id": to_department_id, "reason": reason}))
        await session.commit()
    except Exception:
        pass
    # Notify admins via email (simple heuristic: all users with 'admin' role and email)
    try:
        admin_users = (await session.execute(
            select(User).join_from(User, FileRecipient, isouter=True)  # unrelated join to keep SA quiet on no joins
        ))  # dummy select to satisfy typing
        # Real selection for admins
        from models import Role, UserRole
        res_admins = await session.execute(
            select(User).join(UserRole, User.id == UserRole.user_id).join(Role, Role.id == UserRole.role_id).where(Role.name == 'admin')
        )
        admins = res_admins.scalars().all()
        from_dept = (await session.execute(select(Department.name).where(Department.id == meta.department_id))).scalar_one_or_none()
        to_dept = (await session.execute(select(Department.name).where(Department.id == to_department_id))).scalar_one_or_none()
        for adm in admins:
            if adm.email:
                send_transfer_request_email_admin(adm.email, meta.orig_name, from_dept, to_dept, ctx["user"].username)
    except Exception:
        logger.warning("Failed to send transfer request admin emails")
    return {"message": "Transfer requested", "request_id": tr.id}

@router.get("/transfer/pending")
async def list_pending_transfers(session: AsyncSession = Depends(get_session), ctx=Depends(require_roles('admin'))):
    res = await session.execute(select(TransferRequest).where(TransferRequest.status == 'PENDING'))
    trs = res.scalars().all()
    out = []
    for t in trs:
        from_name = (await session.execute(select(Department.name).where(Department.id == t.from_department_id))).scalar_one_or_none() if t.from_department_id else None
        to_name = (await session.execute(select(Department.name).where(Department.id == t.to_department_id))).scalar_one_or_none() if t.to_department_id else None
        out.append({
            "id": t.id,
            "file_id": t.file_id,
            "from_department_id": t.from_department_id,
            "from_department": from_name,
            "to_department_id": t.to_department_id,
            "to_department": to_name,
            "requester_user_id": t.requester_user_id,
            "status": t.status,
            "reason": t.reason,
            "created_at": t.created_at.isoformat() if t.created_at else None,
        })
    return {"requests": out}

class TransferDecisionBody(BaseModel):
    approve: Optional[bool] = None
    reason: Optional[str] = None

@router.post("/transfer/decision/{request_id}")
async def decide_transfer(request_id: str, body: Optional[TransferDecisionBody] = Body(default=None), approve_q: Optional[bool] = Query(default=None), session: AsyncSession = Depends(get_session), ctx=Depends(require_roles('admin')), request: Request = None):
    # Accept JSON body {"approve": true/false} or fallback to query ?approve=true
    approve: Optional[bool] = None
    if body and body.approve is not None:
        approve = bool(body.approve)
    elif approve_q is not None:
        approve = bool(approve_q)
    elif request is not None:
        # Last-resort: try to parse raw JSON body for { "approve": ... }
        try:
            raw = await request.json()
            if isinstance(raw, dict) and "approve" in raw:
                approve = bool(raw.get("approve"))
        except Exception:
            pass
    if approve is None:
        raise HTTPException(status_code=422, detail="approve required in body or query")
    res = await session.execute(select(TransferRequest).where(TransferRequest.id == request_id))
    tr = res.scalar_one_or_none()
    if not tr or tr.status != 'PENDING':
        raise HTTPException(status_code=404, detail="Transfer request not found or already decided")
    new_status = 'APPROVED' if approve else 'REJECTED'
    update_values = {"status": new_status, "decided_by_user_id": ctx["user"].id, "decided_at": datetime.now(timezone.utc)}
    if body and body.reason:
        update_values["reason"] = body.reason
    await session.execute(update(TransferRequest).where(TransferRequest.id == request_id).values(**update_values))
    if approve and tr.to_department_id:
        await session.execute(update(FileMetadata).where(FileMetadata.file_id == tr.file_id).values(department_id=tr.to_department_id))
    await session.commit()
    # Audit
    try:
        session.add(FileAccessLog(file_id=tr.file_id, actor_user_id=ctx["user"].id, action='approve' if approve else 'reject', ip=request.client.host if request else None, meta={"to_department_id": tr.to_department_id}))
        await session.commit()
    except Exception:
        pass
    # Notify requester of decision
    try:
        requester = (await session.execute(select(User).where(User.id == tr.requester_user_id))).scalar_one_or_none()
        to_dept = (await session.execute(select(Department.name).where(Department.id == tr.to_department_id))).scalar_one_or_none()
        meta = (await session.execute(select(FileMetadata).where(FileMetadata.file_id == tr.file_id))).scalar_one_or_none()
        if requester and requester.email and meta:
            send_transfer_decision_email(requester.email, meta.orig_name, approve, to_dept)
        # Notify owner if department changed
        if approve and meta and meta.owner_user_id:
            owner = (await session.execute(select(User).where(User.id == meta.owner_user_id))).scalar_one_or_none()
            if owner and owner.email:
                send_transfer_approved_owner(owner.email, meta.orig_name, to_dept)
    except Exception:
        logger.warning("Failed to send transfer decision email")
    return {"message": f"Transfer {new_status.lower()}"}

@router.get("/transfer/mine")
async def list_my_transfers(session: AsyncSession = Depends(get_session), ctx=Depends(get_current_user)):
    res = await session.execute(select(TransferRequest).where(TransferRequest.requester_user_id == ctx["user"].id))
    trs = res.scalars().all()
    out = []
    for t in trs:
        from_name = (await session.execute(select(Department.name).where(Department.id == t.from_department_id))).scalar_one_or_none() if t.from_department_id else None
        to_name = (await session.execute(select(Department.name).where(Department.id == t.to_department_id))).scalar_one_or_none() if t.to_department_id else None
        out.append({
            "id": t.id,
            "file_id": t.file_id,
            "from_department_id": t.from_department_id,
            "from_department": from_name,
            "to_department_id": t.to_department_id,
            "to_department": to_name,
            "status": t.status,
            "reason": t.reason,
            "created_at": t.created_at.isoformat() if t.created_at else None,
            "decided_at": t.decided_at.isoformat() if t.decided_at else None,
        })
    return {"requests": out}

@router.get("/transfer/all")
async def list_all_transfers(session: AsyncSession = Depends(get_session), ctx=Depends(require_roles('admin'))):
    res = await session.execute(select(TransferRequest))
    trs = res.scalars().all()
    out = []
    for t in trs:
        from_name = (await session.execute(select(Department.name).where(Department.id == t.from_department_id))).scalar_one_or_none() if t.from_department_id else None
        to_name = (await session.execute(select(Department.name).where(Department.id == t.to_department_id))).scalar_one_or_none() if t.to_department_id else None
        out.append({
            "id": t.id,
            "file_id": t.file_id,
            "from_department_id": t.from_department_id,
            "from_department": from_name,
            "to_department_id": t.to_department_id,
            "to_department": to_name,
            "requester_user_id": t.requester_user_id,
            "status": t.status,
            "reason": t.reason,
            "created_at": t.created_at.isoformat() if t.created_at else None,
            "decided_at": t.decided_at.isoformat() if t.decided_at else None,
        })
    return {"requests": out}
