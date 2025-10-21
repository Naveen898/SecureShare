from fastapi import APIRouter, Request, status, HTTPException, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from db import get_session
from models import User, Role, UserRole, SecuritySettings
from utils.security_utils import hash_password, verify_password
from datetime import datetime, timedelta, timezone
import uuid
import os
import httpx
from services.jwt_service import generate_access_token, validate_token
from utils.auth_deps import get_current_user
from services.email_service import send_reset_email, send_mfa_code_email, send_reset_code_email
from utils.logger import logger

router = APIRouter()

@router.post("/register")
async def register(request: Request, session: AsyncSession = Depends(get_session)):
    try:
        data = await request.json()
        username = data.get('username')
        password = data.get('password')
        email = data.get('email')
        hcaptcha_token = data.get('hcaptcha_token')
        if not username or not password:
            raise HTTPException(status_code=400, detail="Username and password required")
        # captcha check
        if os.getenv('HCAPTCHA_ENABLED', '0') == '1':
            secret = os.getenv('HCAPTCHA_SECRET')
            if not secret:
                raise HTTPException(status_code=500, detail="Captcha secret not configured")
            if not hcaptcha_token:
                raise HTTPException(status_code=400, detail="Captcha required")
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.post('https://hcaptcha.com/siteverify', data={'secret': secret, 'response': hcaptcha_token})
            if resp.status_code != 200 or not resp.json().get('success'):
                raise HTTPException(status_code=400, detail="Captcha failed")
        # uniqueness: username and email
        existing = await session.execute(select(User).where(User.username == username))
        if existing.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="Username taken")
        if email:
            existing_email = await session.execute(select(User).where(User.email == email))
            if existing_email.scalar_one_or_none():
                raise HTTPException(status_code=409, detail="Email already in use")
        # enforce password policy
        settings = (await session.execute(select(SecuritySettings))).scalars().first()
        min_len = settings.min_password_length if settings else 8
        if len(password) < min_len:
            raise HTTPException(status_code=400, detail=f"Password must be at least {min_len} characters")
        # regex optional
        import re
        if settings and settings.password_regex:
            if not re.fullmatch(settings.password_regex, password):
                raise HTTPException(status_code=400, detail="Password does not meet policy requirements")
        user = User(username=username, password_hash=hash_password(password), email=email)
        session.add(user)
        await session.commit()
        return {"message": "Registered"}
    except HTTPException:
        raise
    except IntegrityError as ie:
        # handle unique constraint race that slipped past the pre-checks
        logger.exception("Registration IntegrityError")
        raise HTTPException(status_code=409, detail="Duplicate entry")
    except Exception as e:
        logger.exception("Registration failed")
        # Generic message so frontend always gets valid JSON
        raise HTTPException(status_code=500, detail="Registration failed - server error (check backend logs)")

@router.post("/login")
async def login(request: Request, session: AsyncSession = Depends(get_session)):
    data = await request.json()
    username = data.get('username')
    password = data.get('password')
    hcaptcha_token = data.get('hcaptcha_token')
    if os.getenv('HCAPTCHA_ENABLED', '0') == '1':
        secret = os.getenv('HCAPTCHA_SECRET')
        if not secret:
            raise HTTPException(status_code=500, detail="Captcha secret not configured")
        if not hcaptcha_token:
            raise HTTPException(status_code=400, detail="Captcha required")
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.post('https://hcaptcha.com/siteverify', data={'secret': secret, 'response': hcaptcha_token})
        if resp.status_code != 200 or not resp.json().get('success'):
            raise HTTPException(status_code=400, detail="Captcha failed")
    result = await session.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()
    # lockout check
    if user and user.lockout_until and user.lockout_until > datetime.now(timezone.utc):
        raise HTTPException(status_code=429, detail="Account locked; try later")
    if not user or not verify_password(user.password_hash, password):
        if user:
            # increment failed attempts and set lockout after threshold
            attempts = (user.failed_login_attempts or 0) + 1
            lockout = None
            if attempts >= int(os.getenv('LOGIN_LOCKOUT_THRESHOLD', '5')):
                lockout = datetime.now(timezone.utc) + timedelta(minutes=int(os.getenv('LOGIN_LOCKOUT_MINUTES', '10')))
                attempts = 0
            await session.execute(update(User).where(User.id == user.id).values(failed_login_attempts=attempts, lockout_until=lockout))
            await session.commit()
        raise HTTPException(status_code=401, detail="Invalid credentials")
    # Load roles for claims
    roles = (await session.execute(
        select(Role.name).join(UserRole, Role.id == UserRole.role_id).where(UserRole.user_id == user.id)
    )).scalars().all()
    # MFA for admin if enabled
    # Enforce MFA according to settings
    settings = (await session.execute(select(SecuritySettings))).scalars().first()
    enforce_admin = settings.enforce_mfa_admin if settings else (os.getenv('MFA_ADMIN_ENABLED', '0') == '1')
    # Interpret enforce_mfa_all as 'enforce_mfa_users' (non-admin users)
    enforce_users = settings.enforce_mfa_all if settings else False
    require_mfa = (enforce_admin and ('admin' in roles)) or (enforce_users and ('admin' not in roles))
    if require_mfa:
        # generate one-time code and email it; require otp on second step
        code = str(uuid.uuid4()).split('-')[0]
        expires = datetime.now(timezone.utc) + timedelta(minutes=5)
        await session.execute(update(User).where(User.id == user.id).values(mfa_temp_code=code, mfa_temp_expires_at=expires))
        await session.commit()
        if user.email:
            try:
                send_mfa_code_email(user.email, user.username, code)
            except Exception:
                logger.warning("Failed to send MFA email")
        return {"mfa_required": True, "message": "MFA code sent to registered email"}
    # reset failed attempts on success
    await session.execute(update(User).where(User.id == user.id).values(failed_login_attempts=0, lockout_until=None))
    await session.commit()
    token = generate_access_token(user.id, user.username, roles=roles, department_id=user.department_id)
    return {"token": token}

@router.post("/login/verify-otp")
async def verify_otp(request: Request, session: AsyncSession = Depends(get_session)):
    data = await request.json()
    username = data.get('username')
    otp = data.get('otp')
    if not username or not otp:
        raise HTTPException(status_code=400, detail="username and otp required")
    result = await session.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()
    if not user or not user.mfa_temp_code or not user.mfa_temp_expires_at:
        raise HTTPException(status_code=400, detail="No MFA pending for user")
    # Normalize timezone awareness: assume UTC if DB returned naive datetime
    expires_at = user.mfa_temp_expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    now_utc = datetime.now(timezone.utc)
    if expires_at < now_utc or user.mfa_temp_code != otp:
        raise HTTPException(status_code=400, detail="Invalid or expired code")
    # success: clear code and issue token
    await session.execute(update(User).where(User.id == user.id).values(mfa_temp_code=None, mfa_temp_expires_at=None))
    await session.commit()
    roles = (await session.execute(
        select(Role.name).join(UserRole, Role.id == UserRole.role_id).where(UserRole.user_id == user.id)
    )).scalars().all()
    token = generate_access_token(user.id, user.username, roles=roles, department_id=user.department_id)
    return {"token": token}

@router.post("/forgot")
async def forgot(request: Request, session: AsyncSession = Depends(get_session)):
    data = await request.json()
    username = data.get('username')
    if not username:
        raise HTTPException(status_code=400, detail="Username required")
    result = await session.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()
    if not user:
        # Avoid user enumeration
        return {"message": "If account exists, reset token issued"}
    token = str(uuid.uuid4())
    expires = datetime.now(timezone.utc) + timedelta(minutes=20)
    await session.execute(update(User).where(User.id == user.id).values(reset_token=token, reset_expires_at=expires))
    await session.commit()
    # Attempt to send email if user has an email set
    if user.email:
        send_reset_email(user.email, user.username, token)
    return {"message": "Reset token generated"}

@router.post("/forgot/code")
async def forgot_code(request: Request, session: AsyncSession = Depends(get_session)):
    data = await request.json()
    username = data.get('username')
    if not username:
        raise HTTPException(status_code=400, detail="Username required")
    result = await session.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()
    # Respond success regardless to avoid enumeration
    if not user:
        return {"message": "If account exists, reset code issued"}
    code = str(uuid.uuid4()).split('-')[0]
    expires = datetime.now(timezone.utc) + timedelta(minutes=20)
    await session.execute(update(User).where(User.id == user.id).values(reset_token=code, reset_expires_at=expires))
    await session.commit()
    if user.email:
        try:
            send_reset_code_email(user.email, user.username, code)
        except Exception:
            logger.warning("Failed to send reset code email")
    return {"message": "Reset code issued"}

@router.post("/reset/code")
async def reset_with_code(request: Request, session: AsyncSession = Depends(get_session)):
    data = await request.json()
    username = data.get('username')
    code = data.get('code')
    new_password = data.get('new_password')
    if not username or not code or not new_password:
        raise HTTPException(status_code=400, detail="username, code, new_password required")
    result = await session.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()
    if not user or not user.reset_token or not user.reset_expires_at:
        raise HTTPException(status_code=400, detail="Invalid or expired code")
    exp = user.reset_expires_at
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    if exp < datetime.now(timezone.utc) or user.reset_token != code:
        raise HTTPException(status_code=400, detail="Invalid or expired code")
    # enforce password policy
    settings = (await session.execute(select(SecuritySettings))).scalars().first()
    min_len = settings.min_password_length if settings else 8
    if len(new_password) < min_len:
        raise HTTPException(status_code=400, detail=f"Password must be at least {min_len} characters")
    if settings and settings.password_regex:
        import re
        if not re.fullmatch(settings.password_regex, new_password):
            raise HTTPException(status_code=400, detail="Password does not meet policy requirements")
    await session.execute(update(User).where(User.id == user.id).values(password_hash=hash_password(new_password), reset_token=None, reset_expires_at=None))
    await session.commit()
    return {"message": "Password reset"}

@router.post("/reset")
async def reset(request: Request, session: AsyncSession = Depends(get_session)):
    data = await request.json()
    token = data.get('token')
    new_password = data.get('new_password')
    if not token or not new_password:
        raise HTTPException(status_code=400, detail="Token and new_password required")
    result = await session.execute(select(User).where(User.reset_token == token))
    user = result.scalar_one_or_none()
    if not user or not user.reset_expires_at:
        raise HTTPException(status_code=400, detail="Invalid or expired token")
    exp = user.reset_expires_at
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    if exp < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Invalid or expired token")
    await session.execute(update(User).where(User.id == user.id).values(password_hash=hash_password(new_password), reset_token=None, reset_expires_at=None))
    await session.commit()
    return {"message": "Password reset"}

@router.post("/validate")
async def validate(request: Request):
    data = await request.json()
    token = data.get('token')
    if validate_token(token):
        return {"message": "Token is valid"}
    else:
        return {"message": "Token is invalid"}, status.HTTP_401_UNAUTHORIZED

@router.post("/refresh")
async def refresh(request: Request):
    data = await request.json()
    token = data.get('token')
    if validate_token(token):
        # For simplicity, just echo success; full refresh would require reading user roles again.
        new_token = data.get('token')
        return {"token": new_token}
    else:
        return {"message": "Token is invalid"}, status.HTTP_401_UNAUTHORIZED

@router.get("/me")
async def me(ctx=Depends(get_current_user)):
    user = ctx["user"]
    roles = ctx["roles"]
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "employee_id": user.employee_id,
        "department_id": user.department_id,
        "roles": roles,
        "status": user.status,
        "created_at": user.created_at.isoformat() if user.created_at else None,
    }