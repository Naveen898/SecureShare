from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from db import get_session
from models import User, Role, UserRole, Department, FileMetadata, FileAccessLog, SecuritySettings
from utils.auth_deps import require_roles
from utils.security_utils import hash_password
from sqlalchemy import delete, update, func

router = APIRouter()


@router.get("/users")
async def list_users(session: AsyncSession = Depends(get_session), ctx=Depends(require_roles('admin'))):
    users = (await session.execute(select(User))).scalars().all()
    out = []
    for u in users:
        out.append({
            "id": u.id,
            "username": u.username,
            "email": u.email,
            "employee_id": u.employee_id,
            "department_id": u.department_id,
            "status": u.status,
        })
    return {"users": out}


@router.post("/users")
async def create_user(payload: dict, session: AsyncSession = Depends(get_session), ctx=Depends(require_roles('admin'))):
    username = payload.get('username')
    password = payload.get('password')
    email = payload.get('email')
    employee_id = payload.get('employee_id')
    department_id = payload.get('department_id')
    roles = payload.get('roles', [])
    if not username or not password:
        raise HTTPException(status_code=400, detail="username and password required")
    exists = (await session.execute(select(User).where(User.username == username))).scalar_one_or_none()
    if exists:
        raise HTTPException(status_code=409, detail="Username taken")
    user = User(username=username, password_hash=hash_password(password), email=email, department_id=department_id, employee_id=employee_id)
    session.add(user)
    await session.commit()
    await session.refresh(user)
    # assign roles
    if roles:
        role_ids = (await session.execute(select(Role.id).where(Role.name.in_(roles)))).scalars().all()
        for rid in role_ids:
            session.add(UserRole(user_id=user.id, role_id=rid))
        await session.commit()
    return {"id": user.id}


@router.post("/users/{user_id}/reset-password")
async def admin_reset_password(user_id: int, payload: dict, session: AsyncSession = Depends(get_session), ctx=Depends(require_roles('admin'))):
    new_password = payload.get('new_password')
    if not new_password:
        raise HTTPException(status_code=400, detail="new_password required")
    target = (await session.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    target.password_hash = hash_password(new_password)
    await session.commit()
    return {"message": "Password updated"}


@router.delete("/users/{user_id}")
async def delete_user(user_id: int, session: AsyncSession = Depends(get_session), ctx=Depends(require_roles('admin'))):
    # Ensure user exists
    target = (await session.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    # Clear ownership on files to avoid FK issues
    await session.execute(update(FileMetadata).where(FileMetadata.owner_user_id == user_id).values(owner_user_id=None))
    # Remove role mappings (in case FK cascade not enforced)
    await session.execute(delete(UserRole).where(UserRole.user_id == user_id))
    # Delete user
    await session.execute(delete(User).where(User.id == user_id))
    await session.commit()
    return {"message": "deleted"}

@router.put("/users/{user_id}")
async def update_user(user_id: int, payload: dict, session: AsyncSession = Depends(get_session), ctx=Depends(require_roles('admin'))):
    target = (await session.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    # Allowed fields
    username = payload.get('username')
    email = payload.get('email')
    employee_id = payload.get('employee_id')
    department_id = payload.get('department_id')
    status = payload.get('status')  # 'active' or 'inactive'
    updates = {}
    if username and username != target.username:
        # uniqueness
        exists = (await session.execute(select(User).where(User.username == username, User.id != user_id))).scalar_one_or_none()
        if exists:
            raise HTTPException(status_code=409, detail="Username taken")
        updates['username'] = username
    if email is not None and email != target.email:
        if email:
            exists_e = (await session.execute(select(User).where(User.email == email, User.id != user_id))).scalar_one_or_none()
            if exists_e:
                raise HTTPException(status_code=409, detail="Email already in use")
        updates['email'] = email
    if employee_id is not None and employee_id != target.employee_id:
        if employee_id:
            exists_emp = (await session.execute(select(User).where(User.employee_id == employee_id, User.id != user_id))).scalar_one_or_none()
            if exists_emp:
                raise HTTPException(status_code=409, detail="Employee ID already in use")
        updates['employee_id'] = employee_id
    if department_id is not None:
        updates['department_id'] = department_id
    if status in ('active','inactive'):
        updates['status'] = status
    if not updates:
        return {"message": "no changes"}
    await session.execute(update(User).where(User.id == user_id).values(**updates))
    await session.commit()
    return {"message": "updated"}


# Roles
@router.get("/roles")
async def list_roles(session: AsyncSession = Depends(get_session), ctx=Depends(require_roles('admin'))):
    roles = (await session.execute(select(Role))).scalars().all()
    return {"roles": [{"id": r.id, "name": r.name} for r in roles]}

@router.post("/roles")
async def create_role(payload: dict, session: AsyncSession = Depends(get_session), ctx=Depends(require_roles('admin'))):
    name = payload.get('name')
    if not name:
        raise HTTPException(status_code=400, detail="name required")
    role = Role(name=name)
    session.add(role)
    await session.commit()
    await session.refresh(role)
    return {"id": role.id}

@router.delete("/roles/{role_id}")
async def delete_role(role_id: int, session: AsyncSession = Depends(get_session), ctx=Depends(require_roles('admin'))):
    await session.execute(delete(Role).where(Role.id == role_id))
    await session.commit()
    return {"message": "deleted"}


# Departments
@router.get("/departments")
async def admin_list_departments(session: AsyncSession = Depends(get_session), ctx=Depends(require_roles('admin'))):
    depts = (await session.execute(select(Department))).scalars().all()
    return {"departments": [{"id": d.id, "name": d.name, "pin_set": bool(d.pin_hash)} for d in depts]}

@router.post("/departments")
async def create_department(payload: dict, session: AsyncSession = Depends(get_session), ctx=Depends(require_roles('admin'))):
    name = payload.get('name')
    if not name:
        raise HTTPException(status_code=400, detail="name required")
    d = Department(name=name)
    session.add(d)
    await session.commit()
    await session.refresh(d)
    return {"id": d.id}

@router.delete("/departments/{dept_id}")
async def delete_department(dept_id: int, session: AsyncSession = Depends(get_session), ctx=Depends(require_roles('admin'))):
    await session.execute(delete(Department).where(Department.id == dept_id))
    await session.commit()
    return {"message": "deleted"}

@router.post("/departments/{dept_id}/pin")
async def set_department_pin(dept_id: int, payload: dict, session: AsyncSession = Depends(get_session), ctx=Depends(require_roles('admin'))):
    pin = payload.get('pin')
    if not pin:
        raise HTTPException(status_code=400, detail="pin required")
    dept = (await session.execute(select(Department).where(Department.id == dept_id))).scalar_one_or_none()
    if not dept:
        raise HTTPException(status_code=404, detail="Department not found")
    dept.pin_hash = hash_password(pin)
    await session.commit()
    return {"message": "pin set"}

@router.post("/departments/{dept_id}/pin/generate")
async def generate_department_pin(dept_id: int, session: AsyncSession = Depends(get_session), ctx=Depends(require_roles('admin'))):
    import secrets, string
    dept = (await session.execute(select(Department).where(Department.id == dept_id))).scalar_one_or_none()
    if not dept:
        raise HTTPException(status_code=404, detail="Department not found")
    alphabet = string.ascii_uppercase + string.digits
    pin = ''.join(secrets.choice(alphabet) for _ in range(6))
    dept.pin_hash = hash_password(pin)
    await session.commit()
    # Return the PIN once; do not store plaintext
    return {"pin": pin}

@router.delete("/departments/{dept_id}/pin")
async def clear_department_pin(dept_id: int, session: AsyncSession = Depends(get_session), ctx=Depends(require_roles('admin'))):
    dept = (await session.execute(select(Department).where(Department.id == dept_id))).scalar_one_or_none()
    if not dept:
        raise HTTPException(status_code=404, detail="Department not found")
    dept.pin_hash = None
    await session.commit()
    return {"message": "pin cleared"}

# Optional: verify PIN helper for admins (does not reveal PIN, only checks match)
@router.post("/departments/{dept_id}/pin/verify")
async def verify_department_pin(dept_id: int, payload: dict, session: AsyncSession = Depends(get_session), ctx=Depends(require_roles('admin'))):
    from utils.security_utils import verify_password
    pin = payload.get('pin')
    if not pin:
        raise HTTPException(status_code=400, detail="pin required")
    dept = (await session.execute(select(Department).where(Department.id == dept_id))).scalar_one_or_none()
    if not dept:
        raise HTTPException(status_code=404, detail="Department not found")
    if not dept.pin_hash:
        raise HTTPException(status_code=400, detail="PIN not set")
    ok = verify_password(dept.pin_hash, pin)
    return {"valid": bool(ok)}


# Files (admin)
@router.get("/files")
async def admin_list_files(session: AsyncSession = Depends(get_session), ctx=Depends(require_roles('admin'))):
    files = (await session.execute(select(FileMetadata))).scalars().all()
    out = []
    for f in files:
        out.append({
            "file_id": f.file_id,
            "orig_name": f.orig_name,
            "size": f.size,
            "department_id": f.department_id,
            "owner_user_id": f.owner_user_id,
            "expires_at": f.expires_at.isoformat() if f.expires_at else None,
            "deleted": f.deleted,
            "scan_status": f.scan_status,
            "scanned_at": f.scanned_at.isoformat() if f.scanned_at else None,
        })
    return {"files": out}


# Audit Logs
@router.get("/logs")
async def list_logs(limit: int = 100, session: AsyncSession = Depends(get_session), ctx=Depends(require_roles('admin'))):
    q = await session.execute(select(FileAccessLog).order_by(FileAccessLog.ts.desc()))
    logs = q.scalars().all()
    logs = logs[: max(0, min(1000, limit))]
    return {"logs": [
        {
            "id": l.id,
            "file_id": l.file_id,
            "actor_user_id": l.actor_user_id,
            "action": l.action,
            "ip": l.ip,
            "ts": l.ts.isoformat() if l.ts else None,
            "meta": l.meta,
        } for l in logs
    ]}

@router.delete("/logs")
async def clear_logs(session: AsyncSession = Depends(get_session), ctx=Depends(require_roles('admin'))):
    await session.execute(delete(FileAccessLog))
    await session.commit()
    return {"message": "logs cleared"}

@router.get("/logs/export")
async def export_logs(session: AsyncSession = Depends(get_session), ctx=Depends(require_roles('admin'))):
    q = await session.execute(select(FileAccessLog).order_by(FileAccessLog.ts.asc()))
    logs = q.scalars().all()
    lines = []
    for l in logs:
        meta = l.meta if isinstance(l.meta, (dict, list)) else str(l.meta)
        lines.append(f"{l.ts.isoformat() if l.ts else ''}\t{l.action}\tfile={l.file_id}\tuser={l.actor_user_id}\tip={l.ip}\tmeta={meta}")
    text = "\n".join(lines)
    from fastapi.responses import PlainTextResponse
    return PlainTextResponse(text, media_type="text/plain")


@router.get("/dashboard/summary")
async def dashboard_summary(session: AsyncSession = Depends(get_session), ctx=Depends(require_roles('admin'))):
    users_count = (await session.execute(select(func.count()).select_from(User))).scalar() or 0
    files_count = (await session.execute(select(func.count()).select_from(FileMetadata))).scalar() or 0
    depts_count = (await session.execute(select(func.count()).select_from(Department))).scalar() or 0
    roles_count = (await session.execute(select(func.count()).select_from(Role))).scalar() or 0
    return {
        "users": users_count,
        "files": files_count,
        "departments": depts_count,
        "roles": roles_count,
    }


# Security Settings
@router.get("/security/settings")
async def get_security_settings(session: AsyncSession = Depends(get_session), ctx=Depends(require_roles('admin'))):
    existing = (await session.execute(select(SecuritySettings))).scalars().first()
    if not existing:
        return {
            "enforce_mfa_admin": False,
            "enforce_mfa_all": False,
            "min_password_length": 8,
            "password_regex": None,
        }
    return {
        "enforce_mfa_admin": existing.enforce_mfa_admin,
        "enforce_mfa_all": existing.enforce_mfa_all,
        "min_password_length": existing.min_password_length,
        "password_regex": existing.password_regex,
    }

@router.post("/security/settings")
async def update_security_settings(payload: dict, session: AsyncSession = Depends(get_session), ctx=Depends(require_roles('admin'))):
    enforce_mfa_admin = bool(payload.get('enforce_mfa_admin', False))
    enforce_mfa_all = bool(payload.get('enforce_mfa_all', False))
    min_password_length = int(payload.get('min_password_length', 8))
    password_regex = payload.get('password_regex')
    existing = (await session.execute(select(SecuritySettings))).scalars().first()
    if existing:
        existing.enforce_mfa_admin = enforce_mfa_admin
        existing.enforce_mfa_all = enforce_mfa_all
        existing.min_password_length = min_password_length
        existing.password_regex = password_regex
    else:
        session.add(SecuritySettings(
            enforce_mfa_admin=enforce_mfa_admin,
            enforce_mfa_all=enforce_mfa_all,
            min_password_length=min_password_length,
            password_regex=password_regex,
        ))
    await session.commit()
    return {"message": "updated"}
