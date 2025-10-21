from __future__ import annotations

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from db import get_session
from models import User, Role, UserRole
from services.jwt_service import decode_access_token

bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_user(
    creds: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    session: AsyncSession = Depends(get_session),
):
    if not creds or not creds.scheme.lower() == "bearer":
        raise HTTPException(status_code=401, detail="Authorization required")
    try:
        payload = decode_access_token(creds.credentials)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token payload")
    result = await session.execute(select(User).where(User.id == int(user_id)))
    user = result.scalar_one_or_none()
    if not user or user.status != 'active':
        raise HTTPException(status_code=403, detail="User inactive or not found")
    # attach roles for convenience
    role_ids = (await session.execute(select(UserRole.role_id).where(UserRole.user_id == user.id))).scalars().all()
    role_names = []
    if role_ids:
        role_names = (await session.execute(select(Role.name).where(Role.id.in_(role_ids)))).scalars().all()
    return {"user": user, "roles": role_names}


def require_roles(*required: str):
    async def _dep(ctx=Depends(get_current_user)):
        roles = set(ctx["roles"]) if ctx and ctx.get("roles") else set()
        if not roles.intersection(set(required)):
            raise HTTPException(status_code=403, detail="Insufficient role")
        return ctx
    return _dep
