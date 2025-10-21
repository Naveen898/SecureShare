from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from db import get_session
from models import Department
from utils.auth_deps import get_current_user

router = APIRouter()


@router.get("/departments")
async def list_departments(session: AsyncSession = Depends(get_session), ctx=Depends(get_current_user)):
    res = await session.execute(select(Department))
    depts = res.scalars().all()
    return {"departments": [{"id": d.id, "name": d.name} for d in depts]}
