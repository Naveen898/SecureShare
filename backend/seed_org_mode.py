"""Seeding helper for organizational mode (Phase 1).
Run once after deploying new models to populate base roles & a default department.

Usage (example):
  uvicorn main:app --reload  (tables auto-create on startup)
  python -m backend.seed_org_mode
"""
from __future__ import annotations

import asyncio
from sqlalchemy import select
from db import AsyncSessionLocal, engine, Base
from models import Role, Department
from utils.logger import logger
import os

BASE_ROLES = ["admin", "user", "auditor", "security"]
DEFAULT_DEPARTMENTS = ["General"]


async def seed():
    async with AsyncSessionLocal() as session:
        # Roles
        existing_roles = (await session.execute(select(Role))).scalars().all()
        existing_names = {r.name for r in existing_roles}
        created = 0
        for r in BASE_ROLES:
            if r not in existing_names:
                session.add(Role(name=r))
                created += 1
        # Departments
        existing_depts = (await session.execute(select(Department))).scalars().all()
        existing_dept_names = {d.name for d in existing_depts}
        dept_created = 0
        for d in DEFAULT_DEPARTMENTS:
            if d not in existing_dept_names:
                session.add(Department(name=d))
                dept_created += 1
        if created or dept_created:
            await session.commit()
        # Create admin user if not exists
        from models import User, UserRole
        from utils.security_utils import hash_password
        admin_username = "admin"
        admin_password = os.getenv("ADMIN_PASSWORD", "admin")
        admin_email = os.getenv("ADMIN_EMAIL", "admin@secureshare.local")

        admin_user = (
            await session.execute(
                select(User).where(User.username == admin_username)
            )
        ).scalar_one_or_none()
        general_dept = (
            await session.execute(
                select(Department).where(Department.name == "General")
            )
        ).scalar_one_or_none()
        admin_role = (
            await session.execute(select(Role).where(Role.name == "admin"))
        ).scalar_one_or_none()

        if not admin_user and general_dept and admin_role:
            admin_user = User(
                username=admin_username,
                password_hash=hash_password(admin_password),
                email=admin_email,
                department_id=general_dept.id,
                employee_id=os.getenv("ADMIN_EMPLOYEE_ID", "E0001"),
            )
            session.add(admin_user)
            await session.commit()
            # Assign admin role
            session.add(UserRole(user_id=admin_user.id, role_id=admin_role.id))
            await session.commit()
            logger.info(
                f"Admin user created: username={admin_username}, password={admin_password}"
            )
        elif admin_user:
            # Update existing admin email if provided and changed
            updated = False
            if admin_email and admin_user.email != admin_email:
                admin_user.email = admin_email
                updated = True
                logger.info(f"Admin email updated to {admin_email}")
            # If ADMIN_PASSWORD is provided, reset the password
            if os.getenv("ADMIN_PASSWORD"):
                admin_user.password_hash = hash_password(admin_password)
                updated = True
                logger.info("Admin password reset from env variable ADMIN_PASSWORD")
            if updated:
                await session.commit()

        # Ensure default department PIN if provided via env
        pin = os.getenv("DEFAULT_DEPARTMENT_PIN")
        if pin and general_dept and not general_dept.pin_hash:
            from utils.security_utils import hash_password as _hp
            await session.execute(
                select(Department).where(Department.id == general_dept.id)
            )
            general_dept.pin_hash = _hp(pin)
            await session.commit()

        logger.info(
            f"Seed complete: roles added={created}, departments added={dept_created}"
        )


async def main():
    # Ensure tables exist (safety in case run outside app startup)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    await seed()


if __name__ == "__main__":
    asyncio.run(main())
