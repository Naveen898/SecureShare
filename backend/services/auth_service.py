from __future__ import annotations

from typing import Dict
from utils.security_utils import hash_password, verify_password
from .jwt_service import generate_access_token


class UserService:
    """Simple in-memory user store used only by tests.

    Note: The real app uses DB-backed auth in routes/auth_routes.py.
    """

    def __init__(self):
        self._users: Dict[str, str] = {}
        self._ids: Dict[str, int] = {}
        self._counter = 1

    def create_user(self, username: str, password: str) -> None:
        self._users[username] = hash_password(password)
        self._ids[username] = self._counter
        self._counter += 1

    def login(self, username: str, password: str) -> str | None:
        stored = self._users.get(username)
        if not stored or not verify_password(stored, password):
            return None
        uid = self._ids.get(username, 0)
        return generate_access_token(uid, username, roles=['user'])
