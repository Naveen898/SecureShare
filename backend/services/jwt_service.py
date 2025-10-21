from datetime import datetime, timedelta, timezone
import jwt
import os
import uuid


'''class JWTService:
    def __init__(self):
        self.secret_key = current_app.config['JWT_SECRET_KEY']
        self.algorithm = 'HS256'

    def generate_token(self, user_id, expires_in=3600):
        expiration = datetime.utcnow() + timedelta(seconds=expires_in)
        token = jwt.encode({'user_id': user_id, 'exp': expiration}, self.secret_key, algorithm=self.algorithm)
        return token

    def decode_token(self, token):
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return payload['user_id']
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None

    def is_token_valid(self, token):
        return self.decode_token(token) is not None
'''
SECRET_KEY = os.getenv("JWT_SECRET", "your_local_secret")
SHARE_SECRET = os.getenv("SHARE_TOKEN_SECRET", SECRET_KEY)
ACCESS_TOKEN_TTL_MIN = int(os.getenv("ACCESS_TOKEN_TTL_MIN", "60"))

def generate_access_token(user_id: int, username: str, roles: list[str] | None = None, department_id: int | None = None, expires_in_minutes: int | None = None) -> str:
    now = datetime.now(timezone.utc)
    ttl_min = expires_in_minutes if isinstance(expires_in_minutes, int) and expires_in_minutes > 0 else ACCESS_TOKEN_TTL_MIN
    payload = {
        "sub": str(user_id),
        "username": username,
        "roles": roles or [],
        # keep both keys for backward compatibility with tests/clients
        "department_id": department_id,
        "dept": department_id,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=ttl_min)).timestamp()),
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def decode_access_token(token: str) -> dict:
    return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])  # raises on invalid/expired

def validate_token(token: str) -> bool:
    try:
        decode_access_token(token)
        return True
    except jwt.InvalidTokenError:
        return False

def generate_token(username: str) -> str:
    """Deprecated: kept for backward-compatibility with existing tests.
    Generates an access token with minimal claims.
    """
    return generate_access_token(user_id=0, username=username, roles=['user'])

def generate_share_token(share_id: str, expires_at: datetime):
    """Generate a JWT for shared file access including expiry (exp)."""
    payload = {
        "sid": share_id,
        "exp": int(expires_at.replace(tzinfo=timezone.utc).timestamp()),
        "jti": str(uuid.uuid4())
    }
    return jwt.encode(payload, SHARE_SECRET, algorithm="HS256")

def decode_share_token(token: str):
    return jwt.decode(token, SHARE_SECRET, algorithms=["HS256"]) 
    