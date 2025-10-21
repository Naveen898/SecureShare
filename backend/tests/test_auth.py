import os
import pytest
from backend.services.jwt_service import generate_access_token, decode_access_token

def test_jwt_roundtrip(monkeypatch):
  monkeypatch.setenv('JWT_SECRET', 'test-secret')
  tok = generate_access_token(1, 'tester', roles=['admin'], department_id=2, expires_in_minutes=1)
  assert isinstance(tok, str) and len(tok) > 10
  payload = decode_access_token(tok)
  assert payload['sub'] == '1'
  assert 'admin' in payload['roles']
  assert payload['dept'] == 2