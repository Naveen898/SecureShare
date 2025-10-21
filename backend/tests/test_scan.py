import pytest
from backend.services.scan_service import scan_file, EICAR_SIGNATURE

def test_scan_file_clean_text():
  res = scan_file('readme.txt', b'hello world')
  assert res['is_clean'] is True

def test_scan_file_blocks_eicar():
  res = scan_file('eicar.txt', EICAR_SIGNATURE)
  assert res['is_clean'] is False
  assert 'EICAR' in res['reason']