import pytest

pytestmark = pytest.mark.skip(reason="Legacy Flask-based tests skipped; backend uses FastAPI + S3")