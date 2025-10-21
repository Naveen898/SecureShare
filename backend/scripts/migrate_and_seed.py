"""Run DB migrations to head and then execute seed_org_mode.

Usage:
  python -m backend.scripts.migrate_and_seed
"""
from __future__ import annotations

import subprocess
import sys
import os

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, os.pardir))


def run(cmd: list[str]) -> int:
    print("$", " ".join(cmd))
    return subprocess.call(cmd, cwd=ROOT)


def run_capture(cmd: list[str]) -> tuple[int, str, str]:
    print("$", " ".join(cmd))
    p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    if p.stdout:
        print(p.stdout.strip())
    if p.stderr:
        print(p.stderr.strip())
    return p.returncode, p.stdout, p.stderr


def main() -> int:
    # If DB is unversioned but already has tables (from create_all), stamp instead of upgrade
    _, out, _ = run_capture([sys.executable, "-m", "alembic", "current"])
    if "None" in out:
        code = run([sys.executable, "-m", "alembic", "stamp", "head"])
        if code != 0:
            return code
    else:
        code = run([sys.executable, "-m", "alembic", "upgrade", "head"])
        if code != 0:
            return code
    # Run seed
    return run([sys.executable, "-m", "backend.seed_org_mode"])


if __name__ == "__main__":
    raise SystemExit(main())
