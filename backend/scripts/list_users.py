import sqlite3
import os
import hashlib

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'vaultupload.db')
DB_PATH = os.path.abspath(DB_PATH)
print('Using DB file:', DB_PATH)
con = sqlite3.connect(DB_PATH)
cur = con.cursor()
try:
    cur.execute("SELECT id, username, email, password_hash, created_at FROM users")
    rows = cur.fetchall()
    if not rows:
        print('No users found')
    else:
        for r in rows:
            uid, username, email, pwdhash, created = r
            print(f'id={uid}  username={username!r}  email={email!r}  password_hash={pwdhash!r}  created={created}')
    # Also print computed hash for 'admin' and 'admin123' for quick comparison
    print('\nComputed hashes for reference:')
    print("admin ->", hashlib.sha256(b'admin').hexdigest())
    print("admin123 ->", hashlib.sha256(b'admin123').hexdigest())
finally:
    con.close()
