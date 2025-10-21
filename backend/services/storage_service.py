'''
Deprecated GCP storage client stub removed during AWS migration.
'''
import os

UPLOAD_DIR = "local_uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

def upload_file(file):
    # Save file locally instead of uploading to cloud
    file_path = os.path.join(UPLOAD_DIR, file.filename)
    with open(file_path, "wb") as f:
        f.write(file.file.read())
    return f"/{UPLOAD_DIR}/{file.filename}"

def download_file(file_id):
    # Read file from local storage
    file_path = os.path.join(UPLOAD_DIR, file_id)
    try:
        with open(file_path, "rb") as f:
            return f.read()
    except FileNotFoundError:
        return None