import os
import time

def validate_file(file):
    # For local testing, allow all files
    return True

def validate_file_extension(filename, allowed_extensions):
    """Validate the file extension against allowed extensions."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

def generate_unique_filename(original_filename):
    """Generate a unique filename by appending a timestamp."""
    base, ext = os.path.splitext(original_filename)
    unique_filename = f"{base}_{int(time.time())}{ext}"
    return unique_filename

def save_file(file, upload_folder):
    """Save the uploaded file to the specified folder."""
    if not os.path.exists(upload_folder):
        os.makedirs(upload_folder)
    file_path = os.path.join(upload_folder, file.filename)
    file.save(file_path)
    return file_path

def get_file_size(file):
    """Return the size of the uploaded file."""
    return len(file.read())

def is_file_size_valid(file, max_size):
    """Check if the file size is within the allowed limit."""
    file.seek(0)  # Reset file pointer to the beginning
    return get_file_size(file) <= max_size

def delete_file(file_path):
    """Delete the specified file."""
    if os.path.exists(file_path):
        os.remove(file_path)
        return True
    return False
