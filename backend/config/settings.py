import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your_default_secret_key'
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or 'your_jwt_secret_key'
    CORS_ALLOWED_ORIGINS = os.environ.get('CORS_ALLOWED_ORIGINS') or '*'
    FILE_EXPIRY_DAYS = int(os.environ.get('FILE_EXPIRY_DAYS', 7))  # Default expiry set to 7 days
    MAX_UPLOAD_SIZE = int(os.environ.get('MAX_UPLOAD_SIZE', 16 * 1024 * 1024))  # Default max upload size set to 16 MB

    @staticmethod
    def init_app(app):
        pass  # Additional app initialization can be done here if needed