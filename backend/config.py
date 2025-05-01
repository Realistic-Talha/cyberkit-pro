import os
from datetime import timedelta

class Config:
    # Flask configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-here'
    DEBUG = False
    TESTING = False

    # Security settings
    CORS_HEADERS = 'Content-Type'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    
    # Rate limiting
    RATELIMIT_DEFAULT = "100/hour"
    RATELIMIT_STORAGE_URL = "memory://"
    
    # Tool-specific settings
    PORT_SCAN_MAX_PORTS = 1000
    PORT_SCAN_TIMEOUT = 1  # seconds per port
    
    WEB_CRAWLER_MAX_DEPTH = 5
    WEB_CRAWLER_MAX_URLS = 500
    
    PACKET_CAPTURE_MAX_TIME = 300  # 5 minutes
    PACKET_CAPTURE_MAX_PACKETS = 10000
    
    # Allowed file extensions
    ALLOWED_EXTENSIONS = {'txt', 'log', 'json'}
    
    # Directory paths
    UPLOAD_FOLDER = 'uploads'
    LOG_FOLDER = 'logs'
    
    @staticmethod
    def init_app(app):
        # Create necessary directories
        os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
        os.makedirs(Config.LOG_FOLDER, exist_ok=True)

class DevelopmentConfig(Config):
    DEBUG = True

class ProductionConfig(Config):
    # Production-specific settings
    DEBUG = False
    
    # Use stronger secret key
    SECRET_KEY = os.environ.get('SECRET_KEY')
    
    # Stricter rate limiting
    RATELIMIT_DEFAULT = "50/hour"
    
    # Reduced limits for production
    PORT_SCAN_MAX_PORTS = 500
    WEB_CRAWLER_MAX_URLS = 200

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
