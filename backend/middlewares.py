from functools import wraps
from flask import request, jsonify
import time
import re
from collections import defaultdict

# Simple in-memory cache
class SimpleCache:
    def __init__(self):
        self.cache = defaultdict(list)
        
    def get(self, key):
        return self.cache.get(key)
        
    def set(self, key, value, timeout=None):
        self.cache[key] = value

cache = SimpleCache()

def rate_limit(limit=100, per=3600):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            # Get client IP
            client_ip = request.remote_addr
            
            # Create unique key for this route and IP
            key = f"rate_limit_{request.endpoint}_{client_ip}"
            
            # Get current requests count
            requests = cache.get(key) or []
            now = time.time()
            
            # Clean old requests
            requests = [req for req in requests if req > now - per]
            
            if len(requests) >= limit:
                return jsonify({
                    'status': 'error',
                    'message': 'Rate limit exceeded'
                }), 429

            requests.append(now)
            cache.set(key, requests, timeout=per)
            
            return f(*args, **kwargs)
        return wrapped
    return decorator

def validate_input():
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if request.is_json:
                data = request.get_json()
                
                # Check for common injection patterns
                for key, value in data.items():
                    if isinstance(value, str):
                        if contains_injection(value):
                            return jsonify({
                                'status': 'error',
                                'message': 'Invalid input detected'
                            }), 400

            return f(*args, **kwargs)
        return wrapped
    return decorator

def contains_injection(value):
    """Check for common injection patterns."""
    patterns = [
        r'<script.*?>.*?</script>',  # XSS
        r'(?i)(?:union|select|insert|update|delete|drop)\s+',  # SQL Injection
        r'[;&|`]',  # Command Injection
    ]
    
    return any(re.search(pattern, value) for pattern in patterns)

def require_api_key():
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            api_key = request.headers.get('X-API-Key')
            if not api_key or not is_valid_api_key(api_key):
                return jsonify({
                    'status': 'error',
                    'message': 'Invalid API key'
                }), 401
            return f(*args, **kwargs)
        return wrapped
    return decorator

def is_valid_api_key(api_key):
    """Validate API key."""
    # Implement your API key validation logic here
    return True  # Placeholder
