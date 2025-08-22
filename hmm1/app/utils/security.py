"""
Security utilities for authentication and encryption
"""
import hashlib
import secrets
import bcrypt
import jwt
import logging
from typing import Optional, Dict, Any
from datetime import datetime, timezone, timedelta
from flask import request
from werkzeug.security import generate_password_hash as werkzeug_hash

logger = logging.getLogger(__name__)

def hash_password(password: str) -> str:
    """Hash password using bcrypt"""
    try:
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')
    except Exception as e:
        logger.error(f"Password hashing error: {e}")
        return werkzeug_hash(password)

def verify_password(password: str, hashed: str) -> bool:
    """Verify password against hash"""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    except Exception as e:
        logger.error(f"Password verification error: {e}")
        from werkzeug.security import check_password_hash
        return check_password_hash(hashed, password)

def generate_session_id() -> str:
    """Generate secure session ID"""
    return secrets.token_urlsafe(32)

def generate_csrf_token() -> str:
    """Generate CSRF token"""
    return secrets.token_urlsafe(32)

def generate_challenge_token() -> str:
    """Generate challenge token"""
    timestamp = str(int(datetime.now(timezone.utc).timestamp()))
    random_part = secrets.token_hex(16)
    return f"{timestamp}:{random_part}"

def verify_challenge_token(token: str, max_age_seconds: int = 600) -> bool:
    """Verify challenge token validity"""
    try:
        parts = token.split(':')
        if len(parts) != 2:
            return False
        
        timestamp_str, _ = parts
        token_timestamp = int(timestamp_str)
        current_timestamp = int(datetime.now(timezone.utc).timestamp())
        
        return (current_timestamp - token_timestamp) <= max_age_seconds
    except Exception as e:
        logger.error(f"Challenge token verification error: {e}")
        return False

def create_jwt_token(user_id: int, session_id: str, secret_key: str, 
                    expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT token"""
    try:
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(hours=24)
        
        payload = {
            'sub': str(user_id),
            'session_id': session_id,
            'iat': datetime.now(timezone.utc),
            'exp': expire
        }
        
        return jwt.encode(payload, secret_key, algorithm='HS256')
    except Exception as e:
        logger.error(f"JWT creation error: {e}")
        raise

def verify_jwt_token(token: str, secret_key: str) -> Optional[Dict[str, Any]]:
    """Verify and decode JWT token"""
    try:
        payload = jwt.decode(token, secret_key, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        logger.warning("JWT token expired")
        return None
    except jwt.InvalidTokenError as e:
        logger.warning(f"Invalid JWT token: {e}")
        return None

def verify_jwt_in_request() -> Optional[Dict[str, Any]]:
    """Verify JWT token from request headers"""
    try:
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return None
        
        token = auth_header[7:]  # Remove 'Bearer ' prefix
        # This would use the app's secret key in a real implementation
        return verify_jwt_token(token, 'your-secret-key')
    except Exception as e:
        logger.error(f"JWT verification error: {e}")
        return None

def sanitize_input(data: str, max_length: int = 1000) -> str:
    """Sanitize user input"""
    if not isinstance(data, str):
        return str(data)[:max_length]
    
    # Remove potentially dangerous characters
    sanitized = data.replace('<', '&lt;').replace('>', '&gt;')
    sanitized = sanitized.replace('&', '&amp;').replace('"', '&quot;')
    sanitized = sanitized.replace("'", '&#x27;').replace('/', '&#x2F;')
    
    return sanitized[:max_length]

def generate_secure_filename(original_filename: str) -> str:
    """Generate secure filename"""
    import os
    import re
    
    # Get file extension
    _, ext = os.path.splitext(original_filename)
    
    # Generate random filename
    secure_name = secrets.token_hex(16) + ext.lower()
    
    return secure_name

def rate_limit_key(identifier: str, action: str) -> str:
    """Generate rate limiting key"""
    return f"rate_limit:{action}:{identifier}"

def calculate_hash(data: str, algorithm: str = 'sha256') -> str:
    """Calculate hash of data"""
    try:
        if algorithm == 'sha256':
            return hashlib.sha256(data.encode()).hexdigest()
        elif algorithm == 'md5':
            return hashlib.md5(data.encode()).hexdigest()
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
    except Exception as e:
        logger.error(f"Hash calculation error: {e}")
        raise
