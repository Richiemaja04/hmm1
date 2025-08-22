# ==========================================
# app/utils/helpers.py
"""
General helper utilities
"""
import re
import json
import logging
from typing import Any, Dict, List, Optional, Union
from datetime import datetime, timezone
from flask import request
from user_agents import parse as parse_user_agent

logger = logging.getLogger(__name__)

def get_client_ip(request_obj) -> str:
    """Get client IP address from request"""
    try:
        # Check for X-Forwarded-For header (proxy/load balancer)
        if request_obj.headers.get('X-Forwarded-For'):
            return request_obj.headers.get('X-Forwarded-For').split(',')[0].strip()
        
        # Check for X-Real-IP header
        if request_obj.headers.get('X-Real-IP'):
            return request_obj.headers.get('X-Real-IP')
        
        # Fall back to remote address
        return request_obj.remote_addr or 'unknown'
    except Exception as e:
        logger.error(f"Error getting client IP: {e}")
        return 'unknown'

def get_user_agent(request_obj) -> str:
    """Get user agent string from request"""
    try:
        return request_obj.headers.get('User-Agent', 'unknown')
    except Exception as e:
        logger.error(f"Error getting user agent: {e}")
        return 'unknown'

def parse_user_agent_details(user_agent_string: str) -> Dict[str, Any]:
    """Parse user agent string into components"""
    try:
        user_agent = parse_user_agent(user_agent_string)
        
        return {
            'browser': str(user_agent.browser.family),
            'browser_version': str(user_agent.browser.version_string),
            'os': str(user_agent.os.family),
            'os_version': str(user_agent.os.version_string),
            'device': str(user_agent.device.family),
            'is_mobile': user_agent.is_mobile,
            'is_tablet': user_agent.is_tablet,
            'is_pc': user_agent.is_pc,
            'is_bot': user_agent.is_bot
        }
    except Exception as e:
        logger.error(f"User agent parsing error: {e}")
        return {
            'browser': 'unknown',
            'browser_version': 'unknown',
            'os': 'unknown',
            'os_version': 'unknown',
            'device': 'unknown',
            'is_mobile': False,
            'is_tablet': False,
            'is_pc': True,
            'is_bot': False
        }

def format_datetime(dt: datetime, format_str: str = '%Y-%m-%d %H:%M:%S UTC') -> str:
    """Format datetime object"""
    try:
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.strftime(format_str)
    except Exception as e:
        logger.error(f"Datetime formatting error: {e}")
        return 'unknown'

def parse_datetime(dt_string: str) -> Optional[datetime]:
    """Parse datetime string"""
    try:
        # Try ISO format first
        return datetime.fromisoformat(dt_string.replace('Z', '+00:00'))
    except:
        try:
            # Try common formats
            formats = [
                '%Y-%m-%d %H:%M:%S',
                '%Y-%m-%d %H:%M:%S.%f',
                '%Y-%m-%dT%H:%M:%S',
                '%Y-%m-%dT%H:%M:%S.%f'
            ]
            
            for fmt in formats:
                try:
                    return datetime.strptime(dt_string, fmt)
                except ValueError:
                    continue
            
            return None
        except Exception as e:
            logger.error(f"Datetime parsing error: {e}")
            return None

def safe_json_loads(json_string: str, default: Any = None) -> Any:
    """Safely parse JSON string"""
    try:
        if not json_string:
            return default
        return json.loads(json_string)
    except (json.JSONDecodeError, TypeError) as e:
        logger.warning(f"JSON parsing error: {e}")
        return default

def safe_json_dumps(data: Any, default: str = '{}') -> str:
    """Safely serialize data to JSON"""
    try:
        return json.dumps(data, default=str, ensure_ascii=False)
    except (TypeError, ValueError) as e:
        logger.warning(f"JSON serialization error: {e}")
        return default

def normalize_email(email: str) -> str:
    """Normalize email address"""
    try:
        return email.lower().strip()
    except Exception as e:
        logger.error(f"Email normalization error: {e}")
        return email

def generate_random_string(length: int = 8, include_numbers: bool = True, 
                          include_symbols: bool = False) -> str:
    """Generate random string"""
    import string
    import random
    
    chars = string.ascii_letters
    if include_numbers:
        chars += string.digits
    if include_symbols:
        chars += '!@#$%^&*'
    
    return ''.join(random.choice(chars) for _ in range(length))

def truncate_string(text: str, max_length: int = 100, suffix: str = '...') -> str:
    """Truncate string to maximum length"""
    if len(text) <= max_length:
        return text
    return text[:max_length - len(suffix)] + suffix

def calculate_file_hash(file_path: str, algorithm: str = 'sha256') -> str:
    """Calculate hash of file"""
    import hashlib
    
    hash_obj = getattr(hashlib, algorithm)()
    
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()
    except Exception as e:
        logger.error(f"File hash calculation error: {e}")
        raise

def bytes_to_human_readable(bytes_value: int) -> str:
    """Convert bytes to human readable format"""
    try:
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.1f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.1f} PB"
    except Exception as e:
        logger.error(f"Bytes conversion error: {e}")
        return f"{bytes_value} B"

def clean_string(text: str, remove_extra_whitespace: bool = True) -> str:
    """Clean and normalize string"""
    try:
        # Remove null bytes
        text = text.replace('\x00', '')
        
        # Remove extra whitespace
        if remove_extra_whitespace:
            text = ' '.join(text.split())
        
        return text.strip()
    except Exception as e:
        logger.error(f"String cleaning error: {e}")
        return text

def is_valid_uuid(uuid_string: str) -> bool:
    """Check if string is valid UUID"""
    try:
        import uuid
        uuid.UUID(uuid_string)
        return True
    except (ValueError, TypeError):
        return False

def paginate_results(results: List[Any], page: int = 1, per_page: int = 20) -> Dict[str, Any]:
    """Paginate list of results"""
    try:
        total = len(results)
        start = (page - 1) * per_page
        end = start + per_page
        
        items = results[start:end]
        
        return {
            'items': items,
            'total': total,
            'page': page,
            'per_page': per_page,
            'pages': (total + per_page - 1) // per_page,
            'has_prev': page > 1,
            'has_next': end < total
        }
    except Exception as e:
        logger.error(f"Pagination error: {e}")
        return {
            'items': [],
            'total': 0,
            'page': 1,
            'per_page': per_page,
            'pages': 0,
            'has_prev': False,
            'has_next': False
        }