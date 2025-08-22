# ==========================================
# app/services/auth_service.py
"""
Authentication service for user management and security
"""
import logging
from typing import Dict, Optional, Tuple, Any
from datetime import datetime, timezone, timedelta
import secrets
import hashlib

from app import db
from app.models.database import User, AuthenticationLog
from app.utils.security import generate_session_id, hash_password
from app.utils.validators import validate_email, validate_password

logger = logging.getLogger(__name__)

class AuthenticationService:
    """Service for handling authentication operations"""
    
    def __init__(self):
        self.max_login_attempts = 5
        self.lockout_duration = timedelta(minutes=30)
        self.session_timeout = timedelta(hours=24)
    
    def authenticate_user(self, username: str, password: str, 
                         context_data: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """Authenticate user with username/password"""
        try:
            # Find user
            user = User.query.filter(
                (User.username == username) | (User.email == username)
            ).first()
            
            auth_result = {
                'success': False,
                'user': None,
                'session_id': None,
                'message': '',
                'requires_calibration': False
            }
            
            # Log authentication attempt
            auth_log = AuthenticationLog(
                user_id=user.id if user else None,
                event_type='login',
                event_status='attempt',
                ip_address=context_data.get('ip_address'),
                user_agent=context_data.get('user_agent'),
                username_attempted=username
            )
            
            if not user:
                auth_log.event_status = 'failure'
                auth_log.metadata_data = {'reason': 'user_not_found'}
                db.session.add(auth_log)
                db.session.commit()
                
                auth_result['message'] = 'Invalid credentials'
                return False, auth_result
            
            # Check if account is locked
            if user.is_locked():
                auth_log.event_status = 'failure'
                auth_log.metadata_data = {'reason': 'account_locked'}
                db.session.add(auth_log)
                db.session.commit()
                
                auth_result['message'] = 'Account temporarily locked'
                return False, auth_result
            
            # Verify password
            if not user.check_password(password):
                user.increment_failed_attempts()
                auth_log.event_status = 'failure'
                auth_log.metadata_data = {'reason': 'invalid_password'}
                db.session.add(auth_log)
                db.session.commit()
                
                remaining = max(0, self.max_login_attempts - user.failed_login_attempts)
                auth_result['message'] = f'Invalid credentials. {remaining} attempts remaining'
                return False, auth_result
            
            # Successful authentication
            user.reset_failed_attempts()
            session_id = generate_session_id()
            
            auth_log.event_status = 'success'
            auth_log.session_id = session_id
            auth_log.user_id = user.id
            db.session.add(auth_log)
            db.session.commit()
            
            auth_result.update({
                'success': True,
                'user': user,
                'session_id': session_id,
                'message': 'Authentication successful',
                'requires_calibration': not user.is_calibrated
            })
            
            logger.info(f"User {username} authenticated successfully")
            return True, auth_result
            
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            db.session.rollback()
            return False, {'success': False, 'message': 'Authentication failed'}
    
    def create_user(self, username: str, email: str, password: str) -> Tuple[bool, Dict[str, Any]]:
        """Create new user account"""
        try:
            # Validate input
            if not validate_email(email):
                return False, {'message': 'Invalid email format'}
            
            if not validate_password(password):
                return False, {'message': 'Password does not meet requirements'}
            
            # Check if user exists
            existing_user = User.query.filter(
                (User.username == username) | (User.email == email)
            ).first()
            
            if existing_user:
                return False, {'message': 'Username or email already exists'}
            
            # Create user
            user = User(
                username=username,
                email=email
            )
            user.set_password(password)
            
            db.session.add(user)
            db.session.commit()
            
            logger.info(f"New user created: {username}")
            
            return True, {
                'user': user,
                'message': 'User created successfully',
                'requires_calibration': True
            }
            
        except Exception as e:
            logger.error(f"User creation error: {e}")
            db.session.rollback()
            return False, {'message': 'Failed to create user'}
    
    def validate_session(self, user_id: int, session_id: str) -> Tuple[bool, Optional[User]]:
        """Validate user session"""
        try:
            user = User.query.get(user_id)
            
            if not user or not user.is_active:
                return False, None
            
            # Check if user is locked
            if user.is_locked():
                return False, None
            
            # In a production system, you would store session info in Redis/database
            # For now, we'll assume session is valid if user exists
            
            # Update last activity
            user.last_activity = datetime.now(timezone.utc)
            db.session.commit()
            
            return True, user
            
        except Exception as e:
            logger.error(f"Session validation error: {e}")
            return False, None
    
    def logout_user(self, user_id: int, session_id: str, context_data: Dict[str, Any]) -> bool:
        """Logout user and invalidate session"""
        try:
            # Log logout
            auth_log = AuthenticationLog(
                user_id=user_id,
                event_type='logout',
                event_status='success',
                ip_address=context_data.get('ip_address'),
                user_agent=context_data.get('user_agent'),
                session_id=session_id
            )
            db.session.add(auth_log)
            db.session.commit()
            
            logger.info(f"User {user_id} logged out")
            return True
            
        except Exception as e:
            logger.error(f"Logout error: {e}")
            return False
    
    def reset_password(self, email: str) -> Tuple[bool, str]:
        """Initiate password reset process"""
        try:
            user = User.query.filter_by(email=email).first()
            
            if not user:
                # Don't reveal if email exists
                return True, 'If the email exists, reset instructions have been sent'
            
            # Generate reset token (in production, this would be stored securely)
            reset_token = secrets.token_urlsafe(32)
            
            # In production, send email with reset link
            logger.info(f"Password reset requested for user {user.username}")
            
            return True, 'Reset instructions have been sent to your email'
            
        except Exception as e:
            logger.error(f"Password reset error: {e}")
            return False, 'Failed to process password reset'
    
    def update_user_security_info(self, user_id: int, security_data: Dict[str, Any]) -> bool:
        """Update user security information"""
        try:
            user = User.query.get(user_id)
            if not user:
                return False
            
            # Update risk score
            if 'risk_score' in security_data:
                user.current_risk_score = security_data['risk_score']
            
            # Update anomaly count
            if 'anomaly_detected' in security_data:
                user.anomaly_count_24h += 1
            
            db.session.commit()
            return True
            
        except Exception as e:
            logger.error(f"Security info update error: {e}")
            return False