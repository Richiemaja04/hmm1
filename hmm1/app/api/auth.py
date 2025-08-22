"""
Authentication API endpoints
"""
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity
import logging
from datetime import datetime, timezone, timedelta
from werkzeug.security import check_password_hash

from app import db
from app.models.database import User, AuthenticationLog
from app.services.auth_service import AuthenticationService
from app.utils.validators import validate_email, validate_password
from app.utils.security import hash_password, generate_session_id
from app.utils.helpers import get_client_ip, get_user_agent

logger = logging.getLogger(__name__)
auth_bp = Blueprint('auth', __name__)
auth_service = AuthenticationService()

@auth_bp.route('/register', methods=['POST'])
def register():
    """Register a new user"""
    try:
        data = request.get_json()
        
        # Validate input
        username = data.get('username', '').strip()
        email = data.get('email', '').strip()
        password = data.get('password', '')
        
        if not username or len(username) < 3:
            return jsonify({'error': 'Username must be at least 3 characters long'}), 400
        
        if not validate_email(email):
            return jsonify({'error': 'Invalid email format'}), 400
        
        if not validate_password(password):
            return jsonify({'error': 'Password must be at least 8 characters with uppercase, lowercase, and number'}), 400
        
        # Check if user already exists
        existing_user = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()
        
        if existing_user:
            return jsonify({'error': 'Username or email already exists'}), 409
        
        # Create new user
        user = User(
            username=username,
            email=email
        )
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        # Log registration
        auth_log = AuthenticationLog(
            user_id=user.id,
            event_type='registration',
            event_status='success',
            ip_address=get_client_ip(request),
            user_agent=get_user_agent(request),
            username_attempted=username
        )
        db.session.add(auth_log)
        db.session.commit()
        
        logger.info(f"New user registered: {username}")
        
        return jsonify({
            'message': 'User registered successfully',
            'user_id': user.id,
            'requires_calibration': True
        }), 201
        
    except Exception as e:
        logger.error(f"Registration error: {e}")
        db.session.rollback()
        return jsonify({'error': 'Registration failed'}), 500

@auth_bp.route('/login', methods=['POST'])
def login():
    """Authenticate user and create session"""
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400
        
        # Find user
        user = User.query.filter(
            (User.username == username) | (User.email == username)
        ).first()
        
        ip_address = get_client_ip(request)
        user_agent = get_user_agent(request)
        
        # Log attempt
        auth_log = AuthenticationLog(
            user_id=user.id if user else None,
            event_type='login',
            event_status='pending',
            ip_address=ip_address,
            user_agent=user_agent,
            username_attempted=username
        )
        
        if not user:
            auth_log.event_status = 'failure'
            auth_log.metadata_data = {'error': 'user_not_found'}
            db.session.add(auth_log)
            db.session.commit()
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Check if account is locked
        if user.is_locked():
            auth_log.event_status = 'failure'
            auth_log.metadata_data = {'error': 'account_locked'}
            db.session.add(auth_log)
            db.session.commit()
            return jsonify({'error': 'Account temporarily locked'}), 423
        
        # Verify password
        if not user.check_password(password):
            user.increment_failed_attempts()
            auth_log.event_status = 'failure'
            auth_log.metadata_data = {'error': 'invalid_password'}
            db.session.add(auth_log)
            db.session.commit()
            
            remaining_attempts = 5 - user.failed_login_attempts
            return jsonify({
                'error': 'Invalid credentials',
                'remaining_attempts': max(remaining_attempts, 0)
            }), 401
        
        # Successful authentication
        user.reset_failed_attempts()
        session_id = generate_session_id()
        
        # Create JWT tokens
        access_token = create_access_token(
            identity=user.id,
            additional_claims={'session_id': session_id}
        )
        refresh_token = create_refresh_token(identity=user.id)
        
        # Update auth log
        auth_log.event_status = 'success'
        auth_log.session_id = session_id
        auth_log.user_id = user.id
        
        db.session.add(auth_log)
        db.session.commit()
        
        logger.info(f"User {username} logged in successfully")
        
        response_data = {
            'message': 'Login successful',
            'access_token': access_token,
            'refresh_token': refresh_token,
            'user': user.to_dict(),
            'session_id': session_id,
            'requires_calibration': not user.is_calibrated
        }
        
        # Redirect path based on calibration status
        if user.is_calibrated:
            response_data['redirect'] = '/dashboard'
        else:
            response_data['redirect'] = '/calibration'
        
        return jsonify(response_data), 200
        
    except Exception as e:
        logger.error(f"Login error: {e}")
        db.session.rollback()
        return jsonify({'error': 'Login failed'}), 500

@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    """Logout user and invalidate session"""
    try:
        user_id = get_jwt_identity()
        
        # Log logout
        auth_log = AuthenticationLog(
            user_id=user_id,
            event_type='logout',
            event_status='success',
            ip_address=get_client_ip(request),
            user_agent=get_user_agent(request)
        )
        db.session.add(auth_log)
        db.session.commit()
        
        logger.info(f"User {user_id} logged out")
        
        return jsonify({'message': 'Logout successful'}), 200
        
    except Exception as e:
        logger.error(f"Logout error: {e}")
        return jsonify({'error': 'Logout failed'}), 500

@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    """Refresh access token"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user or not user.is_active:
            return jsonify({'error': 'User not found or inactive'}), 404
        
        # Create new access token
        new_session_id = generate_session_id()
        access_token = create_access_token(
            identity=user_id,
            additional_claims={'session_id': new_session_id}
        )
        
        return jsonify({
            'access_token': access_token,
            'session_id': new_session_id
        }), 200
        
    except Exception as e:
        logger.error(f"Token refresh error: {e}")
        return jsonify({'error': 'Token refresh failed'}), 500

@auth_bp.route('/verify', methods=['GET'])
@jwt_required()
def verify_token():
    """Verify current token and return user info"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user or not user.is_active:
            return jsonify({'error': 'User not found or inactive'}), 404
        
        return jsonify({
            'valid': True,
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        logger.error(f"Token verification error: {e}")
        return jsonify({'error': 'Token verification failed'}), 500
