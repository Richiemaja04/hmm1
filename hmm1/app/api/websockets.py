# app/api/websockets.py
"""
WebSocket handlers for real-time communication
"""
from flask_socketio import emit, join_room, leave_room, disconnect
from flask_jwt_extended import decode_token, get_jwt_identity
import logging
from datetime import datetime, timezone
import json

from app import socketio, db
from app.models.database import User, BehavioralData
from app.services.monitoring_service import MonitoringService
from app.core.feature_extractor import BehavioralFeatureExtractor
from app.utils.validators import validate_behavioral_data
from app.utils.security import verify_jwt_in_request

logger = logging.getLogger(__name__)
monitoring_service = MonitoringService()
feature_extractor = BehavioralFeatureExtractor()

# Store active connections
active_connections = {}

def register_websocket_handlers(socketio_instance):
    """Register all WebSocket event handlers"""
    
    @socketio_instance.on('connect')
    def handle_connect(auth):
        """Handle client connection"""
        try:
            # Verify JWT token
            if not auth or 'token' not in auth:
                logger.warning("WebSocket connection rejected: No token provided")
                disconnect()
                return False
            
            try:
                # Decode JWT token
                token_data = decode_token(auth['token'])
                user_id = token_data['sub']
                session_id = token_data.get('session_id')
                
                if not user_id:
                    disconnect()
                    return False
                
                # Verify user exists and is active
                user = User.query.get(user_id)
                if not user or not user.is_active:
                    disconnect()
                    return False
                
                # Join user-specific room
                join_room(f"user_{user_id}")
                
                # Store connection info
                active_connections[request.sid] = {
                    'user_id': user_id,
                    'session_id': session_id,
                    'connected_at': datetime.now(timezone.utc),
                    'last_activity': datetime.now(timezone.utc)
                }
                
                logger.info(f"WebSocket connection established for user {user_id}")
                
                # Send connection confirmation
                emit('connection_established', {
                    'user_id': user_id,
                    'session_id': session_id,
                    'monitoring_active': user.is_calibrated,
                    'timestamp': datetime.now(timezone.utc).isoformat()
                })
                
                return True
                
            except Exception as e:
                logger.error(f"JWT verification failed: {e}")
                disconnect()
                return False
                
        except Exception as e:
            logger.error(f"WebSocket connection error: {e}")
            disconnect()
            return False
    
    @socketio_instance.on('disconnect')
    def handle_disconnect():
        """Handle client disconnection"""
        try:
            if request.sid in active_connections:
                connection_info = active_connections[request.sid]
                user_id = connection_info['user_id']
                
                # Leave user room
                leave_room(f"user_{user_id}")
                
                # Remove from active connections
                del active_connections[request.sid]
                
                logger.info(f"WebSocket disconnected for user {user_id}")
        except Exception as e:
            logger.error(f"WebSocket disconnect error: {e}")
    
    @socketio_instance.on('behavioral_data')
    def handle_behavioral_data(data):
        """Handle incoming behavioral data from client"""
        try:
            if request.sid not in active_connections:
                logger.warning("Behavioral data received from unregistered connection")
                return
            
            connection_info = active_connections[request.sid]
            user_id = connection_info['user_id']
            session_id = connection_info['session_id']
            
            # Update last activity
            connection_info['last_activity'] = datetime.now(timezone.utc)
            
            # Validate data structure
            keystroke_events = data.get('keystroke_events', [])
            mouse_events = data.get('mouse_events', [])
            window_duration = data.get('window_duration', 30.0)
            
            if not validate_behavioral_data(keystroke_events, mouse_events):
                emit('data_validation_error', {'message': 'Invalid behavioral data format'})
                return
            
            # Process with monitoring service
            result = monitoring_service.process_behavioral_data(
                user_id=user_id,
                session_id=session_id,
                keystroke_events=keystroke_events,
                mouse_events=mouse_events,
                window_duration=window_duration
            )
            
            # Send analysis result back to client
            emit('analysis_result', {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'risk_level': result.get('risk_level', 'low'),
                'anomaly_score': result.get('anomaly_score', 0.0),
                'confidence': result.get('confidence', 0.0),
                'action_required': result.get('action_required', 'continue_monitoring')
            })
            
            # Handle high-risk scenarios
            if result.get('action_required') == 'challenge_verification':
                emit('challenge_required', {
                    'challenge_type': result.get('challenge_type', 'verification'),
                    'reason': 'behavioral_anomaly_detected',
                    'redirect_url': '/challenge'
                })
            
            elif result.get('action_required') == 'block_session':
                emit('session_blocked', {
                    'reason': 'critical_security_threat',
                    'message': 'Session terminated due to security concerns'
                })
                disconnect()
            
            logger.debug(f"Behavioral data processed for user {user_id}")
            
        except Exception as e:
            logger.error(f"Behavioral data processing error: {e}")
            emit('processing_error', {'message': 'Failed to process behavioral data'})
    
    @socketio_instance.on('ping')
    def handle_ping():
        """Handle ping for connection health check"""
        try:
            if request.sid in active_connections:
                connection_info = active_connections[request.sid]
                connection_info['last_activity'] = datetime.now(timezone.utc)
                emit('pong', {'timestamp': datetime.now(timezone.utc).isoformat()})
        except Exception as e:
            logger.error(f"Ping handler error: {e}")
    
    @socketio_instance.on('request_analytics')
    def handle_analytics_request(data):
        """Handle request for real-time analytics"""
        try:
            if request.sid not in active_connections:
                return
            
            connection_info = active_connections[request.sid]
            user_id = connection_info['user_id']
            
            # Get analytics data
            analytics = monitoring_service.get_real_time_analytics(user_id)
            
            emit('analytics_update', analytics)
            
        except Exception as e:
            logger.error(f"Analytics request error: {e}")

# Utility functions for WebSocket management
def send_notification_to_user(user_id, notification_type, data):
    """Send notification to specific user via WebSocket"""
    try:
        socketio.emit('notification', {
            'type': notification_type,
            'data': data,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }, room=f"user_{user_id}")
        
        logger.debug(f"Notification sent to user {user_id}: {notification_type}")
        
    except Exception as e:
        logger.error(f"Failed to send notification to user {user_id}: {e}")

def broadcast_security_alert(alert_data):
    """Broadcast security alert to all connected administrators"""
    try:
        socketio.emit('security_alert', {
            'alert': alert_data,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }, room='administrators')
        
        logger.info("Security alert broadcasted")
        
    except Exception as e:
        logger.error(f"Failed to broadcast security alert: {e}")

def get_active_users():
    """Get list of currently active users"""
    active_users = set()
    for connection in active_connections.values():
        active_users.add(connection['user_id'])
    return list(active_users)