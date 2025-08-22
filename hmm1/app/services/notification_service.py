# ==========================================
# app/services/notification_service.py
"""
Notification service for security alerts and user communications
"""
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
from enum import Enum

logger = logging.getLogger(__name__)

class NotificationType(Enum):
    SECURITY_ALERT = "security_alert"
    CHALLENGE_REQUIRED = "challenge_required"
    DRIFT_DETECTED = "drift_detected"
    TRAINING_COMPLETE = "training_complete"
    SESSION_WARNING = "session_warning"
    ACCOUNT_LOCKED = "account_locked"

class NotificationService:
    """Service for handling notifications and alerts"""
    
    def __init__(self):
        self.notification_queue = []
        self.user_preferences = {}
        
    def send_security_alert(self, user_id: int, alert_type: str, 
                          details: Dict[str, Any]) -> bool:
        """Send security alert to user"""
        try:
            notification = {
                'type': NotificationType.SECURITY_ALERT.value,
                'user_id': user_id,
                'alert_type': alert_type,
                'details': details,
                'timestamp': datetime.now(timezone.utc),
                'priority': self._determine_priority(alert_type, details),
                'channels': self._determine_channels(user_id, alert_type)
            }
            
            # Add to queue for processing
            self.notification_queue.append(notification)
            
            # Process immediately for high priority
            if notification['priority'] == 'high':
                self._process_notification(notification)
            
            logger.info(f"Security alert queued for user {user_id}: {alert_type}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send security alert: {e}")
            return False
    
    def send_challenge_notification(self, user_id: int, challenge_type: str,
                                  reason: str) -> bool:
        """Send challenge requirement notification"""
        try:
            notification = {
                'type': NotificationType.CHALLENGE_REQUIRED.value,
                'user_id': user_id,
                'challenge_type': challenge_type,
                'reason': reason,
                'timestamp': datetime.now(timezone.utc),
                'priority': 'medium',
                'channels': ['websocket', 'ui']
            }
            
            self._process_notification(notification)
            
            logger.info(f"Challenge notification sent to user {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send challenge notification: {e}")
            return False
    
    def send_drift_notification(self, user_id: int, drift_details: Dict[str, Any]) -> bool:
        """Send behavioral drift notification"""
        try:
            notification = {
                'type': NotificationType.DRIFT_DETECTED.value,
                'user_id': user_id,
                'drift_details': drift_details,
                'timestamp': datetime.now(timezone.utc),
                'priority': 'low',
                'channels': ['ui']
            }
            
            self._process_notification(notification)
            
            logger.info(f"Drift notification sent to user {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send drift notification: {e}")
            return False
    
    def send_training_complete_notification(self, user_id: int, 
                                          training_results: Dict[str, Any]) -> bool:
        """Send training completion notification"""
        try:
            notification = {
                'type': NotificationType.TRAINING_COMPLETE.value,
                'user_id': user_id,
                'training_results': training_results,
                'timestamp': datetime.now(timezone.utc),
                'priority': 'medium',
                'channels': ['websocket', 'ui']
            }
            
            self._process_notification(notification)
            
            logger.info(f"Training complete notification sent to user {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send training notification: {e}")
            return False
    
    def _determine_priority(self, alert_type: str, details: Dict[str, Any]) -> str:
        """Determine notification priority"""
        high_priority_alerts = [
            'session_security_action',
            'critical_anomaly',
            'account_locked'
        ]
        
        if alert_type in high_priority_alerts:
            return 'high'
        
        # Check risk level in details
        risk_level = details.get('risk_level', 'low')
        if risk_level in ['high', 'critical']:
            return 'high'
        elif risk_level == 'medium':
            return 'medium'
        else:
            return 'low'
    
    def _determine_channels(self, user_id: int, alert_type: str) -> List[str]:
        """Determine notification channels based on user preferences and alert type"""
        # Default channels
        channels = ['ui']
        
        # Add WebSocket for real-time alerts
        if alert_type in ['high_risk_anomaly', 'session_security_action']:
            channels.append('websocket')
        
        # In production, check user preferences
        user_prefs = self.user_preferences.get(user_id, {})
        if user_prefs.get('email_alerts', False):
            channels.append('email')
        
        return channels
    
    def _process_notification(self, notification: Dict[str, Any]) -> None:
        """Process and send notification through appropriate channels"""
        try:
            channels = notification['channels']
            
            if 'websocket' in channels:
                self._send_websocket_notification(notification)
            
            if 'ui' in channels:
                self._send_ui_notification(notification)
            
            if 'email' in channels:
                self._send_email_notification(notification)
            
        except Exception as e:
            logger.error(f"Notification processing error: {e}")
    
    def _send_websocket_notification(self, notification: Dict[str, Any]) -> None:
        """Send notification via WebSocket"""
        try:
            from app.api.websockets import send_notification_to_user
            
            send_notification_to_user(
                user_id=notification['user_id'],
                notification_type=notification['type'],
                data=notification
            )
            
        except Exception as e:
            logger.error(f"WebSocket notification error: {e}")
    
    def _send_ui_notification(self, notification: Dict[str, Any]) -> None:
        """Send notification to UI (stored for later retrieval)"""
        try:
            # In production, store in database or cache
            logger.debug(f"UI notification stored for user {notification['user_id']}")
            
        except Exception as e:
            logger.error(f"UI notification error: {e}")
    
    def _send_email_notification(self, notification: Dict[str, Any]) -> None:
        """Send email notification"""
        try:
            # In production, use email service (SendGrid, SES, etc.)
            logger.debug(f"Email notification sent to user {notification['user_id']}")
            
        except Exception as e:
            logger.error(f"Email notification error: {e}")
    
    def get_user_notifications(self, user_id: int, limit: int = 20) -> List[Dict[str, Any]]:
        """Get recent notifications for user"""
        try:
            # In production, query from database
            user_notifications = [
                n for n in self.notification_queue[-100:]  # Last 100 notifications
                if n.get('user_id') == user_id
            ]
            
            # Sort by timestamp (newest first) and limit
            user_notifications.sort(key=lambda x: x['timestamp'], reverse=True)
            return user_notifications[:limit]
            
        except Exception as e:
            logger.error(f"Failed to get user notifications: {e}")
            return []
    
    def mark_notification_read(self, user_id: int, notification_id: str) -> bool:
        """Mark notification as read"""
        try:
            # In production, update database
            logger.debug(f"Notification {notification_id} marked as read for user {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to mark notification as read: {e}")
            return False