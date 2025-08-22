# ==========================================
# app/services/monitoring_service.py
"""
Real-time behavioral monitoring service
"""
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone, timedelta
import numpy as np

from app import db
from app.models.database import User, BehavioralData, AuthenticationLog
from app.core.feature_extractor import BehavioralFeatureExtractor
from app.core.anomaly_detector import BehavioralAnomalyDetector, AnomalyDetectionResult
from app.core.drift_detector import BehavioralDriftDetector, DriftDetectionResult
from app.core.security_manager import SecurityManager, SecurityAssessment
from app.services.notification_service import NotificationService
from app.utils.helpers import generate_session_id

logger = logging.getLogger(__name__)

class MonitoringService:
    """Service for real-time behavioral monitoring"""
    
    def __init__(self):
        self.feature_extractor = BehavioralFeatureExtractor()
        self.anomaly_detector = BehavioralAnomalyDetector({
            'low_risk_threshold': 0.3,
            'medium_risk_threshold': 0.6,
            'high_risk_threshold': 0.8,
            'min_data_quality': 0.5
        })
        self.drift_detector = BehavioralDriftDetector({
            'drift_window_size': 100,
            'significance_level': 0.05
        })
        self.security_manager = SecurityManager({
            'session_timeout': 3600,
            'max_failed_challenges': 3
        })
        self.notification_service = NotificationService()
        
        # Monitoring state
        self.user_monitoring_state = {}
        
    def initialize_user_monitoring(self, user_id: int) -> bool:
        """Initialize monitoring for a user"""
        try:
            user = User.query.get(user_id)
            if not user or not user.is_calibrated:
                logger.warning(f"Cannot initialize monitoring for user {user_id}: not calibrated")
                return False
            
            # Load user baseline data
            baseline_data = {
                'keystroke_baseline': user.keystroke_baseline_data,
                'mouse_baseline': user.mouse_baseline_data
            }
            
            # Initialize anomaly detector with user baseline
            success = self.anomaly_detector.load_user_baseline(user_id, baseline_data)
            if not success:
                logger.error(f"Failed to load baseline for user {user_id}")
                return False
            
            # Initialize monitoring state
            self.user_monitoring_state[user_id] = {
                'initialized_at': datetime.now(timezone.utc),
                'data_windows_processed': 0,
                'last_analysis_time': None,
                'recent_features': [],
                'anomaly_history': [],
                'drift_history': []
            }
            
            logger.info(f"Monitoring initialized for user {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize monitoring for user {user_id}: {e}")
            return False
    
    def process_behavioral_data(self, user_id: int, session_id: str,
                              keystroke_events: List[Dict], mouse_events: List[Dict],
                              window_duration: float = 30.0) -> Dict[str, Any]:
        """Process incoming behavioral data window"""
        try:
            # Ensure monitoring is initialized
            if user_id not in self.user_monitoring_state:
                if not self.initialize_user_monitoring(user_id):
                    return self._create_error_response("Monitoring not initialized")
            
            # Extract features
            keystroke_features = self.feature_extractor.extract_keystroke_features(keystroke_events)
            mouse_features = self.feature_extractor.extract_mouse_features(mouse_events)
            
            # Store behavioral data
            behavioral_data = BehavioralData(
                user_id=user_id,
                session_id=session_id,
                data_type='monitoring',
                window_duration=window_duration,
                keystroke_events_data=keystroke_events,
                mouse_events_data=mouse_events,
                keystroke_features_data=keystroke_features,
                mouse_features_data=mouse_features
            )
            
            # Perform anomaly detection
            anomaly_result = self.anomaly_detector.analyze_behavioral_data(
                user_id=user_id,
                session_id=session_id,
                keystroke_events=keystroke_events,
                mouse_events=mouse_events
            )
            
            # Update behavioral data with anomaly results
            behavioral_data.anomaly_score = anomaly_result.anomaly_score
            behavioral_data.risk_level = anomaly_result.risk_level.value
            behavioral_data.model_predictions = anomaly_result.model_predictions
            
            db.session.add(behavioral_data)
            
            # Update monitoring state
            state = self.user_monitoring_state[user_id]
            state['data_windows_processed'] += 1
            state['last_analysis_time'] = datetime.now(timezone.utc)
            
            # Add to recent features for drift detection
            all_features = {**keystroke_features, **mouse_features}
            state['recent_features'].append(all_features)
            
            # Keep only recent features (last 50 windows)
            if len(state['recent_features']) > 50:
                state['recent_features'] = state['recent_features'][-50:]
            
            # Perform drift detection if enough data
            drift_result = None
            if len(state['recent_features']) >= 20:
                drift_result = self.drift_detector.detect_drift(
                    user_id=user_id,
                    recent_features=state['recent_features'][-10:],
                    analysis_timestamp=datetime.now(timezone.utc)
                )
                
                # Update drift history
                state['drift_history'].append(drift_result)
                if len(state['drift_history']) > 10:
                    state['drift_history'] = state['drift_history'][-10:]
            
            # Perform security assessment
            context_data = {
                'timestamp': datetime.now(timezone.utc),
                'session_info': {'start_time': datetime.now(timezone.utc) - timedelta(hours=1)}
            }
            
            security_assessment = self.security_manager.assess_security(
                user_id=user_id,
                session_id=session_id,
                anomaly_result=anomaly_result,
                drift_result=drift_result,
                context_data=context_data
            )
            
            # Update user risk score
            user = User.query.get(user_id)
            user.current_risk_score = security_assessment.risk_score
            user.last_activity = datetime.now(timezone.utc)
            
            # Create response
            response = self._create_monitoring_response(
                anomaly_result, drift_result, security_assessment
            )
            
            # Handle notifications and alerts
            self._handle_monitoring_alerts(user_id, anomaly_result, security_assessment)
            
            # Log significant events
            if anomaly_result.is_anomaly or security_assessment.recommended_action.value != 'allow':
                auth_log = AuthenticationLog(
                    user_id=user_id,
                    session_id=session_id,
                    event_type='monitoring',
                    event_status='anomaly_detected' if anomaly_result.is_anomaly else 'normal',
                    risk_score=security_assessment.risk_score,
                    anomaly_type=anomaly_result.anomaly_type.value,
                    confidence_score=security_assessment.confidence,
                    action_taken=security_assessment.recommended_action.value
                )
                db.session.add(auth_log)
            
            db.session.commit()
            
            logger.debug(f"Behavioral data processed for user {user_id}: "
                        f"{security_assessment.threat_level.value} threat")
            
            return response
            
        except Exception as e:
            logger.error(f"Behavioral data processing error: {e}")
            db.session.rollback()
            return self._create_error_response("Processing failed")
    
    def get_real_time_analytics(self, user_id: int) -> Dict[str, Any]:
        """Get real-time analytics for user dashboard"""
        try:
            # Get recent behavioral data
            recent_data = BehavioralData.query.filter(
                BehavioralData.user_id == user_id,
                BehavioralData.timestamp >= datetime.now(timezone.utc) - timedelta(hours=24)
            ).order_by(BehavioralData.timestamp.desc()).limit(50).all()
            
            if not recent_data:
                return self._create_empty_analytics()
            
            # Calculate analytics
            analytics = {
                'current_session': self._analyze_current_session(user_id),
                'typing_pattern': self._analyze_typing_pattern(recent_data),
                'mouse_pattern': self._analyze_mouse_pattern(recent_data),
                'risk_trend': self._analyze_risk_trend(recent_data),
                'anomaly_summary': self._summarize_anomalies(recent_data)
            }
            
            return analytics
            
        except Exception as e:
            logger.error(f"Analytics generation error: {e}")
            return self._create_empty_analytics()
    
    def get_monitoring_status(self, user_id: int) -> Dict[str, Any]:
        """Get current monitoring status for user"""
        try:
            state = self.user_monitoring_state.get(user_id)
            user = User.query.get(user_id)
            
            if not state or not user:
                return {
                    'monitoring_active': False,
                    'message': 'Monitoring not initialized'
                }
            
            return {
                'monitoring_active': True,
                'initialized_at': state['initialized_at'].isoformat(),
                'data_windows_processed': state['data_windows_processed'],
                'last_analysis': state['last_analysis_time'].isoformat() if state['last_analysis_time'] else None,
                'current_risk_score': user.current_risk_score,
                'calibration_status': 'complete' if user.is_calibrated else 'required'
            }
            
        except Exception as e:
            logger.error(f"Monitoring status error: {e}")
            return {'monitoring_active': False, 'error': str(e)}
    
    def _create_monitoring_response(self, anomaly_result: AnomalyDetectionResult,
                                  drift_result: Optional[DriftDetectionResult],
                                  security_assessment: SecurityAssessment) -> Dict[str, Any]:
        """Create response from monitoring analysis"""
        response = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'anomaly_score': anomaly_result.anomaly_score,
            'confidence': anomaly_result.confidence,
            'risk_level': anomaly_result.risk_level.value,
            'threat_level': security_assessment.threat_level.value,
            'action_required': security_assessment.recommended_action.value,
            'is_anomaly': anomaly_result.is_anomaly,
            'data_quality': anomaly_result.data_quality
        }
        
        # Add challenge information if needed
        if security_assessment.recommended_action.value in ['challenge', 'restrict']:
            response['challenge_type'] = security_assessment.action_details.get('challenge_type', 'verification')
            response['challenge_reason'] = security_assessment.action_details.get('reason', 'security_check')
        
        # Add drift information if available
        if drift_result:
            response['drift_detected'] = drift_result.drift_detected
            response['drift_severity'] = drift_result.drift_severity.value
            response['retraining_required'] = drift_result.retraining_required
        
        return response
    
    def _handle_monitoring_alerts(self, user_id: int, anomaly_result: AnomalyDetectionResult,
                                security_assessment: SecurityAssessment) -> None:
        """Handle alerts and notifications from monitoring"""
        try:
            # High-risk anomaly alert
            if anomaly_result.risk_level.value in ['high', 'critical']:
                self.notification_service.send_security_alert(
                    user_id=user_id,
                    alert_type='high_risk_anomaly',
                    details={
                        'risk_level': anomaly_result.risk_level.value,
                        'anomaly_score': anomaly_result.anomaly_score,
                        'confidence': anomaly_result.confidence
                    }
                )
            
            # Security action alert
            if security_assessment.recommended_action.value in ['block', 'logout']:
                self.notification_service.send_security_alert(
                    user_id=user_id,
                    alert_type='session_security_action',
                    details={
                        'action': security_assessment.recommended_action.value,
                        'threat_level': security_assessment.threat_level.value,
                        'risk_score': security_assessment.risk_score
                    }
                )
            
        except Exception as e:
            logger.error(f"Alert handling error: {e}")
    
    def _analyze_current_session(self, user_id: int) -> Dict[str, Any]:
        """Analyze current session metrics"""
        state = self.user_monitoring_state.get(user_id, {})
        
        return {
            'windows_processed': state.get('data_windows_processed', 0),
            'session_duration': self._calculate_session_duration(state),
            'last_activity': state.get('last_analysis_time', datetime.now(timezone.utc)).isoformat()
        }
    
    def _analyze_typing_pattern(self, recent_data: List[BehavioralData]) -> Dict[str, Any]:
        """Analyze typing pattern from recent data"""
        typing_speeds = []
        rhythm_scores = []
        
        for data in recent_data:
            features = data.keystroke_features_data
            if features:
                typing_speeds.append(features.get('typing_speed_wpm', 0))
                rhythm_scores.append(features.get('session_typing_rhythm', 0))
        
        return {
            'average_speed': np.mean(typing_speeds) if typing_speeds else 0,
            'speed_variance': np.var(typing_speeds) if len(typing_speeds) > 1 else 0,
            'rhythm_consistency': np.mean(rhythm_scores) if rhythm_scores else 0
        }
    
    def _analyze_mouse_pattern(self, recent_data: List[BehavioralData]) -> Dict[str, Any]:
        """Analyze mouse pattern from recent data"""
        mouse_speeds = []
        click_rates = []
        
        for data in recent_data:
            features = data.mouse_features_data
            if features:
                mouse_speeds.append(features.get('avg_mouse_speed', 0))
                click_rates.append(features.get('click_rate', 0))
        
        return {
            'average_speed': np.mean(mouse_speeds) if mouse_speeds else 0,
            'speed_variance': np.var(mouse_speeds) if len(mouse_speeds) > 1 else 0,
            'click_frequency': np.mean(click_rates) if click_rates else 0
        }
    
    def _analyze_risk_trend(self, recent_data: List[BehavioralData]) -> Dict[str, Any]:
        """Analyze risk score trend"""
        risk_scores = [data.anomaly_score for data in recent_data if data.anomaly_score is not None]
        
        if not risk_scores:
            return {'trend': 'stable', 'current': 0.0, 'change': 0.0}
        
        current_risk = risk_scores[-1]
        previous_risk = np.mean(risk_scores[:-5]) if len(risk_scores) > 5 else risk_scores[0]
        change = current_risk - previous_risk
        
        if change > 0.1:
            trend = 'increasing'
        elif change < -0.1:
            trend = 'decreasing'
        else:
            trend = 'stable'
        
        return {
            'trend': trend,
            'current': current_risk,
            'change': change
        }
    
    def _summarize_anomalies(self, recent_data: List[BehavioralData]) -> Dict[str, Any]:
        """Summarize anomaly detection results"""
        total_windows = len(recent_data)
        anomaly_windows = sum(1 for data in recent_data 
                            if data.risk_level in ['medium', 'high', 'critical'])
        
        risk_distribution = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
        for data in recent_data:
            risk_level = data.risk_level or 'low'
            if risk_level in risk_distribution:
                risk_distribution[risk_level] += 1
        
        return {
            'total_windows': total_windows,
            'anomaly_windows': anomaly_windows,
            'anomaly_rate': anomaly_windows / total_windows if total_windows > 0 else 0,
            'risk_distribution': risk_distribution
        }
    
    def _calculate_session_duration(self, state: Dict[str, Any]) -> int:
        """Calculate session duration in seconds"""
        if 'initialized_at' not in state:
            return 0
        
        duration = datetime.now(timezone.utc) - state['initialized_at']
        return int(duration.total_seconds())
    
    def _create_error_response(self, message: str) -> Dict[str, Any]:
        """Create error response"""
        return {
            'error': True,
            'message': message,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'risk_level': 'medium',
            'action_required': 'monitor'
        }
    
    def _create_empty_analytics(self) -> Dict[str, Any]:
        """Create empty analytics response"""
        return {
            'current_session': {'windows_processed': 0, 'session_duration': 0},
            'typing_pattern': {'average_speed': 0, 'speed_variance': 0},
            'mouse_pattern': {'average_speed': 0, 'click_frequency': 0},
            'risk_trend': {'trend': 'stable', 'current': 0.0},
            'anomaly_summary': {'total_windows': 0, 'anomaly_rate': 0}
        }