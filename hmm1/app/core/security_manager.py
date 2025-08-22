# ==========================================
# app/core/security_manager.py
"""
Security and risk assessment manager for continuous authentication
"""
import hashlib
import secrets
import logging
from typing import Dict, List, Tuple, Optional, Any
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass
from enum import Enum
import json
import ipaddress

from app.core.anomaly_detector import AnomalyDetectionResult, RiskLevel
from app.core.drift_detector import DriftDetectionResult, DriftSeverity

logger = logging.getLogger(__name__)

class ThreatLevel(Enum):
    MINIMAL = "minimal"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"

class SecurityAction(Enum):
    ALLOW = "allow"
    MONITOR = "monitor"
    CHALLENGE = "challenge"
    RESTRICT = "restrict"
    BLOCK = "block"
    LOGOUT = "logout"

@dataclass
class SecurityAssessment:
    """Comprehensive security assessment result"""
    timestamp: datetime
    user_id: int
    session_id: str
    
    # Threat assessment
    threat_level: ThreatLevel
    risk_score: float
    confidence: float
    
    # Contributing factors
    anomaly_contribution: float
    drift_contribution: float
    context_contribution: float
    history_contribution: float
    
    # Recommended action
    recommended_action: SecurityAction
    action_details: Dict[str, Any]
    
    # Additional context
    factors_analyzed: List[str]
    metadata: Dict[str, Any]

class SecurityManager:
    """Comprehensive security and risk assessment manager"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        
        # Risk thresholds
        self.risk_thresholds = {
            ThreatLevel.MINIMAL: 0.1,
            ThreatLevel.LOW: 0.3,
            ThreatLevel.MODERATE: 0.5,
            ThreatLevel.HIGH: 0.7,
            ThreatLevel.CRITICAL: 0.9
        }
        
        # Session tracking
        self.active_sessions = {}
        self.user_security_history = {}
        self.blocked_ips = set()
        self.suspicious_patterns = {}
        
        # Timing parameters
        self.session_timeout = config.get('session_timeout', 3600)  # 1 hour
        self.max_failed_challenges = config.get('max_failed_challenges', 3)
        self.lockout_duration = config.get('lockout_duration', 900)  # 15 minutes
        
    def assess_security(self, user_id: int, session_id: str,
                       anomaly_result: Optional[AnomalyDetectionResult] = None,
                       drift_result: Optional[DriftDetectionResult] = None,
                       context_data: Optional[Dict[str, Any]] = None) -> SecurityAssessment:
        """Perform comprehensive security assessment"""
        
        assessment_timestamp = datetime.now(timezone.utc)
        
        # Initialize risk components
        anomaly_risk = 0.0
        drift_risk = 0.0
        context_risk = 0.0
        history_risk = 0.0
        
        factors_analyzed = []
        
        # Analyze anomaly detection results
        if anomaly_result:
            anomaly_risk = self._assess_anomaly_risk(anomaly_result)
            factors_analyzed.append("behavioral_anomaly")
        
        # Analyze drift detection results
        if drift_result:
            drift_risk = self._assess_drift_risk(drift_result)
            factors_analyzed.append("behavioral_drift")
        
        # Analyze contextual factors
        if context_data:
            context_risk = self._assess_contextual_risk(user_id, context_data)
            factors_analyzed.append("contextual_analysis")
        
        # Analyze historical security patterns
        history_risk = self._assess_historical_risk(user_id, session_id)
        factors_analyzed.append("historical_patterns")
        
        # Calculate weighted risk score
        risk_weights = {
            'anomaly': 0.4,
            'drift': 0.2,
            'context': 0.2,
            'history': 0.2
        }
        
        overall_risk = (
            anomaly_risk * risk_weights['anomaly'] +
            drift_risk * risk_weights['drift'] +
            context_risk * risk_weights['context'] +
            history_risk * risk_weights['history']
        )
        
        # Determine threat level
        threat_level = self._determine_threat_level(overall_risk)
        
        # Calculate confidence
        confidence = self._calculate_confidence(anomaly_result, drift_result, context_data)
        
        # Determine recommended action
        recommended_action, action_details = self._determine_security_action(
            threat_level, overall_risk, confidence, user_id, session_id
        )
        
        # Update security history
        self._update_security_history(user_id, session_id, threat_level, overall_risk)
        
        assessment = SecurityAssessment(
            timestamp=assessment_timestamp,
            user_id=user_id,
            session_id=session_id,
            threat_level=threat_level,
            risk_score=overall_risk,
            confidence=confidence,
            anomaly_contribution=anomaly_risk,
            drift_contribution=drift_risk,
            context_contribution=context_risk,
            history_contribution=history_risk,
            recommended_action=recommended_action,
            action_details=action_details,
            factors_analyzed=factors_analyzed,
            metadata={
                'anomaly_result': anomaly_result.__dict__ if anomaly_result else None,
                'drift_result': drift_result.__dict__ if drift_result else None,
                'context_data': context_data
            }
        )
        
        logger.info(f"Security assessment complete for user {user_id}: "
                   f"{threat_level.value} threat, {recommended_action.value} action")
        
        return assessment
    
    def _assess_anomaly_risk(self, anomaly_result: AnomalyDetectionResult) -> float:
        """Assess risk contribution from anomaly detection"""
        base_risk = anomaly_result.anomaly_score
        
        # Risk modifiers based on anomaly characteristics
        risk_multipliers = {
            RiskLevel.LOW: 0.5,
            RiskLevel.MEDIUM: 1.0,
            RiskLevel.HIGH: 1.5,
            RiskLevel.CRITICAL: 2.0
        }
        
        multiplier = risk_multipliers.get(anomaly_result.risk_level, 1.0)
        confidence_factor = anomaly_result.confidence
        
        # Adjust for data quality
        quality_factor = max(anomaly_result.data_quality, 0.3)  # Minimum quality threshold
        
        adjusted_risk = base_risk * multiplier * confidence_factor * quality_factor
        return min(adjusted_risk, 1.0)
    
    def _assess_drift_risk(self, drift_result: DriftDetectionResult) -> float:
        """Assess risk contribution from drift detection"""
        if not drift_result.drift_detected:
            return 0.1  # Minimal risk if no drift
        
        severity_risks = {
            DriftSeverity.MINOR: 0.2,
            DriftSeverity.MODERATE: 0.4,
            DriftSeverity.MAJOR: 0.7,
            DriftSeverity.CRITICAL: 0.9
        }
        
        base_risk = severity_risks.get(drift_result.drift_severity, 0.3)
        confidence_factor = drift_result.confidence
        
        # Consider number of affected features
        feature_factor = min(len(drift_result.affected_features) / 10.0, 1.0)
        
        adjusted_risk = base_risk * confidence_factor * (0.7 + 0.3 * feature_factor)
        return min(adjusted_risk, 1.0)
    
    def _assess_contextual_risk(self, user_id: int, context_data: Dict[str, Any]) -> float:
        """Assess risk from contextual factors"""
        risk_factors = []
        
        # IP address analysis
        ip_address = context_data.get('ip_address')
        if ip_address:
            ip_risk = self._assess_ip_risk(user_id, ip_address)
            risk_factors.append(ip_risk)
        
        # User agent analysis
        user_agent = context_data.get('user_agent')
        if user_agent:
            ua_risk = self._assess_user_agent_risk(user_id, user_agent)
            risk_factors.append(ua_risk)
        
        # Time-based analysis
        timestamp = context_data.get('timestamp', datetime.now(timezone.utc))
        time_risk = self._assess_temporal_risk(user_id, timestamp)
        risk_factors.append(time_risk)
        
        # Session analysis
        session_data = context_data.get('session_info', {})
        session_risk = self._assess_session_risk(user_id, session_data)
        risk_factors.append(session_risk)
        
        # Geographic analysis (if available)
        location_data = context_data.get('location')
        if location_data:
            geo_risk = self._assess_geographic_risk(user_id, location_data)
            risk_factors.append(geo_risk)
        
        return np.mean(risk_factors) if risk_factors else 0.0
    
    def _assess_historical_risk(self, user_id: int, session_id: str) -> float:
        """Assess risk based on historical security patterns"""
        if user_id not in self.user_security_history:
            return 0.3  # Moderate risk for new users
        
        history = self.user_security_history[user_id]
        
        # Recent threat levels
        recent_threats = [event['threat_level'] for event in history[-10:]]
        if recent_threats:
            threat_values = {
                ThreatLevel.MINIMAL: 0.05,
                ThreatLevel.LOW: 0.2,
                ThreatLevel.MODERATE: 0.5,
                ThreatLevel.HIGH: 0.8,
                ThreatLevel.CRITICAL: 1.0
            }
            avg_recent_threat = np.mean([threat_values.get(t, 0.5) for t in recent_threats])
        else:
            avg_recent_threat = 0.3
        
        # Challenge failure rate
        recent_challenges = [event for event in history[-20:] if 'challenge_result' in event]
        if recent_challenges:
            failed_challenges = sum(1 for event in recent_challenges 
                                  if event.get('challenge_result') == 'failed')
            failure_rate = failed_challenges / len(recent_challenges)
        else:
            failure_rate = 0.0
        
        # Frequency of security events
        recent_events = [event for event in history if 
                        (datetime.now(timezone.utc) - event['timestamp']).days < 7]
        event_frequency = len(recent_events) / 7.0  # Events per day
        
        # Combine factors
        history_risk = (
            avg_recent_threat * 0.5 +
            failure_rate * 0.3 +
            min(event_frequency / 5.0, 1.0) * 0.2  # Cap at 5 events/day
        )
        
        return min(history_risk, 1.0)
    
    def _assess_ip_risk(self, user_id: int, ip_address: str) -> float:
        """Assess risk based on IP address"""
        try:
            ip = ipaddress.ip_address(ip_address)
            
            # Check if IP is in blocked list
            if ip_address in self.blocked_ips:
                return 1.0
            
            # Check if IP is new for this user
            user_ips = self._get_user_ip_history(user_id)
            if ip_address not in user_ips:
                return 0.4  # Moderate risk for new IP
            
            # Check IP reputation (simplified)
            if ip.is_private:
                return 0.1  # Low risk for private IPs
            elif ip.is_reserved or ip.is_loopback:
                return 0.05  # Very low risk
            else:
                return 0.2  # Moderate risk for public IPs
                
        except Exception as e:
            logger.warning(f"IP risk assessment failed: {e}")
            return 0.3
    
    def _assess_user_agent_risk(self, user_id: int, user_agent: str) -> float:
        """Assess risk based on user agent string"""
        # Get user's typical user agents
        typical_agents = self._get_user_agent_history(user_id)
        
        if not typical_agents:
            return 0.2  # Moderate risk for new user
        
        # Check if current user agent is familiar
        if user_agent in typical_agents:
            return 0.1  # Low risk for familiar agent
        
        # Check for suspicious patterns
        suspicious_patterns = ['bot', 'crawler', 'scanner', 'automated']
        if any(pattern in user_agent.lower() for pattern in suspicious_patterns):
            return 0.8  # High risk for suspicious agents
        
        return 0.3  # Moderate risk for new but normal-looking agent
    
    def _assess_temporal_risk(self, user_id: int, timestamp: datetime) -> float:
        """Assess risk based on timing patterns"""
        # Get user's typical activity hours
        typical_hours = self._get_user_activity_hours(user_id)
        
        current_hour = timestamp.hour
        
        if not typical_hours:
            return 0.2  # Moderate risk for new user
        
        # Check if current time is within typical hours
        if current_hour in typical_hours:
            return 0.1  # Low risk during typical hours
        
        # Check if it's extremely unusual time (e.g., middle of night)
        if current_hour in [2, 3, 4, 5]:  # 2-5 AM
            if current_hour not in typical_hours:
                return 0.6  # Higher risk for unusual late hours
        
        return 0.3  # Moderate risk for atypical but reasonable hours
    
    def _assess_session_risk(self, user_id: int, session_data: Dict[str, Any]) -> float:
        """Assess risk based on session characteristics"""
        risk_factors = []
        
        # Session duration
        session_start = session_data.get('start_time')
        if session_start:
            duration = (datetime.now(timezone.utc) - session_start).total_seconds()
            # Very long sessions might be suspicious
            if duration > 8 * 3600:  # 8 hours
                risk_factors.append(0.4)
            elif duration > 12 * 3600:  # 12 hours
                risk_factors.append(0.7)
            else:
                risk_factors.append(0.1)
        
        # Number of concurrent sessions
        concurrent_sessions = session_data.get('concurrent_sessions', 1)
        if concurrent_sessions > 3:
            risk_factors.append(0.5)
        elif concurrent_sessions > 1:
            risk_factors.append(0.2)
        else:
            risk_factors.append(0.0)
        
        # Session activity level
        activity_level = session_data.get('activity_level', 'normal')
        activity_risks = {
            'very_low': 0.3,
            'low': 0.2,
            'normal': 0.1,
            'high': 0.2,
            'very_high': 0.4
        }
        risk_factors.append(activity_risks.get(activity_level, 0.2))
        
        return np.mean(risk_factors) if risk_factors else 0.2
    
    def _assess_geographic_risk(self, user_id: int, location_data: Dict[str, Any]) -> float:
        """Assess risk based on geographic location"""
        # Simplified geographic risk assessment
        # In a real implementation, this would use comprehensive geo-IP databases
        
        country = location_data.get('country', '').upper()
        typical_countries = self._get_user_typical_countries(user_id)
        
        if not typical_countries:
            return 0.2  # Moderate risk for new user
        
        if country in typical_countries:
            return 0.1  # Low risk for typical country
        
        # High-risk countries (this would be configurable)
        high_risk_countries = self.config.get('high_risk_countries', [])
        if country in high_risk_countries:
            return 0.8
        
        return 0.4  # Moderate risk for new country
    
    def _determine_threat_level(self, risk_score: float) -> ThreatLevel:
        """Determine threat level based on risk score"""
        if risk_score >= self.risk_thresholds[ThreatLevel.CRITICAL]:
            return ThreatLevel.CRITICAL
        elif risk_score >= self.risk_thresholds[ThreatLevel.HIGH]:
            return ThreatLevel.HIGH
        elif risk_score >= self.risk_thresholds[ThreatLevel.MODERATE]:
            return ThreatLevel.MODERATE
        elif risk_score >= self.risk_thresholds[ThreatLevel.LOW]:
            return ThreatLevel.LOW
        else:
            return ThreatLevel.MINIMAL
    
    def _calculate_confidence(self, anomaly_result: Optional[AnomalyDetectionResult],
                            drift_result: Optional[DriftDetectionResult],
                            context_data: Optional[Dict[str, Any]]) -> float:
        """Calculate confidence in security assessment"""
        confidence_factors = []
        
        if anomaly_result:
            confidence_factors.append(anomaly_result.confidence)
        
        if drift_result:
            confidence_factors.append(drift_result.confidence)
        
        if context_data:
            # Context data quality
            context_quality = len(context_data) / 10.0  # Normalize by expected fields
            confidence_factors.append(min(context_quality, 1.0))
        
        # Base confidence for having multiple data sources
        if len(confidence_factors) > 1:
            base_confidence = 0.7
        else:
            base_confidence = 0.5
        
        if confidence_factors:
            return base_confidence * np.mean(confidence_factors)
        else:
            return 0.3  # Low confidence with no data
    
    def _determine_security_action(self, threat_level: ThreatLevel, risk_score: float,
                                 confidence: float, user_id: int, 
                                 session_id: str) -> Tuple[SecurityAction, Dict[str, Any]]:
        """Determine recommended security action"""
        
        action_details = {
            'threat_level': threat_level.value,
            'risk_score': risk_score,
            'confidence': confidence,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        # Check if user is currently locked out
        if self._is_user_locked_out(user_id):
            return SecurityAction.BLOCK, {**action_details, 'reason': 'user_locked_out'}
        
        # Critical threat level
        if threat_level == ThreatLevel.CRITICAL:
            if confidence > 0.8:
                return SecurityAction.LOGOUT, {**action_details, 'reason': 'critical_threat_high_confidence'}
            else:
                return SecurityAction.BLOCK, {**action_details, 'reason': 'critical_threat_moderate_confidence'}
        
        # High threat level
        elif threat_level == ThreatLevel.HIGH:
            if confidence > 0.7:
                challenge_type = 'verification' if risk_score > 0.8 else 'adaptive'
                return SecurityAction.CHALLENGE, {
                    **action_details, 
                    'challenge_type': challenge_type,
                    'reason': 'high_threat'
                }
            else:
                return SecurityAction.RESTRICT, {**action_details, 'reason': 'high_threat_low_confidence'}
        
        # Moderate threat level
        elif threat_level == ThreatLevel.MODERATE:
            if confidence > 0.6:
                return SecurityAction.CHALLENGE, {
                    **action_details,
                    'challenge_type': 'lightweight',
                    'reason': 'moderate_threat'
                }
            else:
                return SecurityAction.MONITOR, {**action_details, 'reason': 'moderate_threat_uncertain'}
        
        # Low or minimal threat
        else:
            return SecurityAction.ALLOW, {**action_details, 'reason': 'low_threat'}
    
    def _update_security_history(self, user_id: int, session_id: str, 
                               threat_level: ThreatLevel, risk_score: float) -> None:
        """Update user's security history"""
        if user_id not in self.user_security_history:
            self.user_security_history[user_id] = []
        
        event = {
            'timestamp': datetime.now(timezone.utc),
            'session_id': session_id,
            'threat_level': threat_level,
            'risk_score': risk_score
        }
        
        self.user_security_history[user_id].append(event)
        
        # Keep only recent history (last 100 events)
        if len(self.user_security_history[user_id]) > 100:
            self.user_security_history[user_id] = self.user_security_history[user_id][-100:]
    
    def _is_user_locked_out(self, user_id: int) -> bool:
        """Check if user is currently locked out"""
        # This would integrate with the database to check lockout status
        # For now, return False as placeholder
        return False
    
    def _get_user_ip_history(self, user_id: int) -> List[str]:
        """Get user's historical IP addresses"""
        # Placeholder - would query database
        return []
    
    def _get_user_agent_history(self, user_id: int) -> List[str]:
        """Get user's historical user agents"""
        # Placeholder - would query database
        return []
    
    def _get_user_activity_hours(self, user_id: int) -> List[int]:
        """Get user's typical activity hours"""
        # Placeholder - would analyze historical login times
        return list(range(8, 18))  # Default 8 AM to 6 PM
    
    def _get_user_typical_countries(self, user_id: int) -> List[str]:
        """Get user's typical countries"""
        # Placeholder - would query historical location data
        return ['US', 'CA']  # Default countries
    
    def generate_challenge_token(self, user_id: int, challenge_type: str) -> str:
        """Generate secure challenge token"""
        timestamp = datetime.now(timezone.utc).isoformat()
        data = f"{user_id}:{challenge_type}:{timestamp}:{secrets.token_hex(16)}"
        
        # Create hash
        token_hash = hashlib.sha256(data.encode()).hexdigest()
        return token_hash
    
    def validate_challenge_response(self, user_id: int, token: str, 
                                  response_data: Dict[str, Any]) -> bool:
        """Validate challenge response"""
        # This would implement actual challenge validation logic
        # For now, return True as placeholder
        return True