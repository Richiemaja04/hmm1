# app/core/anomaly_detector.py
"""
Advanced anomaly detection system for behavioral biometrics
"""
import numpy as np
import logging
from typing import Dict, List, Tuple, Optional, Any
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass
from enum import Enum
import json

from app.models.ml_models import BehavioralMLEnsemble
from app.core.feature_extractor import BehavioralFeatureExtractor

logger = logging.getLogger(__name__)

class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class AnomalyType(Enum):
    KEYSTROKE = "keystroke"
    MOUSE = "mouse"
    COMBINED = "combined"
    TEMPORAL = "temporal"
    DRIFT = "drift"

@dataclass
class AnomalyDetectionResult:
    """Result of anomaly detection analysis"""
    timestamp: datetime
    user_id: int
    session_id: str
    
    # Overall assessment
    anomaly_score: float
    confidence: float
    risk_level: RiskLevel
    is_anomaly: bool
    
    # Detailed analysis
    anomaly_type: AnomalyType
    feature_deviations: Dict[str, float]
    model_predictions: Dict[str, Any]
    
    # Contextual information
    data_quality: float
    sample_size: int
    time_since_last_analysis: float
    
    # Recommended actions
    action_required: str
    challenge_type: Optional[str] = None
    retrain_suggested: bool = False

class BehavioralAnomalyDetector:
    """Advanced anomaly detection for continuous authentication"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.feature_extractor = BehavioralFeatureExtractor()
        self.ml_ensemble = BehavioralMLEnsemble()
        
        # Thresholds from config
        self.low_risk_threshold = config.get('low_risk_threshold', 0.3)
        self.medium_risk_threshold = config.get('medium_risk_threshold', 0.6)
        self.high_risk_threshold = config.get('high_risk_threshold', 0.8)
        self.critical_risk_threshold = config.get('critical_risk_threshold', 0.9)
        
        # Feature deviation thresholds
        self.feature_deviation_threshold = config.get('feature_deviation_threshold', 2.0)
        self.min_data_quality = config.get('min_data_quality', 0.5)
        self.min_sample_size = config.get('min_sample_size', 10)
        
        # Temporal analysis
        self.max_analysis_interval = config.get('max_analysis_interval', 300)  # 5 minutes
        self.min_analysis_interval = config.get('min_analysis_interval', 30)   # 30 seconds
        
        # User baselines cache
        self.user_baselines = {}
        self.last_analysis_time = {}
        
    def load_user_baseline(self, user_id: int, baseline_data: Dict[str, Any]) -> bool:
        """Load user's behavioral baseline for comparison"""
        try:
            self.user_baselines[user_id] = {
                'keystroke_baseline': baseline_data.get('keystroke_baseline', {}),
                'mouse_baseline': baseline_data.get('mouse_baseline', {}),
                'model_ensemble': BehavioralMLEnsemble(),
                'last_updated': datetime.now(timezone.utc)
            }
            
            # Load trained models if available
            model_path = baseline_data.get('model_path')
            if model_path:
                success = self.user_baselines[user_id]['model_ensemble'].load_models(model_path)
                if not success:
                    logger.warning(f"Failed to load ML models for user {user_id}")
            
            logger.info(f"Loaded baseline for user {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load baseline for user {user_id}: {e}")
            return False
    
    def analyze_behavioral_data(self, user_id: int, session_id: str, 
                              keystroke_events: List[Dict], 
                              mouse_events: List[Dict]) -> AnomalyDetectionResult:
        """Comprehensive behavioral anomaly analysis"""
        
        analysis_timestamp = datetime.now(timezone.utc)
        
        # Check if user baseline exists
        if user_id not in self.user_baselines:
            logger.warning(f"No baseline found for user {user_id}")
            return self._create_default_result(user_id, session_id, analysis_timestamp)
        
        # Extract features
        keystroke_features = self.feature_extractor.extract_keystroke_features(keystroke_events)
        mouse_features = self.feature_extractor.extract_mouse_features(mouse_events)
        
        # Combine features
        all_features = {**keystroke_features, **mouse_features}
        feature_array = np.array(list(all_features.values()))
        
        # Data quality assessment
        data_quality = self._assess_data_quality(keystroke_events, mouse_events, all_features)
        
        if data_quality < self.min_data_quality:
            logger.warning(f"Low data quality ({data_quality:.2f}) for user {user_id}")
            return self._create_low_quality_result(user_id, session_id, analysis_timestamp, data_quality)
        
        # ML ensemble prediction
        ml_results = self.user_baselines[user_id]['model_ensemble'].predict_anomaly(feature_array)
        
        # Baseline deviation analysis
        feature_deviations = self._analyze_feature_deviations(user_id, all_features)
        
        # Temporal analysis
        time_since_last = self._get_time_since_last_analysis(user_id, analysis_timestamp)
        
        # Determine anomaly type
        anomaly_type = self._determine_anomaly_type(keystroke_features, mouse_features, feature_deviations)
        
        # Risk assessment
        risk_assessment = self._assess_risk_level(ml_results, feature_deviations, data_quality, time_since_last)
        
        # Action determination
        action_required, challenge_type, retrain_suggested = self._determine_actions(risk_assessment)
        
        # Update last analysis time
        self.last_analysis_time[user_id] = analysis_timestamp
        
        result = AnomalyDetectionResult(
            timestamp=analysis_timestamp,
            user_id=user_id,
            session_id=session_id,
            anomaly_score=risk_assessment['anomaly_score'],
            confidence=risk_assessment['confidence'],
            risk_level=risk_assessment['risk_level'],
            is_anomaly=risk_assessment['is_anomaly'],
            anomaly_type=anomaly_type,
            feature_deviations=feature_deviations,
            model_predictions=ml_results,
            data_quality=data_quality,
            sample_size=len(keystroke_events) + len(mouse_events),
            time_since_last_analysis=time_since_last,
            action_required=action_required,
            challenge_type=challenge_type,
            retrain_suggested=retrain_suggested
        )
        
        logger.info(f"Anomaly analysis complete for user {user_id}: {risk_assessment['risk_level'].value} risk")
        return result
    
    def _assess_data_quality(self, keystroke_events: List[Dict], 
                           mouse_events: List[Dict], features: Dict[str, float]) -> float:
        """Assess quality of behavioral data"""
        quality_score = 1.0
        
        # Check minimum sample sizes
        if len(keystroke_events) < 5:
            quality_score *= 0.7
        if len(mouse_events) < 10:
            quality_score *= 0.8
        
        # Check for missing or invalid features
        invalid_features = sum(1 for v in features.values() if np.isnan(v) or np.isinf(v))
        if invalid_features > 0:
            quality_score *= (1 - invalid_features / len(features))
        
        # Check temporal distribution
        if keystroke_events:
            timestamps = [event.get('timestamp') for event in keystroke_events if event.get('timestamp')]
            if len(timestamps) > 1:
                time_span = max(timestamps) - min(timestamps)
                if hasattr(time_span, 'total_seconds'):
                    span_seconds = time_span.total_seconds()
                    if span_seconds < 5:  # Too short
                        quality_score *= 0.6
                    elif span_seconds > 300:  # Too long
                        quality_score *= 0.8
        
        return max(0.0, min(1.0, quality_score))
    
    def _analyze_feature_deviations(self, user_id: int, current_features: Dict[str, float]) -> Dict[str, float]:
        """Analyze deviations from user's baseline features"""
        baseline = self.user_baselines[user_id]
        keystroke_baseline = baseline['keystroke_baseline']
        mouse_baseline = baseline['mouse_baseline']
        
        deviations = {}
        
        # Analyze keystroke feature deviations
        for feature_name, current_value in current_features.items():
            if feature_name in keystroke_baseline:
                baseline_mean = keystroke_baseline[feature_name].get('mean', current_value)
                baseline_std = keystroke_baseline[feature_name].get('std', 1.0)
                
                if baseline_std > 0:
                    z_score = abs(current_value - baseline_mean) / baseline_std
                    deviations[feature_name] = z_score
                else:
                    deviations[feature_name] = 0.0
            
            elif feature_name in mouse_baseline:
                baseline_mean = mouse_baseline[feature_name].get('mean', current_value)
                baseline_std = mouse_baseline[feature_name].get('std', 1.0)
                
                if baseline_std > 0:
                    z_score = abs(current_value - baseline_mean) / baseline_std
                    deviations[feature_name] = z_score
                else:
                    deviations[feature_name] = 0.0
            else:
                # No baseline available for this feature
                deviations[feature_name] = 0.0
        
        return deviations
    
    def _determine_anomaly_type(self, keystroke_features: Dict[str, float], 
                               mouse_features: Dict[str, float], 
                               feature_deviations: Dict[str, float]) -> AnomalyType:
        """Determine the primary type of anomaly detected"""
        
        keystroke_deviation_count = sum(1 for k, v in feature_deviations.items() 
                                      if k in keystroke_features and v > self.feature_deviation_threshold)
        
        mouse_deviation_count = sum(1 for k, v in feature_deviations.items() 
                                  if k in mouse_features and v > self.feature_deviation_threshold)
        
        total_keystroke_features = len(keystroke_features)
        total_mouse_features = len(mouse_features)
        
        # Calculate deviation ratios
        keystroke_ratio = keystroke_deviation_count / total_keystroke_features if total_keystroke_features > 0 else 0
        mouse_ratio = mouse_deviation_count / total_mouse_features if total_mouse_features > 0 else 0
        
        if keystroke_ratio > 0.3 and mouse_ratio > 0.3:
            return AnomalyType.COMBINED
        elif keystroke_ratio > mouse_ratio:
            return AnomalyType.KEYSTROKE
        elif mouse_ratio > 0:
            return AnomalyType.MOUSE
        else:
            return AnomalyType.TEMPORAL
    
    def _assess_risk_level(self, ml_results: Dict[str, Any], 
                          feature_deviations: Dict[str, float],
                          data_quality: float, time_since_last: float) -> Dict[str, Any]:
        """Comprehensive risk level assessment"""
        
        # Base anomaly score from ML ensemble
        base_anomaly_score = ml_results.get('ensemble_score', 0.5)
        base_confidence = ml_results.get('confidence', 0.0)
        
        # Feature deviation score
        high_deviation_count = sum(1 for v in feature_deviations.values() if v > self.feature_deviation_threshold)
        deviation_ratio = high_deviation_count / len(feature_deviations) if feature_deviations else 0
        deviation_score = min(deviation_ratio * 2, 1.0)  # Scale to 0-1
        
        # Temporal score (longer gaps increase suspicion)
        temporal_score = min(time_since_last / self.max_analysis_interval, 1.0) * 0.2
        
        # Data quality penalty
        quality_penalty = (1.0 - data_quality) * 0.3
        
        # Combined anomaly score
        combined_score = (base_anomaly_score * 0.6 + 
                         deviation_score * 0.3 + 
                         temporal_score * 0.1 + 
                         quality_penalty)
        
        combined_score = max(0.0, min(1.0, combined_score))
        
        # Adjust confidence based on data quality
        adjusted_confidence = base_confidence * data_quality
        
        # Determine risk level
        if combined_score >= self.critical_risk_threshold:
            risk_level = RiskLevel.CRITICAL
            is_anomaly = True
        elif combined_score >= self.high_risk_threshold:
            risk_level = RiskLevel.HIGH
            is_anomaly = True
        elif combined_score >= self.medium_risk_threshold:
            risk_level = RiskLevel.MEDIUM
            is_anomaly = adjusted_confidence > 0.5  # Only flag if confident
        else:
            risk_level = RiskLevel.LOW
            is_anomaly = False
        
        return {
            'anomaly_score': combined_score,
            'confidence': adjusted_confidence,
            'risk_level': risk_level,
            'is_anomaly': is_anomaly,
            'component_scores': {
                'ml_ensemble': base_anomaly_score,
                'feature_deviation': deviation_score,
                'temporal': temporal_score,
                'quality_penalty': quality_penalty
            }
        }
    
    def _determine_actions(self, risk_assessment: Dict[str, Any]) -> Tuple[str, Optional[str], bool]:
        """Determine required actions based on risk assessment"""
        risk_level = risk_assessment['risk_level']
        confidence = risk_assessment['confidence']
        
        if risk_level == RiskLevel.CRITICAL:
            return "block_session", None, True
        elif risk_level == RiskLevel.HIGH:
            if confidence > 0.7:
                return "challenge_verification", "high_risk", True
            else:
                return "challenge_verification", "moderate_risk", False
        elif risk_level == RiskLevel.MEDIUM:
            if confidence > 0.6:
                return "monitor_closely", None, False
            else:
                return "log_event", None, False
        else:
            return "continue_monitoring", None, False
    
    def _get_time_since_last_analysis(self, user_id: int, current_time: datetime) -> float:
        """Get time since last analysis in seconds"""
        if user_id not in self.last_analysis_time:
            return 0.0
        
        time_diff = current_time - self.last_analysis_time[user_id]
        return time_diff.total_seconds()
    
    def _create_default_result(self, user_id: int, session_id: str, timestamp: datetime) -> AnomalyDetectionResult:
        """Create default result when no baseline is available"""
        return AnomalyDetectionResult(
            timestamp=timestamp,
            user_id=user_id,
            session_id=session_id,
            anomaly_score=0.5,
            confidence=0.0,
            risk_level=RiskLevel.MEDIUM,
            is_anomaly=False,
            anomaly_type=AnomalyType.TEMPORAL,
            feature_deviations={},
            model_predictions={},
            data_quality=0.0,
            sample_size=0,
            time_since_last_analysis=0.0,
            action_required="calibration_required",
            challenge_type=None,
            retrain_suggested=True
        )
    
    def _create_low_quality_result(self, user_id: int, session_id: str, 
                                 timestamp: datetime, data_quality: float) -> AnomalyDetectionResult:
        """Create result for low-quality data"""
        return AnomalyDetectionResult(
            timestamp=timestamp,
            user_id=user_id,
            session_id=session_id,
            anomaly_score=0.3,  # Lower score due to uncertainty
            confidence=0.1,
            risk_level=RiskLevel.LOW,
            is_anomaly=False,
            anomaly_type=AnomalyType.TEMPORAL,
            feature_deviations={},
            model_predictions={},
            data_quality=data_quality,
            sample_size=0,
            time_since_last_analysis=0.0,
            action_required="improve_data_quality",
            challenge_type=None,
            retrain_suggested=False
        )
