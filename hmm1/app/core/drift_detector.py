# ==========================================
# app/core/drift_detector.py
"""
Behavioral drift detection for continuous authentication
"""
import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Optional, Any
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass
from enum import Enum
import logging
from scipy import stats
from scipy.stats import ks_2samp, chi2_contingency
from sklearn.metrics import jensen_shannon_distance
import warnings

logger = logging.getLogger(__name__)

class DriftType(Enum):
    GRADUAL = "gradual"
    SUDDEN = "sudden"
    SEASONAL = "seasonal"
    CONCEPT = "concept"

class DriftSeverity(Enum):
    MINOR = "minor"
    MODERATE = "moderate"
    MAJOR = "major"
    CRITICAL = "critical"

@dataclass
class DriftDetectionResult:
    """Result of drift detection analysis"""
    timestamp: datetime
    user_id: int
    
    # Drift assessment
    drift_detected: bool
    drift_type: DriftType
    drift_severity: DriftSeverity
    drift_score: float
    confidence: float
    
    # Affected features
    affected_features: List[str]
    feature_drift_scores: Dict[str, float]
    
    # Statistical tests
    statistical_tests: Dict[str, Any]
    
    # Recommendations
    retraining_required: bool
    adaptation_strategy: str
    data_collection_required: bool

class BehavioralDriftDetector:
    """Detect behavioral drift in user patterns"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        
        # Drift detection parameters
        self.window_size = config.get('drift_window_size', 100)
        self.min_samples = config.get('min_drift_samples', 30)
        self.significance_level = config.get('significance_level', 0.05)
        
        # Drift thresholds
        self.minor_drift_threshold = config.get('minor_drift_threshold', 0.1)
        self.moderate_drift_threshold = config.get('moderate_drift_threshold', 0.3)
        self.major_drift_threshold = config.get('major_drift_threshold', 0.6)
        
        # Feature monitoring
        self.feature_drift_threshold = config.get('feature_drift_threshold', 0.2)
        self.max_drift_features = config.get('max_drift_features', 10)
        
        # Historical data storage
        self.user_feature_history = {}
        self.baseline_statistics = {}
        
    def update_baseline(self, user_id: int, features: Dict[str, float], 
                       timestamp: datetime) -> None:
        """Update user's baseline statistics with new data"""
        if user_id not in self.user_feature_history:
            self.user_feature_history[user_id] = []
            self.baseline_statistics[user_id] = {}
        
        # Add timestamped features
        feature_record = {
            'timestamp': timestamp,
            'features': features.copy()
        }
        
        self.user_feature_history[user_id].append(feature_record)
        
        # Maintain sliding window
        cutoff_time = timestamp - timedelta(days=30)  # Keep 30 days of history
        self.user_feature_history[user_id] = [
            record for record in self.user_feature_history[user_id]
            if record['timestamp'] > cutoff_time
        ]
        
        # Update baseline statistics
        self._update_baseline_statistics(user_id)
    
    def detect_drift(self, user_id: int, recent_features: List[Dict[str, float]], 
                    analysis_timestamp: datetime) -> DriftDetectionResult:
        """Detect behavioral drift using multiple statistical methods"""
        
        if user_id not in self.user_feature_history:
            logger.warning(f"No historical data for user {user_id}")
            return self._create_no_history_result(user_id, analysis_timestamp)
        
        history = self.user_feature_history[user_id]
        if len(history) < self.min_samples:
            logger.info(f"Insufficient historical data for user {user_id}")
            return self._create_insufficient_data_result(user_id, analysis_timestamp)
        
        # Prepare historical and recent data
        historical_features = [record['features'] for record in history[:-len(recent_features)]]
        
        if len(historical_features) < self.min_samples:
            return self._create_insufficient_data_result(user_id, analysis_timestamp)
        
        # Perform drift detection tests
        statistical_tests = self._perform_statistical_tests(historical_features, recent_features)
        
        # Analyze feature-level drift
        feature_drift_scores = self._analyze_feature_drift(historical_features, recent_features)
        
        # Determine overall drift score
        drift_score = self._calculate_overall_drift_score(statistical_tests, feature_drift_scores)
        
        # Classify drift type and severity
        drift_type = self._classify_drift_type(user_id, analysis_timestamp)
        drift_severity = self._classify_drift_severity(drift_score, feature_drift_scores)
        
        # Determine affected features
        affected_features = [
            feature for feature, score in feature_drift_scores.items()
            if score > self.feature_drift_threshold
        ]
        
        # Calculate confidence
        confidence = self._calculate_drift_confidence(statistical_tests, feature_drift_scores)
        
        # Make recommendations
        retraining_required, adaptation_strategy, data_collection_required = \
            self._make_recommendations(drift_severity, len(affected_features), confidence)
        
        result = DriftDetectionResult(
            timestamp=analysis_timestamp,
            user_id=user_id,
            drift_detected=drift_score > self.minor_drift_threshold,
            drift_type=drift_type,
            drift_severity=drift_severity,
            drift_score=drift_score,
            confidence=confidence,
            affected_features=affected_features,
            feature_drift_scores=feature_drift_scores,
            statistical_tests=statistical_tests,
            retraining_required=retraining_required,
            adaptation_strategy=adaptation_strategy,
            data_collection_required=data_collection_required
        )
        
        logger.info(f"Drift detection complete for user {user_id}: "
                   f"{drift_severity.value} {drift_type.value} drift (score: {drift_score:.3f})")
        
        return result
    
    def _perform_statistical_tests(self, historical_data: List[Dict[str, float]], 
                                 recent_data: List[Dict[str, float]]) -> Dict[str, Any]:
        """Perform multiple statistical tests for drift detection"""
        tests = {}
        
        # Convert to feature matrices
        hist_df = pd.DataFrame(historical_data)
        recent_df = pd.DataFrame(recent_data)
        
        # Common features
        common_features = set(hist_df.columns) & set(recent_df.columns)
        
        # Kolmogorov-Smirnov test for each feature
        ks_test_results = {}
        for feature in common_features:
            try:
                hist_values = hist_df[feature].dropna()
                recent_values = recent_df[feature].dropna()
                
                if len(hist_values) > 5 and len(recent_values) > 5:
                    ks_statistic, p_value = ks_2samp(hist_values, recent_values)
                    ks_test_results[feature] = {
                        'statistic': float(ks_statistic),
                        'p_value': float(p_value),
                        'drift_detected': p_value < self.significance_level
                    }
            except Exception as e:
                logger.warning(f"KS test failed for feature {feature}: {e}")
        
        tests['kolmogorov_smirnov'] = ks_test_results
        
        # Jensen-Shannon divergence test
        js_divergences = {}
        for feature in common_features:
            try:
                hist_values = hist_df[feature].dropna()
                recent_values = recent_df[feature].dropna()
                
                if len(hist_values) > 5 and len(recent_values) > 5:
                    # Create histograms
                    hist_range = (min(hist_values.min(), recent_values.min()),
                                max(hist_values.max(), recent_values.max()))
                    
                    hist_counts, _ = np.histogram(hist_values, bins=10, range=hist_range, density=True)
                    recent_counts, _ = np.histogram(recent_values, bins=10, range=hist_range, density=True)
                    
                    # Normalize to probability distributions
                    hist_dist = hist_counts / (hist_counts.sum() + 1e-10)
                    recent_dist = recent_counts / (recent_counts.sum() + 1e-10)
                    
                    # Calculate JS divergence
                    js_div = self._jensen_shannon_divergence(hist_dist, recent_dist)
                    js_divergences[feature] = float(js_div)
                    
            except Exception as e:
                logger.warning(f"JS divergence calculation failed for feature {feature}: {e}")
        
        tests['jensen_shannon'] = js_divergences
        
        # Population stability index (PSI)
        psi_scores = {}
        for feature in common_features:
            try:
                psi_score = self._calculate_psi(hist_df[feature], recent_df[feature])
                psi_scores[feature] = float(psi_score)
            except Exception as e:
                logger.warning(f"PSI calculation failed for feature {feature}: {e}")
        
        tests['population_stability_index'] = psi_scores
        
        return tests
    
    def _analyze_feature_drift(self, historical_data: List[Dict[str, float]], 
                             recent_data: List[Dict[str, float]]) -> Dict[str, float]:
        """Analyze drift at the feature level"""
        hist_df = pd.DataFrame(historical_data)
        recent_df = pd.DataFrame(recent_data)
        
        feature_drift_scores = {}
        common_features = set(hist_df.columns) & set(recent_df.columns)
        
        for feature in common_features:
            try:
                hist_values = hist_df[feature].dropna()
                recent_values = recent_df[feature].dropna()
                
                if len(hist_values) > 5 and len(recent_values) > 5:
                    # Statistical measures
                    hist_mean = hist_values.mean()
                    recent_mean = recent_values.mean()
                    hist_std = hist_values.std()
                    recent_std = recent_values.std()
                    
                    # Mean shift score
                    mean_shift = abs(recent_mean - hist_mean) / (hist_std + 1e-10)
                    
                    # Variance change score
                    variance_ratio = max(recent_std / (hist_std + 1e-10), 
                                       hist_std / (recent_std + 1e-10)) - 1
                    
                    # Combined score
                    drift_score = (mean_shift * 0.7 + variance_ratio * 0.3)
                    feature_drift_scores[feature] = min(drift_score, 1.0)
                    
            except Exception as e:
                logger.warning(f"Feature drift analysis failed for {feature}: {e}")
                feature_drift_scores[feature] = 0.0
        
        return feature_drift_scores
    
    def _calculate_overall_drift_score(self, statistical_tests: Dict[str, Any], 
                                     feature_drift_scores: Dict[str, float]) -> float:
        """Calculate overall drift score from all tests"""
        scores = []
        
        # KS test contribution
        ks_results = statistical_tests.get('kolmogorov_smirnov', {})
        ks_drift_ratio = sum(1 for result in ks_results.values() if result.get('drift_detected', False))
        ks_drift_ratio = ks_drift_ratio / len(ks_results) if ks_results else 0
        scores.append(ks_drift_ratio)
        
        # JS divergence contribution
        js_results = statistical_tests.get('jensen_shannon', {})
        js_scores = list(js_results.values()) if js_results else [0]
        js_avg = np.mean(js_scores)
        scores.append(min(js_avg * 2, 1.0))  # Scale JS divergence
        
        # PSI contribution
        psi_results = statistical_tests.get('population_stability_index', {})
        psi_scores = list(psi_results.values()) if psi_results else [0]
        psi_avg = np.mean(psi_scores)
        scores.append(min(psi_avg / 0.25, 1.0))  # PSI > 0.25 indicates significant drift
        
        # Feature drift contribution
        feature_scores = list(feature_drift_scores.values()) if feature_drift_scores else [0]
        feature_avg = np.mean(feature_scores)
        scores.append(feature_avg)
        
        # Weighted average
        weights = [0.3, 0.3, 0.2, 0.2]
        overall_score = np.average(scores, weights=weights)
        
        return float(overall_score)
    
    def _classify_drift_type(self, user_id: int, timestamp: datetime) -> DriftType:
        """Classify the type of drift based on temporal patterns"""
        if user_id not in self.user_feature_history:
            return DriftType.SUDDEN
        
        history = self.user_feature_history[user_id]
        if len(history) < 20:
            return DriftType.SUDDEN
        
        # Analyze temporal patterns in recent history
        recent_window = 10
        recent_records = history[-recent_window:]
        earlier_records = history[-recent_window*2:-recent_window]
        
        if len(earlier_records) < recent_window:
            return DriftType.SUDDEN
        
        # Calculate feature variance trends
        recent_features = [record['features'] for record in recent_records]
        earlier_features = [record['features'] for record in earlier_records]
        
        recent_df = pd.DataFrame(recent_features)
        earlier_df = pd.DataFrame(earlier_features)
        
        # Compare variance patterns
        variance_changes = []
        for col in recent_df.columns:
            if col in earlier_df.columns:
                recent_var = recent_df[col].var()
                earlier_var = earlier_df[col].var()
                if earlier_var > 0:
                    variance_change = abs(recent_var - earlier_var) / earlier_var
                    variance_changes.append(variance_change)
        
        if variance_changes:
            avg_variance_change = np.mean(variance_changes)
            if avg_variance_change > 0.5:
                return DriftType.SUDDEN
            else:
                return DriftType.GRADUAL
        
        return DriftType.GRADUAL
    
    def _classify_drift_severity(self, drift_score: float, 
                               feature_drift_scores: Dict[str, float]) -> DriftSeverity:
        """Classify drift severity based on score and affected features"""
        affected_count = sum(1 for score in feature_drift_scores.values() 
                           if score > self.feature_drift_threshold)
        total_features = len(feature_drift_scores)
        affected_ratio = affected_count / total_features if total_features > 0 else 0
        
        if drift_score >= self.major_drift_threshold or affected_ratio > 0.7:
            return DriftSeverity.CRITICAL
        elif drift_score >= self.moderate_drift_threshold or affected_ratio > 0.4:
            return DriftSeverity.MAJOR
        elif drift_score >= self.minor_drift_threshold or affected_ratio > 0.2:
            return DriftSeverity.MODERATE
        else:
            return DriftSeverity.MINOR
    
    def _calculate_drift_confidence(self, statistical_tests: Dict[str, Any], 
                                  feature_drift_scores: Dict[str, float]) -> float:
        """Calculate confidence in drift detection"""
        confidence_scores = []
        
        # KS test confidence
        ks_results = statistical_tests.get('kolmogorov_smirnov', {})
        ks_confidences = [1 - result.get('p_value', 0.5) for result in ks_results.values()]
        if ks_confidences:
            confidence_scores.append(np.mean(ks_confidences))
        
        # Feature drift confidence
        feature_scores = list(feature_drift_scores.values())
        if feature_scores:
            feature_confidence = min(np.mean(feature_scores) * 2, 1.0)
            confidence_scores.append(feature_confidence)
        
        # Sample size confidence
        sample_confidence = min(len(feature_scores) / 20.0, 1.0)  # Full confidence with 20+ features
        confidence_scores.append(sample_confidence)
        
        return float(np.mean(confidence_scores)) if confidence_scores else 0.5
    
    def _make_recommendations(self, drift_severity: DriftSeverity, 
                            affected_features_count: int, 
                            confidence: float) -> Tuple[bool, str, bool]:
        """Make recommendations based on drift analysis"""
        
        retraining_required = False
        adaptation_strategy = "monitor"
        data_collection_required = False
        
        if drift_severity == DriftSeverity.CRITICAL:
            retraining_required = True
            adaptation_strategy = "immediate_recalibration"
            data_collection_required = True
        elif drift_severity == DriftSeverity.MAJOR:
            if confidence > 0.7:
                retraining_required = True
                adaptation_strategy = "guided_recalibration"
                data_collection_required = True
            else:
                adaptation_strategy = "extended_monitoring"
                data_collection_required = True
        elif drift_severity == DriftSeverity.MODERATE:
            if affected_features_count > 5:
                adaptation_strategy = "partial_recalibration"
                data_collection_required = True
            else:
                adaptation_strategy = "targeted_monitoring"
        
        return retraining_required, adaptation_strategy, data_collection_required
    
    def _update_baseline_statistics(self, user_id: int) -> None:
        """Update baseline statistics for a user"""
        history = self.user_feature_history[user_id]
        if not history:
            return
        
        # Extract all features
        all_features = {}
        for record in history:
            for feature, value in record['features'].items():
                if feature not in all_features:
                    all_features[feature] = []
                all_features[feature].append(value)
        
        # Calculate statistics
        baseline_stats = {}
        for feature, values in all_features.items():
            values_array = np.array(values)
            baseline_stats[feature] = {
                'mean': float(np.mean(values_array)),
                'std': float(np.std(values_array)),
                'min': float(np.min(values_array)),
                'max': float(np.max(values_array)),
                'count': len(values_array)
            }
        
        self.baseline_statistics[user_id] = baseline_stats
    
    def _jensen_shannon_divergence(self, p: np.ndarray, q: np.ndarray) -> float:
        """Calculate Jensen-Shannon divergence between two probability distributions"""
        # Ensure probabilities sum to 1
        p = p / (p.sum() + 1e-10)
        q = q / (q.sum() + 1e-10)
        
        # Calculate JS divergence
        m = (p + q) / 2
        divergence = 0.5 * self._kl_divergence(p, m) + 0.5 * self._kl_divergence(q, m)
        return divergence
    
    def _kl_divergence(self, p: np.ndarray, q: np.ndarray) -> float:
        """Calculate Kullback-Leibler divergence"""
        # Avoid log(0) by adding small epsilon
        epsilon = 1e-10
        p_safe = p + epsilon
        q_safe = q + epsilon
        
        return np.sum(p_safe * np.log(p_safe / q_safe))
    
    def _calculate_psi(self, baseline: pd.Series, current: pd.Series, bins: int = 10) -> float:
        """Calculate Population Stability Index (PSI)"""
        try:
            # Remove NaN values
            baseline_clean = baseline.dropna()
            current_clean = current.dropna()
            
            if len(baseline_clean) == 0 or len(current_clean) == 0:
                return 0.0
            
            # Create bins based on baseline quantiles
            _, bin_edges = pd.qcut(baseline_clean, bins, retbins=True, duplicates='drop')
            
            # Calculate bin populations
            baseline_counts = pd.cut(baseline_clean, bin_edges, include_lowest=True).value_counts()
            current_counts = pd.cut(current_clean, bin_edges, include_lowest=True).value_counts()
            
            # Convert to proportions
            baseline_props = baseline_counts / len(baseline_clean)
            current_props = current_counts / len(current_clean)
            
            # Align indices and fill missing values
            baseline_props = baseline_props.reindex(current_props.index, fill_value=0.001)
            current_props = current_props.fillna(0.001)
            
            # Calculate PSI
            psi = np.sum((current_props - baseline_props) * np.log(current_props / baseline_props))
            return float(psi)
            
        except Exception as e:
            logger.warning(f"PSI calculation failed: {e}")
            return 0.0
    
    def _create_no_history_result(self, user_id: int, timestamp: datetime) -> DriftDetectionResult:
        """Create result when no historical data exists"""
        return DriftDetectionResult(
            timestamp=timestamp,
            user_id=user_id,
            drift_detected=False,
            drift_type=DriftType.GRADUAL,
            drift_severity=DriftSeverity.MINOR,
            drift_score=0.0,
            confidence=0.0,
            affected_features=[],
            feature_drift_scores={},
            statistical_tests={},
            retraining_required=False,
            adaptation_strategy="collect_baseline",
            data_collection_required=True
        )
    
    def _create_insufficient_data_result(self, user_id: int, timestamp: datetime) -> DriftDetectionResult:
        """Create result when insufficient data exists"""
        return DriftDetectionResult(
            timestamp=timestamp,
            user_id=user_id,
            drift_detected=False,
            drift_type=DriftType.GRADUAL,
            drift_severity=DriftSeverity.MINOR,
            drift_score=0.0,
            confidence=0.0,
            affected_features=[],
            feature_drift_scores={},
            statistical_tests={},
            retraining_required=False,
            adaptation_strategy="collect_more_data",
            data_collection_required=True
        )