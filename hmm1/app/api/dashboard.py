# ==========================================
# app/api/dashboard.py
"""
Dashboard API endpoints for main user interface
"""
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
import logging
from datetime import datetime, timezone, timedelta
from sqlalchemy import desc, func

from app import db
from app.models.database import User, BehavioralData, AuthenticationLog
from app.services.monitoring_service import MonitoringService
from app.utils.helpers import get_client_ip, get_user_agent

logger = logging.getLogger(__name__)
dashboard_bp = Blueprint('dashboard', __name__)
monitoring_service = MonitoringService()

@dashboard_bp.route('/user-info', methods=['GET'])
@jwt_required()
def get_user_info():
    """Get current user information for dashboard"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Get recent activity stats
        recent_activity = _get_recent_activity_stats(user_id)
        
        return jsonify({
            'user': user.to_dict(),
            'activity_stats': recent_activity,
            'monitoring_active': user.is_calibrated
        }), 200
        
    except Exception as e:
        logger.error(f"Dashboard user info error: {e}")
        return jsonify({'error': 'Failed to get user information'}), 500

@dashboard_bp.route('/analytics', methods=['GET'])
@jwt_required()
def get_analytics_data():
    """Get behavioral analytics data for dashboard charts"""
    try:
        user_id = get_jwt_identity()
        days = request.args.get('days', 7, type=int)
        
        # Get behavioral data from last N days
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
        
        behavioral_data = BehavioralData.query.filter(
            BehavioralData.user_id == user_id,
            BehavioralData.timestamp >= cutoff_date
        ).order_by(BehavioralData.timestamp).all()
        
        # Process data for charts
        analytics = _process_analytics_data(behavioral_data)
        
        return jsonify(analytics), 200
        
    except Exception as e:
        logger.error(f"Dashboard analytics error: {e}")
        return jsonify({'error': 'Failed to get analytics data'}), 500

@dashboard_bp.route('/risk-assessment', methods=['GET'])
@jwt_required()
def get_current_risk_assessment():
    """Get current user risk assessment"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Get recent security events
        recent_events = AuthenticationLog.query.filter(
            AuthenticationLog.user_id == user_id,
            AuthenticationLog.timestamp >= datetime.now(timezone.utc) - timedelta(hours=24)
        ).order_by(desc(AuthenticationLog.timestamp)).limit(10).all()
        
        # Process risk assessment
        risk_data = _calculate_current_risk(user, recent_events)
        
        return jsonify(risk_data), 200
        
    except Exception as e:
        logger.error(f"Risk assessment error: {e}")
        return jsonify({'error': 'Failed to get risk assessment'}), 500

@dashboard_bp.route('/security-events', methods=['GET'])
@jwt_required()
def get_security_events():
    """Get recent security events for user"""
    try:
        user_id = get_jwt_identity()
        limit = request.args.get('limit', 20, type=int)
        
        events = AuthenticationLog.query.filter(
            AuthenticationLog.user_id == user_id
        ).order_by(desc(AuthenticationLog.timestamp)).limit(limit).all()
        
        events_data = []
        for event in events:
            events_data.append({
                'id': event.id,
                'timestamp': event.timestamp.isoformat(),
                'event_type': event.event_type,
                'event_status': event.event_status,
                'risk_score': event.risk_score,
                'action_taken': event.action_taken,
                'ip_address': event.ip_address,
                'metadata': event.metadata_data
            })
        
        return jsonify({'events': events_data}), 200
        
    except Exception as e:
        logger.error(f"Security events error: {e}")
        return jsonify({'error': 'Failed to get security events'}), 500

@dashboard_bp.route('/training-status', methods=['GET'])
@jwt_required()
def get_training_status():
    """Get ML model training status"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify({
            'is_calibrated': user.is_calibrated,
            'model_version': user.model_version,
            'last_trained': user.model_last_trained.isoformat() if user.model_last_trained else None,
            'training_samples': user.model_training_samples,
            'monitoring_active': user.is_calibrated
        }), 200
        
    except Exception as e:
        logger.error(f"Training status error: {e}")
        return jsonify({'error': 'Failed to get training status'}), 500

def _get_recent_activity_stats(user_id):
    """Get recent activity statistics"""
    try:
        # Last 24 hours
        yesterday = datetime.now(timezone.utc) - timedelta(hours=24)
        
        # Count recent behavioral data points
        recent_data_count = BehavioralData.query.filter(
            BehavioralData.user_id == user_id,
            BehavioralData.timestamp >= yesterday
        ).count()
        
        # Count recent authentication events
        recent_auth_count = AuthenticationLog.query.filter(
            AuthenticationLog.user_id == user_id,
            AuthenticationLog.timestamp >= yesterday
        ).count()
        
        # Get last login
        last_login = AuthenticationLog.query.filter(
            AuthenticationLog.user_id == user_id,
            AuthenticationLog.event_type == 'login',
            AuthenticationLog.event_status == 'success'
        ).order_by(desc(AuthenticationLog.timestamp)).first()
        
        return {
            'data_points_24h': recent_data_count,
            'auth_events_24h': recent_auth_count,
            'last_login': last_login.timestamp.isoformat() if last_login else None,
            'session_duration': _calculate_session_duration(user_id)
        }
        
    except Exception as e:
        logger.error(f"Failed to get activity stats: {e}")
        return {}

def _process_analytics_data(behavioral_data):
    """Process behavioral data for dashboard analytics"""
    if not behavioral_data:
        return {
            'typing_speed_chart': [],
            'anomaly_summary': {'pass': 0, 'alert': 0, 'block': 0},
            'feature_deviations': []
        }
    
    # Typing speed over time
    typing_speed_data = []
    anomaly_counts = {'pass': 0, 'alert': 0, 'block': 0}
    
    for data in behavioral_data:
        timestamp = data.timestamp.isoformat()
        
        # Extract typing speed from keystroke features
        keystroke_features = data.keystroke_features_data
        typing_speed = keystroke_features.get('typing_speed_wpm', 0)
        
        typing_speed_data.append({
            'timestamp': timestamp,
            'typing_speed': typing_speed
        })
        
        # Categorize risk level
        if data.risk_level == 'low':
            anomaly_counts['pass'] += 1
        elif data.risk_level == 'medium':
            anomaly_counts['alert'] += 1
        else:
            anomaly_counts['block'] += 1
    
    # Feature deviation analysis (last 10 data points)
    recent_data = behavioral_data[-10:] if len(behavioral_data) >= 10 else behavioral_data
    feature_deviations = _analyze_feature_deviations(recent_data)
    
    return {
        'typing_speed_chart': typing_speed_data,
        'anomaly_summary': anomaly_counts,
        'feature_deviations': feature_deviations
    }

def _analyze_feature_deviations(recent_data):
    """Analyze feature deviations for bar chart"""
    if not recent_data:
        return []
    
    # Aggregate feature values
    feature_aggregates = {}
    for data in recent_data:
        features = {**data.keystroke_features_data, **data.mouse_features_data}
        for feature, value in features.items():
            if feature not in feature_aggregates:
                feature_aggregates[feature] = []
            feature_aggregates[feature].append(value)
    
    # Calculate deviation scores (simplified)
    deviations = []
    for feature, values in feature_aggregates.items():
        if len(values) > 1:
            mean_val = sum(values) / len(values)
            variance = sum((x - mean_val)**2 for x in values) / len(values)
            deviation_score = min(variance / (mean_val + 1e-10), 1.0)
            
            deviations.append({
                'feature': feature.replace('_', ' ').title(),
                'deviation': deviation_score
            })
    
    # Return top 10 deviations
    deviations.sort(key=lambda x: x['deviation'], reverse=True)
    return deviations[:10]

def _calculate_current_risk(user, recent_events):
    """Calculate current risk assessment"""
    current_risk = user.current_risk_score
    
    # Count recent anomalies
    anomaly_events = [e for e in recent_events if e.event_type == 'anomaly']
    challenge_events = [e for e in recent_events if e.event_type == 'challenge']
    
    # Risk level categorization
    if current_risk < 0.3:
        risk_level = 'Low'
        risk_color = 'green'
    elif current_risk < 0.6:
        risk_level = 'Medium'
        risk_color = 'yellow'
    elif current_risk < 0.8:
        risk_level = 'High'
        risk_color = 'orange'
    else:
        risk_level = 'Critical'
        risk_color = 'red'
    
    return {
        'current_risk_score': current_risk,
        'risk_level': risk_level,
        'risk_color': risk_color,
        'anomalies_24h': len(anomaly_events),
        'challenges_24h': len(challenge_events),
        'recommendations': _generate_risk_recommendations(current_risk, recent_events)
    }

def _generate_risk_recommendations(risk_score, recent_events):
    """Generate risk-based recommendations"""
    recommendations = []
    
    if risk_score > 0.7:
        recommendations.append("Consider updating your password")
        recommendations.append("Review recent login locations")
    
    failed_challenges = [e for e in recent_events if 
                        e.event_type == 'challenge' and e.challenge_result == 'failed']
    if len(failed_challenges) > 2:
        recommendations.append("Multiple challenge failures detected - consider recalibration")
    
    if risk_score < 0.3 and len(recent_events) < 5:
        recommendations.append("Your account security is excellent")
    
    return recommendations

def _calculate_session_duration(user_id):
    """Calculate current session duration"""
    try:
        # Find most recent login
        recent_login = AuthenticationLog.query.filter(
            AuthenticationLog.user_id == user_id,
            AuthenticationLog.event_type == 'login',
            AuthenticationLog.event_status == 'success'
        ).order_by(desc(AuthenticationLog.timestamp)).first()
        
        if recent_login:
            duration = datetime.now(timezone.utc) - recent_login.timestamp
            return int(duration.total_seconds())
        
        return 0
    except:
        return 0
