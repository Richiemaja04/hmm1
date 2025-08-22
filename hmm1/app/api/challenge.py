# ==========================================
# app/api/challenge.py
"""
Challenge API endpoints for reactive security verification
"""
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
import logging
from datetime import datetime, timezone
import secrets
import uuid

from app import db
from app.models.database import User, AuthenticationLog
from app.services.challenge_service import ChallengeService
from app.core.feature_extractor import BehavioralFeatureExtractor
from app.utils.helpers import get_client_ip, get_user_agent
from app.utils.validators import validate_behavioral_data

logger = logging.getLogger(__name__)
challenge_bp = Blueprint('challenge', __name__)
challenge_service = ChallengeService()
feature_extractor = BehavioralFeatureExtractor()

@challenge_bp.route('/initiate', methods=['POST'])
@jwt_required()
def initiate_challenge():
    """Initiate a security challenge"""
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        
        challenge_type = data.get('challenge_type', 'verification')
        trigger_reason = data.get('trigger_reason', 'manual')
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Generate challenge
        challenge_data = challenge_service.create_challenge(
            user_id=user_id,
            challenge_type=challenge_type,
            trigger_reason=trigger_reason
        )
        
        # Log challenge initiation
        auth_log = AuthenticationLog(
            user_id=user_id,
            event_type='challenge',
            event_status='initiated',
            ip_address=get_client_ip(request),
            user_agent=get_user_agent(request),
            metadata_data={
                'challenge_type': challenge_type,
                'trigger_reason': trigger_reason,
                'challenge_id': challenge_data['challenge_id']
            }
        )
        db.session.add(auth_log)
        db.session.commit()
        
        logger.info(f"Challenge initiated for user {user_id}: {challenge_type}")
        
        return jsonify(challenge_data), 200
        
    except Exception as e:
        logger.error(f"Challenge initiation error: {e}")
        return jsonify({'error': 'Failed to initiate challenge'}), 500

@challenge_bp.route('/submit', methods=['POST'])
@jwt_required()
def submit_challenge_response():
    """Submit challenge response with behavioral data"""
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        
        challenge_id = data.get('challenge_id')
        text_content = data.get('text_content', '')
        keystroke_events = data.get('keystroke_events', [])
        mouse_events = data.get('mouse_events', [])
        
        if not challenge_id:
            return jsonify({'error': 'Challenge ID required'}), 400
        
        # Validate challenge
        challenge = challenge_service.get_challenge(challenge_id)
        if not challenge or challenge['user_id'] != user_id:
            return jsonify({'error': 'Invalid challenge'}), 404
        
        if challenge['status'] != 'active':
            return jsonify({'error': 'Challenge not active'}), 400
        
        # Validate behavioral data
        if not validate_behavioral_data(keystroke_events, mouse_events):
            return jsonify({'error': 'Invalid behavioral data'}), 400
        
        # Extract features
        keystroke_features = feature_extractor.extract_keystroke_features(keystroke_events)
        mouse_features = feature_extractor.extract_mouse_features(mouse_events)
        
        # Verify challenge response
        verification_result = challenge_service.verify_challenge_response(
            challenge_id=challenge_id,
            text_content=text_content,
            keystroke_features=keystroke_features,
            mouse_features=mouse_features
        )
        
        # Log challenge result
        auth_log = AuthenticationLog(
            user_id=user_id,
            event_type='challenge',
            event_status='completed',
            challenge_result=verification_result['result'],
            confidence_score=verification_result['confidence'],
            ip_address=get_client_ip(request),
            user_agent=get_user_agent(request),
            metadata_data={
                'challenge_id': challenge_id,
                'challenge_type': challenge['challenge_type'],
                'verification_details': verification_result.get('details', {})
            }
        )
        db.session.add(auth_log)
        db.session.commit()
        
        # Handle challenge result
        if verification_result['result'] == 'passed':
            # Update user risk score
            user = User.query.get(user_id)
            user.current_risk_score = max(0, user.current_risk_score - 0.1)
            db.session.commit()
            
            response_data = {
                'result': 'passed',
                'message': 'Challenge completed successfully',
                'redirect': '/dashboard'
            }
        elif verification_result['result'] == 'failed':
            # Increment risk and check for lockout
            user = User.query.get(user_id)
            user.current_risk_score = min(1.0, user.current_risk_score + 0.2)
            
            # Check if user should be locked out
            failed_challenges_count = _count_recent_failed_challenges(user_id)
            if failed_challenges_count >= 3:
                user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=15)
                response_data = {
                    'result': 'failed',
                    'message': 'Too many failed challenges. Account temporarily locked.',
                    'action': 'logout'
                }
            else:
                response_data = {
                    'result': 'failed',
                    'message': f'Challenge failed. {3 - failed_challenges_count} attempts remaining.',
                    'action': 'retry'
                }
            
            db.session.commit()
        else:
            response_data = {
                'result': 'inconclusive',
                'message': 'Challenge result unclear. Please try again.',
                'action': 'retry'
            }
        
        logger.info(f"Challenge {challenge_id} completed by user {user_id}: {verification_result['result']}")
        
        return jsonify(response_data), 200
        
    except Exception as e:
        logger.error(f"Challenge submission error: {e}")
        db.session.rollback()
        return jsonify({'error': 'Failed to submit challenge response'}), 500

@challenge_bp.route('/generate-text', methods=['POST'])
@jwt_required()
def generate_challenge_text():
    """Generate challenge text based on type"""
    try:
        data = request.get_json()
        challenge_type = data.get('challenge_type', 'verification')
        
        text_data = challenge_service.generate_challenge_text(challenge_type)
        
        return jsonify(text_data), 200
        
    except Exception as e:
        logger.error(f"Challenge text generation error: {e}")
        return jsonify({'error': 'Failed to generate challenge text'}), 500

@challenge_bp.route('/status/<challenge_id>', methods=['GET'])
@jwt_required()
def get_challenge_status(challenge_id):
    """Get challenge status"""
    try:
        user_id = get_jwt_identity()
        
        challenge = challenge_service.get_challenge(challenge_id)
        if not challenge or challenge['user_id'] != user_id:
            return jsonify({'error': 'Challenge not found'}), 404
        
        return jsonify({
            'challenge_id': challenge_id,
            'status': challenge['status'],
            'challenge_type': challenge['challenge_type'],
            'created_at': challenge['created_at'],
            'expires_at': challenge['expires_at']
        }), 200
        
    except Exception as e:
        logger.error(f"Challenge status error: {e}")
        return jsonify({'error': 'Failed to get challenge status'}), 500

def _count_recent_failed_challenges(user_id):
    """Count recent failed challenges for user"""
    try:
        recent_time = datetime.now(timezone.utc) - timedelta(hours=1)
        
        failed_count = AuthenticationLog.query.filter(
            AuthenticationLog.user_id == user_id,
            AuthenticationLog.event_type == 'challenge',
            AuthenticationLog.challenge_result == 'failed',
            AuthenticationLog.timestamp >= recent_time
        ).count()
        
        return failed_count
    except:
        return 0