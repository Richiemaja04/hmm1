"""
Calibration API endpoints for initial behavioral profile creation
"""
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
import logging
from datetime import datetime, timezone
import uuid
import json

from app import db
from app.models.database import User, CalibrationSession, BehavioralData
from app.services.auth_service import AuthenticationService
from app.core.feature_extractor import BehavioralFeatureExtractor
from app.models.ml_models import BehavioralMLEnsemble
from app.utils.helpers import get_client_ip, get_user_agent
from app.utils.validators import validate_behavioral_data

logger = logging.getLogger(__name__)
calibration_bp = Blueprint('calibration', __name__)
auth_service = AuthenticationService()
feature_extractor = BehavioralFeatureExtractor()

@calibration_bp.route('/start', methods=['POST'])
@jwt_required()
def start_calibration():
    """Start a new calibration session"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        if user.is_calibrated:
            return jsonify({'error': 'User already calibrated'}), 400
        
        # Create new calibration session
        session_id = str(uuid.uuid4())
        calibration_session = CalibrationSession(
            user_id=user_id,
            session_id=session_id,
            total_tasks=5,  # Number of calibration tasks
            status='in_progress'
        )
        
        db.session.add(calibration_session)
        db.session.commit()
        
        # Generate calibration tasks
        tasks = _generate_calibration_tasks()
        calibration_session.task_data_parsed = tasks
        db.session.commit()
        
        logger.info(f"Calibration session started for user {user_id}")
        
        return jsonify({
            'session_id': session_id,
            'tasks': tasks,
            'current_task': 0,
            'total_tasks': len(tasks)
        }), 200
        
    except Exception as e:
        logger.error(f"Calibration start error: {e}")
        db.session.rollback()
        return jsonify({'error': 'Failed to start calibration'}), 500

@calibration_bp.route('/submit-data', methods=['POST'])
@jwt_required()
def submit_calibration_data():
    """Submit behavioral data for a calibration task"""
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        
        session_id = data.get('session_id')
        task_index = data.get('task_index')
        keystroke_events = data.get('keystroke_events', [])
        mouse_events = data.get('mouse_events', [])
        
        if not session_id:
            return jsonify({'error': 'Session ID required'}), 400
        
        # Find calibration session
        calibration_session = CalibrationSession.query.filter_by(
            user_id=user_id,
            session_id=session_id,
            status='in_progress'
        ).first()
        
        if not calibration_session:
            return jsonify({'error': 'Calibration session not found'}), 404
        
        # Validate behavioral data
        if not validate_behavioral_data(keystroke_events, mouse_events):
            return jsonify({'error': 'Invalid behavioral data'}), 400
        
        # Extract features
        keystroke_features = feature_extractor.extract_keystroke_features(keystroke_events)
        mouse_features = feature_extractor.extract_mouse_features(mouse_events)
        
        # Store behavioral data
        behavioral_data = BehavioralData(
            user_id=user_id,
            session_id=session_id,
            data_type='calibration',
            window_duration=30.0,  # 30-second window
            keystroke_events_data=keystroke_events,
            mouse_events_data=mouse_events,
            keystroke_features_data=keystroke_features,
            mouse_features_data=mouse_features
        )
        
        db.session.add(behavioral_data)
        
        # Update calibration session
        calibration_session.completed_tasks += 1
        calibration_session.keystroke_samples += len(keystroke_events)
        calibration_session.mouse_samples += len(mouse_events)
        
        # Calculate data quality
        data_quality = _assess_calibration_data_quality(keystroke_events, mouse_events)
        calibration_session.data_quality_score = (
            (calibration_session.data_quality_score * (calibration_session.completed_tasks - 1) + data_quality) /
            calibration_session.completed_tasks
        )
        
        db.session.commit()
        
        # Check if calibration is complete
        is_complete = calibration_session.completed_tasks >= calibration_session.total_tasks
        has_sufficient_data = (
            calibration_session.keystroke_samples >= 100 and 
            calibration_session.mouse_samples >= 200 and
            calibration_session.data_quality_score >= 0.7
        )
        
        response_data = {
            'task_completed': True,
            'completed_tasks': calibration_session.completed_tasks,
            'total_tasks': calibration_session.total_tasks,
            'progress': (calibration_session.completed_tasks / calibration_session.total_tasks) * 100,
            'data_quality': data_quality
        }
        
        if is_complete:
            if has_sufficient_data:
                # Mark session as ready for training
                calibration_session.status = 'completed'
                calibration_session.sufficient_data = True
                calibration_session.completed_at = datetime.now(timezone.utc)
                
                # Trigger model training (asynchronous)
                _trigger_model_training(user_id, session_id)
                
                response_data.update({
                    'calibration_complete': True,
                    'training_started': True,
                    'message': 'Calibration complete. Training models...'
                })
            else:
                response_data.update({
                    'calibration_complete': False,
                    'needs_more_data': True,
                    'message': 'Need more data for reliable calibration'
                })
        
        db.session.commit()
        
        logger.info(f"Calibration data submitted for user {user_id}, task {task_index}")
        
        return jsonify(response_data), 200
        
    except Exception as e:
        logger.error(f"Calibration data submission error: {e}")
        db.session.rollback()
        return jsonify({'error': 'Failed to submit calibration data'}), 500

@calibration_bp.route('/status/<session_id>', methods=['GET'])
@jwt_required()
def get_calibration_status(session_id):
    """Get calibration session status"""
    try:
        user_id = get_jwt_identity()
        
        calibration_session = CalibrationSession.query.filter_by(
            user_id=user_id,
            session_id=session_id
        ).first()
        
        if not calibration_session:
            return jsonify({'error': 'Calibration session not found'}), 404
        
        response_data = {
            'session_id': session_id,
            'status': calibration_session.status,
            'completed_tasks': calibration_session.completed_tasks,
            'total_tasks': calibration_session.total_tasks,
            'progress': calibration_session.progress_percentage,
            'data_quality': calibration_session.data_quality_score,
            'training_status': calibration_session.model_training_status
        }
        
        # Add training completion info if available
        if calibration_session.model_training_status == 'completed':
            user = User.query.get(user_id)
            response_data.update({
                'training_complete': True,
                'user_calibrated': user.is_calibrated,
                'model_accuracy': calibration_session.model_accuracy
            })
        
        return jsonify(response_data), 200
        
    except Exception as e:
        logger.error(f"Calibration status error: {e}")
        return jsonify({'error': 'Failed to get calibration status'}), 500

def _generate_calibration_tasks():
    """Generate calibration tasks for user"""
    tasks = [
        {
            'type': 'typing',
            'title': 'Typing Sample 1',
            'instruction': 'Please type the following text naturally:',
            'text': 'The quick brown fox jumps over the lazy dog. This sentence contains every letter of the alphabet.',
            'min_duration': 30
        },
        {
            'type': 'typing',
            'title': 'Typing Sample 2', 
            'instruction': 'Type this passage at your normal speed:',
            'text': 'Behavioral biometrics analyze the unique patterns in how individuals interact with devices. These patterns include typing rhythm, mouse movements, and other behavioral characteristics.',
            'min_duration': 45
        },
        {
            'type': 'mixed',
            'title': 'Navigation Task',
            'instruction': 'Click on the buttons below in the order shown, then type your name:',
            'text': 'Please enter your full name after completing the clicking sequence.',
            'min_duration': 30
        },
        {
            'type': 'typing',
            'title': 'Free Text',
            'instruction': 'Write a short paragraph about your favorite hobby or interest:',
            'text': '',
            'min_duration': 60
        },
        {
            'type': 'mixed',
            'title': 'Final Sample',
            'instruction': 'Complete this final task by typing and using mouse interactions:',
            'text': 'Authentication systems are becoming more sophisticated with the integration of behavioral biometrics.',
            'min_duration': 40
        }
    ]
    
    return tasks

def _assess_calibration_data_quality(keystroke_events, mouse_events):
    """Assess quality of calibration data"""
    quality_score = 1.0
    
    # Check minimum event counts
    if len(keystroke_events) < 20:
        quality_score *= 0.7
    if len(mouse_events) < 50:
        quality_score *= 0.8
    
    # Check for temporal distribution
    if keystroke_events:
        timestamps = [event.get('timestamp') for event in keystroke_events]
        if timestamps and len(set(timestamps)) < len(timestamps) * 0.8:
            quality_score *= 0.6  # Too many duplicate timestamps
    
    # Check for realistic values
    for event in keystroke_events:
        if event.get('type') == 'keydown' and len(event.get('key', '')) > 20:
            quality_score *= 0.9  # Suspicious key values
    
    return max(0.0, min(1.0, quality_score))

def _trigger_model_training(user_id, session_id):
    """Trigger asynchronous model training"""
    # In a production system, this would use a task queue like Celery
    # For now, we'll simulate the training process
    try:
        from threading import Thread
        thread = Thread(target=_train_user_models, args=(user_id, session_id))
        thread.daemon = True
        thread.start()
        logger.info(f"Model training thread started for user {user_id}")
    except Exception as e:
        logger.error(f"Failed to start model training: {e}")

def _train_user_models(user_id, session_id):
    """Train ML models for user (runs in background)"""
    try:
        # Get calibration data
        behavioral_data = BehavioralData.query.filter_by(
            user_id=user_id,
            session_id=session_id
        ).all()
        
        if not behavioral_data:
            logger.error(f"No calibration data found for user {user_id}")
            return
        
        # Prepare training data
        training_features = []
        for data in behavioral_data:
            features = {**data.keystroke_features_data, **data.mouse_features_data}
            feature_array = list(features.values())
            training_features.append(feature_array)
        
        # Train models
        ml_ensemble = BehavioralMLEnsemble()
        training_results = ml_ensemble.train(training_features)
        
        # Update database
        with db.app.app_context():
            user = User.query.get(user_id)
            calibration_session = CalibrationSession.query.filter_by(
                user_id=user_id,
                session_id=session_id
            ).first()
            
            if user and calibration_session:
                # Mark user as calibrated
                user.is_calibrated = True
                user.model_last_trained = datetime.now(timezone.utc)
                user.model_training_samples = len(training_features)
                
                # Update calibration session
                calibration_session.model_training_status = 'completed'
                calibration_session.training_completion_time = datetime.now(timezone.utc)
                calibration_session.model_accuracy = training_results.get('ensemble_trained', False)
                
                # Save baseline statistics
                _save_user_baseline(user_id, behavioral_data)
                
                db.session.commit()
                logger.info(f"Model training completed for user {user_id}")
        
    except Exception as e:
        logger.error(f"Model training failed for user {user_id}: {e}")
        # Update status to failed
        try:
            with db.app.app_context():
                calibration_session = CalibrationSession.query.filter_by(
                    user_id=user_id,
                    session_id=session_id
                ).first()
                if calibration_session:
                    calibration_session.model_training_status = 'failed'
                    db.session.commit()
        except:
            pass

def _save_user_baseline(user_id, behavioral_data):
    """Save user baseline statistics"""
    try:
        # Aggregate features from all calibration data
        keystroke_features = {}
        mouse_features = {}
        
        for data in behavioral_data:
            for feature, value in data.keystroke_features_data.items():
                if feature not in keystroke_features:
                    keystroke_features[feature] = []
                keystroke_features[feature].append(value)
            
            for feature, value in data.mouse_features_data.items():
                if feature not in mouse_features:
                    mouse_features[feature] = []
                mouse_features[feature].append(value)
        
        # Calculate statistics
        keystroke_baseline = {}
        for feature, values in keystroke_features.items():
            keystroke_baseline[feature] = {
                'mean': float(sum(values) / len(values)),
                'std': float((sum((x - sum(values)/len(values))**2 for x in values) / len(values))**0.5),
                'count': len(values)
            }
        
        mouse_baseline = {}
        for feature, values in mouse_features.items():
            mouse_baseline[feature] = {
                'mean': float(sum(values) / len(values)),
                'std': float((sum((x - sum(values)/len(values))**2 for x in values) / len(values))**0.5),
                'count': len(values)
            }
        
        # Save to user
        user = User.query.get(user_id)
        user.keystroke_baseline_data = keystroke_baseline
        user.mouse_baseline_data = mouse_baseline
        db.session.commit()
        
        logger.info(f"Baseline statistics saved for user {user_id}")
        
    except Exception as e:
        logger.error(f"Failed to save baseline for user {user_id}: {e}")
