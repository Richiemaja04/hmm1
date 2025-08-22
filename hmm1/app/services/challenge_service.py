# ==========================================
# app/services/challenge_service.py
"""
Challenge service for security verification
"""
import logging
import secrets
import random
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone, timedelta
import uuid

from app.core.feature_extractor import BehavioralFeatureExtractor
from app.models.ml_models import BehavioralMLEnsemble

logger = logging.getLogger(__name__)

class ChallengeService:
    """Service for managing security challenges"""
    
    def __init__(self):
        self.feature_extractor = BehavioralFeatureExtractor()
        self.active_challenges = {}  # In production, use Redis or database
        self.challenge_texts = self._load_challenge_texts()
        
    def create_challenge(self, user_id: int, challenge_type: str, 
                        trigger_reason: str) -> Dict[str, Any]:
        """Create a new security challenge"""
        try:
            challenge_id = str(uuid.uuid4())
            
            # Generate challenge content
            challenge_content = self._generate_challenge_content(challenge_type)
            
            # Create challenge record
            challenge_data = {
                'challenge_id': challenge_id,
                'user_id': user_id,
                'challenge_type': challenge_type,
                'trigger_reason': trigger_reason,
                'content': challenge_content,
                'created_at': datetime.now(timezone.utc),
                'expires_at': datetime.now(timezone.utc) + timedelta(minutes=10),
                'status': 'active',
                'attempts': 0,
                'max_attempts': 3
            }
            
            self.active_challenges[challenge_id] = challenge_data
            
            logger.info(f"Challenge created for user {user_id}: {challenge_type}")
            
            return {
                'challenge_id': challenge_id,
                'challenge_type': challenge_type,
                'content': challenge_content,
                'expires_at': challenge_data['expires_at'].isoformat(),
                'max_attempts': challenge_data['max_attempts']
            }
            
        except Exception as e:
            logger.error(f"Challenge creation error: {e}")
            raise
    
    def verify_challenge_response(self, challenge_id: str, text_content: str,
                                keystroke_features: Dict[str, float],
                                mouse_features: Dict[str, float]) -> Dict[str, Any]:
        """Verify challenge response using behavioral analysis"""
        try:
            challenge = self.active_challenges.get(challenge_id)
            
            if not challenge:
                return {'result': 'failed', 'reason': 'challenge_not_found'}
            
            if challenge['status'] != 'active':
                return {'result': 'failed', 'reason': 'challenge_inactive'}
            
            if datetime.now(timezone.utc) > challenge['expires_at']:
                challenge['status'] = 'expired'
                return {'result': 'failed', 'reason': 'challenge_expired'}
            
            # Increment attempts
            challenge['attempts'] += 1
            
            # Check max attempts
            if challenge['attempts'] > challenge['max_attempts']:
                challenge['status'] = 'failed'
                return {'result': 'failed', 'reason': 'max_attempts_exceeded'}
            
            # Verify text content
            text_match = self._verify_text_content(challenge, text_content)
            
            # Verify behavioral characteristics
            behavioral_match = self._verify_behavioral_characteristics(
                challenge['user_id'], keystroke_features, mouse_features
            )
            
            # Combine verification results
            overall_confidence = (text_match['confidence'] + behavioral_match['confidence']) / 2
            
            if text_match['passed'] and behavioral_match['passed'] and overall_confidence > 0.7:
                challenge['status'] = 'completed'
                result = 'passed'
                reason = 'verification_successful'
            elif overall_confidence > 0.4:
                result = 'inconclusive'
                reason = 'insufficient_confidence'
            else:
                result = 'failed'
                reason = 'verification_failed'
            
            logger.info(f"Challenge {challenge_id} result: {result} (confidence: {overall_confidence:.2f})")
            
            return {
                'result': result,
                'confidence': overall_confidence,
                'reason': reason,
                'details': {
                    'text_verification': text_match,
                    'behavioral_verification': behavioral_match,
                    'attempts_remaining': challenge['max_attempts'] - challenge['attempts']
                }
            }
            
        except Exception as e:
            logger.error(f"Challenge verification error: {e}")
            return {'result': 'failed', 'reason': 'verification_error'}
    
    def get_challenge(self, challenge_id: str) -> Optional[Dict[str, Any]]:
        """Get challenge by ID"""
        return self.active_challenges.get(challenge_id)
    
    def generate_challenge_text(self, challenge_type: str) -> Dict[str, str]:
        """Generate challenge text based on type"""
        try:
            if challenge_type == 'verification':
                texts = self.challenge_texts['verification']
                selected_text = random.choice(texts)
                
                return {
                    'text': selected_text,
                    'instruction': 'Please type the following text exactly as shown:',
                    'type': 'verification'
                }
            
            elif challenge_type == 'adaptive':
                texts = self.challenge_texts['adaptive']
                selected_text = random.choice(texts)
                
                return {
                    'text': selected_text,
                    'instruction': 'Please copy the following paragraph to help us adapt to your typing style:',
                    'type': 'adaptive'
                }
            
            elif challenge_type == 'high_risk':
                texts = self.challenge_texts['high_risk']
                selected_text = random.choice(texts)
                
                return {
                    'text': selected_text,
                    'instruction': 'Security verification required. Please type the following text:',
                    'type': 'high_risk'
                }
            
            else:
                # Default to simple verification
                return {
                    'text': 'Please verify your identity by typing this sentence.',
                    'instruction': 'Type the following text:',
                    'type': 'simple'
                }
                
        except Exception as e:
            logger.error(f"Challenge text generation error: {e}")
            return {
                'text': 'Please verify your identity.',
                'instruction': 'Type the following text:',
                'type': 'simple'
            }
    
    def _generate_challenge_content(self, challenge_type: str) -> Dict[str, Any]:
        """Generate complete challenge content"""
        text_data = self.generate_challenge_text(challenge_type)
        
        return {
            'text': text_data['text'],
            'instruction': text_data['instruction'],
            'type': challenge_type,
            'expected_min_length': len(text_data['text']) * 0.8,
            'expected_max_length': len(text_data['text']) * 1.2
        }
    
    def _verify_text_content(self, challenge: Dict[str, Any], 
                           submitted_text: str) -> Dict[str, Any]:
        """Verify submitted text content"""
        expected_text = challenge['content']['text']
        
        # Calculate similarity
        similarity = self._calculate_text_similarity(expected_text, submitted_text)
        
        # Check length
        length_ratio = len(submitted_text) / len(expected_text)
        length_acceptable = 0.8 <= length_ratio <= 1.2
        
        # Determine if passed
        passed = similarity > 0.8 and length_acceptable
        confidence = similarity * (1.0 if length_acceptable else 0.7)
        
        return {
            'passed': passed,
            'confidence': confidence,
            'similarity': similarity,
            'length_ratio': length_ratio
        }
    
    def _verify_behavioral_characteristics(self, user_id: int,
                                         keystroke_features: Dict[str, float],
                                         mouse_features: Dict[str, float]) -> Dict[str, Any]:
        """Verify behavioral characteristics against user profile"""
        try:
            # In production, load user's trained model
            # For now, use simplified verification
            
            # Check for reasonable feature values
            reasonable_features = True
            confidence_factors = []
            
            # Keystroke feature validation
            typing_speed = keystroke_features.get('typing_speed_wpm', 0)
            if 10 <= typing_speed <= 200:  # Reasonable WPM range
                confidence_factors.append(0.8)
            else:
                reasonable_features = False
                confidence_factors.append(0.3)
            
            # Mouse feature validation
            mouse_speed = mouse_features.get('avg_mouse_speed', 0)
            if 0 <= mouse_speed <= 1000:  # Reasonable mouse speed
                confidence_factors.append(0.7)
            else:
                reasonable_features = False
                confidence_factors.append(0.2)
            
            overall_confidence = sum(confidence_factors) / len(confidence_factors)
            
            return {
                'passed': reasonable_features and overall_confidence > 0.6,
                'confidence': overall_confidence,
                'details': {
                    'typing_speed_valid': 10 <= typing_speed <= 200,
                    'mouse_pattern_valid': 0 <= mouse_speed <= 1000
                }
            }
            
        except Exception as e:
            logger.error(f"Behavioral verification error: {e}")
            return {'passed': False, 'confidence': 0.0, 'error': str(e)}
    
    def _calculate_text_similarity(self, expected: str, submitted: str) -> float:
        """Calculate similarity between expected and submitted text"""
        try:
            expected_lower = expected.lower().strip()
            submitted_lower = submitted.lower().strip()
            
            # Simple character-based similarity
            if not expected_lower or not submitted_lower:
                return 0.0
            
            # Levenshtein distance approximation
            matches = sum(1 for a, b in zip(expected_lower, submitted_lower) if a == b)
            max_length = max(len(expected_lower), len(submitted_lower))
            
            similarity = matches / max_length if max_length > 0 else 0.0
            
            return min(similarity, 1.0)
            
        except Exception as e:
            logger.error(f"Text similarity calculation error: {e}")
            return 0.0
    
    def _load_challenge_texts(self) -> Dict[str, List[str]]:
        """Load challenge text templates"""
        return {
            'verification': [
                'The quick brown fox jumps over the lazy dog.',
                'Authentication systems protect digital resources from unauthorized access.',
                'Behavioral biometrics analyze unique user interaction patterns.',
                'Security challenges verify user identity through typing patterns.',
                'Continuous authentication monitors user behavior in real-time.'
            ],
            'adaptive': [
                'Behavioral biometrics represent a significant advancement in cybersecurity technology. By analyzing unique patterns in how users interact with their devices, these systems can provide continuous authentication without interrupting normal workflow. The technology examines keystroke dynamics, mouse movements, and other behavioral characteristics to create a unique digital fingerprint for each user.',
                'Machine learning algorithms play a crucial role in modern authentication systems. These algorithms can detect subtle changes in user behavior that might indicate unauthorized access or security threats. By continuously learning and adapting to user patterns, these systems become more accurate over time while reducing false positive alerts.',
                'The future of cybersecurity lies in adaptive and intelligent systems that can respond to emerging threats in real-time. Traditional static authentication methods are being replaced by dynamic systems that monitor user behavior continuously and can detect anomalies or potential security breaches as they occur.'
            ],
            'high_risk': [
                'SECURITY VERIFICATION REQUIRED: Please type this exact message to confirm your identity.',
                'HIGH RISK ACTIVITY DETECTED: Confirm your identity by typing this security phrase.',
                'AUTHENTICATION CHALLENGE: Type this message to verify you are the authorized user.',
                'SECURITY ALERT: Please confirm your identity by accurately typing this verification text.'
            ]
        }