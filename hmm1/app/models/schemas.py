"""
Pydantic schemas for API request/response validation
"""
from pydantic import BaseModel, validator, Field
from typing import Optional, List, Dict, Any, Union
from datetime import datetime
from enum import Enum

class UserRole(str, Enum):
    USER = "user"
    ADMIN = "admin"

class EventType(str, Enum):
    KEYDOWN = "keydown"
    KEYUP = "keyup"
    MOUSEMOVE = "mousemove"
    CLICK = "click"
    MOUSEDOWN = "mousedown"
    MOUSEUP = "mouseup"
    WHEEL = "wheel"

class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

# Request Schemas
class UserRegistrationRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=30)
    email: str = Field(..., min_length=5, max_length=254)
    password: str = Field(..., min_length=8, max_length=128)
    
    @validator('username')
    def validate_username(cls, v):
        import re
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError('Username can only contain letters, numbers, underscores, and hyphens')
        return v
    
    @validator('email')
    def validate_email(cls, v):
        from app.utils.validators import validate_email
        if not validate_email(v):
            raise ValueError('Invalid email format')
        return v.lower()
    
    @validator('password')
    def validate_password(cls, v):
        from app.utils.validators import validate_password
        if not validate_password(v):
            raise ValueError('Password must be at least 8 characters with uppercase, lowercase, and number')
        return v

class UserLoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=254)
    password: str = Field(..., min_length=1, max_length=128)

class KeystrokeEvent(BaseModel):
    type: EventType
    key: str = Field(..., max_length=50)
    timestamp: Union[str, float, datetime]
    keyCode: Optional[int] = None
    ctrlKey: Optional[bool] = False
    shiftKey: Optional[bool] = False
    altKey: Optional[bool] = False
    metaKey: Optional[bool] = False

class MouseEvent(BaseModel):
    type: EventType
    timestamp: Union[str, float, datetime]
    clientX: Optional[float] = None
    clientY: Optional[float] = None
    button: Optional[int] = None
    deltaX: Optional[float] = None
    deltaY: Optional[float] = None
    deltaZ: Optional[float] = None

class BehavioralDataSubmission(BaseModel):
    session_id: str = Field(..., min_length=10, max_length=100)
    window_duration: float = Field(default=30.0, ge=1.0, le=300.0)
    keystroke_events: List[KeystrokeEvent] = Field(default_factory=list)
    mouse_events: List[MouseEvent] = Field(default_factory=list)
    
    @validator('keystroke_events')
    def validate_keystroke_events(cls, v):
        if len(v) > 1000:  # Reasonable limit
            raise ValueError('Too many keystroke events')
        return v
    
    @validator('mouse_events')
    def validate_mouse_events(cls, v):
        if len(v) > 5000:  # Reasonable limit
            raise ValueError('Too many mouse events')
        return v

class CalibrationDataSubmission(BaseModel):
    session_id: str = Field(..., min_length=10, max_length=100)
    task_index: int = Field(..., ge=0, le=20)
    keystroke_events: List[KeystrokeEvent] = Field(default_factory=list)
    mouse_events: List[MouseEvent] = Field(default_factory=list)
    task_completion_time: Optional[float] = Field(default=None, ge=0)

class ChallengeInitiationRequest(BaseModel):
    challenge_type: str = Field(default="verification", regex=r'^(verification|adaptive|high_risk)$')
    trigger_reason: str = Field(default="manual", max_length=100)

class ChallengeSubmissionRequest(BaseModel):
    challenge_id: str = Field(..., min_length=10, max_length=100)
    text_content: str = Field(..., max_length=2000)
    keystroke_events: List[KeystrokeEvent] = Field(default_factory=list)
    mouse_events: List[MouseEvent] = Field(default_factory=list)

# Response Schemas
class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    is_active: bool
    is_calibrated: bool
    created_at: Optional[datetime]
    last_login: Optional[datetime]
    model_version: Optional[int]
    current_risk_score: float

class AuthenticationResponse(BaseModel):
    message: str
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    user: Optional[UserResponse] = None
    session_id: Optional[str] = None
    requires_calibration: bool = False
    redirect: Optional[str] = None

class CalibrationTask(BaseModel):
    type: str
    title: str
    instruction: str
    text: str
    min_duration: int

class CalibrationStatusResponse(BaseModel):
    session_id: str
    status: str
    completed_tasks: int
    total_tasks: int
    progress: float
    data_quality: float
    training_status: str
    training_complete: Optional[bool] = None
    user_calibrated: Optional[bool] = None
    model_accuracy: Optional[float] = None

class BehavioralAnalysisResult(BaseModel):
    timestamp: datetime
    anomaly_score: float
    confidence: float
    risk_level: RiskLevel
    threat_level: str
    action_required: str
    is_anomaly: bool
    data_quality: float
    challenge_type: Optional[str] = None
    challenge_reason: Optional[str] = None
    drift_detected: Optional[bool] = None
    drift_severity: Optional[str] = None
    retraining_required: Optional[bool] = None

class SecurityEvent(BaseModel):
    id: int
    timestamp: datetime
    event_type: str
    event_status: str
    risk_score: Optional[float]
    action_taken: Optional[str]
    ip_address: Optional[str]
    metadata: Optional[Dict[str, Any]]

class AnalyticsData(BaseModel):
    current_session: Dict[str, Any]
    typing_pattern: Dict[str, float]
    mouse_pattern: Dict[str, float]
    risk_trend: Dict[str, Any]
    anomaly_summary: Dict[str, Any]

class ChallengeResponse(BaseModel):
    challenge_id: str
    challenge_type: str
    content: Dict[str, Any]
    expires_at: datetime
    max_attempts: int

class ChallengeVerificationResult(BaseModel):
    result: str  # passed, failed, inconclusive
    confidence: float
    reason: str
    details: Optional[Dict[str, Any]] = None

class NotificationResponse(BaseModel):
    type: str
    data: Dict[str, Any]
    timestamp: datetime

class ErrorResponse(BaseModel):
    error: str
    message: Optional[str] = None
    details: Optional[Dict[str, Any]] = None

# WebSocket Message Schemas
class WebSocketMessage(BaseModel):
    type: str
    data: Optional[Dict[str, Any]] = None
    timestamp: Optional[datetime] = None

class BehavioralDataMessage(WebSocketMessage):
    type: str = "behavioral_data"
    data: BehavioralDataSubmission

class AnalysisResultMessage(WebSocketMessage):
    type: str = "analysis_result"
    data: BehavioralAnalysisResult

class NotificationMessage(WebSocketMessage):
    type: str = "notification"
    data: NotificationResponse

class ChallengeRequiredMessage(WebSocketMessage):
    type: str = "challenge_required"
    data: Dict[str, str]  # challenge_type, reason, redirect_url

class SessionBlockedMessage(WebSocketMessage):
    type: str = "session_blocked"
    data: Dict[str, str]  # reaso