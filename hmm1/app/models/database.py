# ==========================================
# app/models/database.py
"""
SQLAlchemy database models for the authentication agent
"""
import json
from datetime import datetime, timezone
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.ext.hybrid import hybrid_property
from app import db

class User(db.Model):
    """User model with authentication and behavioral profile data"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    
    # User status and security
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    is_calibrated = db.Column(db.Boolean, default=False, nullable=False)
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime(timezone=True), nullable=True)
    
    # Timestamps
    created_at = db.Column(db.DateTime(timezone=True), default=datetime.now(timezone.utc))
    last_login = db.Column(db.DateTime(timezone=True), nullable=True)
    last_activity = db.Column(db.DateTime(timezone=True), nullable=True)
    
    # ML Model metadata
    model_version = db.Column(db.Integer, default=1)
    model_last_trained = db.Column(db.DateTime(timezone=True), nullable=True)
    model_training_samples = db.Column(db.Integer, default=0)
    
    # Behavioral baseline statistics (JSON stored)
    keystroke_baseline = db.Column(db.Text, nullable=True)  # JSON
    mouse_baseline = db.Column(db.Text, nullable=True)      # JSON
    
    # Risk assessment
    current_risk_score = db.Column(db.Float, default=0.0)
    anomaly_count_24h = db.Column(db.Integer, default=0)
    
    # Relationships
    behavioral_data = db.relationship('BehavioralData', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    auth_logs = db.relationship('AuthenticationLog', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    calibration_sessions = db.relationship('CalibrationSession', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    
    def set_password(self, password):
        """Hash and set user password"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Check if provided password matches stored hash"""
        return check_password_hash(self.password_hash, password)
    
    def is_locked(self):
        """Check if user account is currently locked"""
        if self.locked_until is None:
            return False
        return datetime.now(timezone.utc) < self.locked_until
    
    def increment_failed_attempts(self):
        """Increment failed login attempts and lock if necessary"""
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 5:  # Configure this threshold
            from datetime import timedelta
            self.locked_until = datetime.now(timezone.utc) + timedelta(minutes=30)
    
    def reset_failed_attempts(self):
        """Reset failed login attempts on successful login"""
        self.failed_login_attempts = 0
        self.locked_until = None
        self.last_login = datetime.now(timezone.utc)
    
    @hybrid_property
    def keystroke_baseline_data(self):
        """Parse keystroke baseline JSON"""
        if self.keystroke_baseline:
            return json.loads(self.keystroke_baseline)
        return {}
    
    @keystroke_baseline_data.setter
    def keystroke_baseline_data(self, value):
        """Set keystroke baseline as JSON"""
        self.keystroke_baseline = json.dumps(value) if value else None
    
    @hybrid_property
    def mouse_baseline_data(self):
        """Parse mouse baseline JSON"""
        if self.mouse_baseline:
            return json.loads(self.mouse_baseline)
        return {}
    
    @mouse_baseline_data.setter
    def mouse_baseline_data(self, value):
        """Set mouse baseline as JSON"""
        self.mouse_baseline = json.dumps(value) if value else None
    
    def to_dict(self):
        """Convert user to dictionary for API responses"""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'is_active': self.is_active,
            'is_calibrated': self.is_calibrated,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'model_version': self.model_version,
            'current_risk_score': self.current_risk_score
        }

class BehavioralData(db.Model):
    """Store real-time behavioral biometric data"""
    __tablename__ = 'behavioral_data'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    session_id = db.Column(db.String(64), nullable=False, index=True)
    
    # Timestamp and context
    timestamp = db.Column(db.DateTime(timezone=True), default=datetime.now(timezone.utc), index=True)
    data_type = db.Column(db.String(20), nullable=False)  # 'keystroke', 'mouse', 'mixed'
    window_duration = db.Column(db.Float, nullable=False)  # Window size in seconds
    
    # Raw behavioral data (JSON)
    keystroke_events = db.Column(db.Text, nullable=True)  # JSON array of keystroke events
    mouse_events = db.Column(db.Text, nullable=True)      # JSON array of mouse events
    
    # Extracted features (JSON)
    keystroke_features = db.Column(db.Text, nullable=True)  # JSON object with 20 features
    mouse_features = db.Column(db.Text, nullable=True)      # JSON object with 20 features
    
    # ML Analysis results
    anomaly_score = db.Column(db.Float, nullable=True)
    risk_level = db.Column(db.String(10), nullable=True)  # 'low', 'medium', 'high'
    model_predictions = db.Column(db.Text, nullable=True)  # JSON with all model outputs
    
    # Data quality metrics
    keystroke_count = db.Column(db.Integer, default=0)
    mouse_event_count = db.Column(db.Integer, default=0)
    data_quality_score = db.Column(db.Float, default=1.0)
    
    @hybrid_property
    def keystroke_events_data(self):
        """Parse keystroke events JSON"""
        if self.keystroke_events:
            return json.loads(self.keystroke_events)
        return []
    
    @keystroke_events_data.setter
    def keystroke_events_data(self, value):
        """Set keystroke events as JSON"""
        self.keystroke_events = json.dumps(value) if value else None
        self.keystroke_count = len(value) if value else 0
    
    @hybrid_property
    def mouse_events_data(self):
        """Parse mouse events JSON"""
        if self.mouse_events:
            return json.loads(self.mouse_events)
        return []
    
    @mouse_events_data.setter
    def mouse_events_data(self, value):
        """Set mouse events as JSON"""
        self.mouse_events = json.dumps(value) if value else None
        self.mouse_event_count = len(value) if value else 0
    
    @hybrid_property
    def keystroke_features_data(self):
        """Parse keystroke features JSON"""
        if self.keystroke_features:
            return json.loads(self.keystroke_features)
        return {}
    
    @keystroke_features_data.setter
    def keystroke_features_data(self, value):
        """Set keystroke features as JSON"""
        self.keystroke_features = json.dumps(value) if value else None
    
    @hybrid_property
    def mouse_features_data(self):
        """Parse mouse features JSON"""
        if self.mouse_features:
            return json.loads(self.mouse_features)
        return {}
    
    @mouse_features_data.setter
    def mouse_features_data(self, value):
        """Set mouse features as JSON"""
        self.mouse_features = json.dumps(value) if value else None

class AuthenticationLog(db.Model):
    """Log authentication events and anomaly detections"""
    __tablename__ = 'authentication_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    session_id = db.Column(db.String(64), nullable=True, index=True)
    
    # Event details
    timestamp = db.Column(db.DateTime(timezone=True), default=datetime.now(timezone.utc), index=True)
    event_type = db.Column(db.String(50), nullable=False)  # 'login', 'logout', 'anomaly', 'challenge', 'drift'
    event_status = db.Column(db.String(20), nullable=False)  # 'success', 'failure', 'pending'
    
    # Context information
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.Text, nullable=True)
    username_attempted = db.Column(db.String(80), nullable=True)
    
    # Risk and anomaly details
    risk_score = db.Column(db.Float, nullable=True)
    anomaly_type = db.Column(db.String(50), nullable=True)  # 'keystroke', 'mouse', 'combined'
    confidence_score = db.Column(db.Float, nullable=True)
    
    # Action taken
    action_taken = db.Column(db.String(100), nullable=True)  # 'blocked', 'challenged', 'logged', 'retrained'
    challenge_result = db.Column(db.String(20), nullable=True)  # 'passed', 'failed', 'timeout'
    
    # Additional metadata
    metadata = db.Column(db.Text, nullable=True)  # JSON for additional context
    
    @hybrid_property
    def metadata_data(self):
        """Parse metadata JSON"""
        if self.metadata:
            return json.loads(self.metadata)
        return {}
    
    @metadata_data.setter
    def metadata_data(self, value):
        """Set metadata as JSON"""
        self.metadata = json.dumps(value) if value else None

class CalibrationSession(db.Model):
    """Track user calibration sessions for initial model training"""
    __tablename__ = 'calibration_sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    session_id = db.Column(db.String(64), nullable=False, unique=True, index=True)
    
    # Session metadata
    started_at = db.Column(db.DateTime(timezone=True), default=datetime.now(timezone.utc))
    completed_at = db.Column(db.DateTime(timezone=True), nullable=True)
    status = db.Column(db.String(20), default='in_progress')  # 'in_progress', 'completed', 'failed'
    
    # Calibration tasks
    total_tasks = db.Column(db.Integer, default=0)
    completed_tasks = db.Column(db.Integer, default=0)
    task_data = db.Column(db.Text, nullable=True)  # JSON with task details
    
    # Data collection metrics
    keystroke_samples = db.Column(db.Integer, default=0)
    mouse_samples = db.Column(db.Integer, default=0)
    total_duration = db.Column(db.Float, default=0.0)  # Total time in seconds
    
    # Quality metrics
    data_quality_score = db.Column(db.Float, default=0.0)
    sufficient_data = db.Column(db.Boolean, default=False)
    
    # Model training results
    model_training_status = db.Column(db.String(20), default='pending')  # 'pending', 'training', 'completed', 'failed'
    model_accuracy = db.Column(db.Float, nullable=True)
    training_completion_time = db.Column(db.DateTime(timezone=True), nullable=True)
    
    @hybrid_property
    def task_data_parsed(self):
        """Parse task data JSON"""
        if self.task_data:
            return json.loads(self.task_data)
        return {}
    
    @task_data_parsed.setter
    def task_data_parsed(self, value):
        """Set task data as JSON"""
        self.task_data = json.dumps(value) if value else None
    
    @property
    def progress_percentage(self):
        """Calculate completion percentage"""
        if self.total_tasks == 0:
            return 0
        return (self.completed_tasks / self.total_tasks) * 100

def init_db():
    """Initialize database tables"""
    db.create_all()
    print("Database tables created successfully")# ==========================================
# app/models/database.py
"""
SQLAlchemy database models for the authentication agent
"""
import json
from datetime import datetime, timezone
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.ext.hybrid import hybrid_property
from app import db

class User(db.Model):
    """User model with authentication and behavioral profile data"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    
    # User status and security
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    is_calibrated = db.Column(db.Boolean, default=False, nullable=False)
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime(timezone=True), nullable=True)
    
    # Timestamps
    created_at = db.Column(db.DateTime(timezone=True), default=datetime.now(timezone.utc))
    last_login = db.Column(db.DateTime(timezone=True), nullable=True)
    last_activity = db.Column(db.DateTime(timezone=True), nullable=True)
    
    # ML Model metadata
    model_version = db.Column(db.Integer, default=1)
    model_last_trained = db.Column(db.DateTime(timezone=True), nullable=True)
    model_training_samples = db.Column(db.Integer, default=0)
    
    # Behavioral baseline statistics (JSON stored)
    keystroke_baseline = db.Column(db.Text, nullable=True)  # JSON
    mouse_baseline = db.Column(db.Text, nullable=True)      # JSON
    
    # Risk assessment
    current_risk_score = db.Column(db.Float, default=0.0)
    anomaly_count_24h = db.Column(db.Integer, default=0)
    
    # Relationships
    behavioral_data = db.relationship('BehavioralData', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    auth_logs = db.relationship('AuthenticationLog', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    calibration_sessions = db.relationship('CalibrationSession', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    
    def set_password(self, password):
        """Hash and set user password"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Check if provided password matches stored hash"""
        return check_password_hash(self.password_hash, password)
    
    def is_locked(self):
        """Check if user account is currently locked"""
        if self.locked_until is None:
            return False
        return datetime.now(timezone.utc) < self.locked_until
    
    def increment_failed_attempts(self):
        """Increment failed login attempts and lock if necessary"""
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 5:  # Configure this threshold
            from datetime import timedelta
            self.locked_until = datetime.now(timezone.utc) + timedelta(minutes=30)
    
    def reset_failed_attempts(self):
        """Reset failed login attempts on successful login"""
        self.failed_login_attempts = 0
        self.locked_until = None
        self.last_login = datetime.now(timezone.utc)
    
    @hybrid_property
    def keystroke_baseline_data(self):
        """Parse keystroke baseline JSON"""
        if self.keystroke_baseline:
            return json.loads(self.keystroke_baseline)
        return {}
    
    @keystroke_baseline_data.setter
    def keystroke_baseline_data(self, value):
        """Set keystroke baseline as JSON"""
        self.keystroke_baseline = json.dumps(value) if value else None
    
    @hybrid_property
    def mouse_baseline_data(self):
        """Parse mouse baseline JSON"""
        if self.mouse_baseline:
            return json.loads(self.mouse_baseline)
        return {}
    
    @mouse_baseline_data.setter
    def mouse_baseline_data(self, value):
        """Set mouse baseline as JSON"""
        self.mouse_baseline = json.dumps(value) if value else None
    
    def to_dict(self):
        """Convert user to dictionary for API responses"""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'is_active': self.is_active,
            'is_calibrated': self.is_calibrated,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'model_version': self.model_version,
            'current_risk_score': self.current_risk_score
        }

class BehavioralData(db.Model):
    """Store real-time behavioral biometric data"""
    __tablename__ = 'behavioral_data'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    session_id = db.Column(db.String(64), nullable=False, index=True)
    
    # Timestamp and context
    timestamp = db.Column(db.DateTime(timezone=True), default=datetime.now(timezone.utc), index=True)
    data_type = db.Column(db.String(20), nullable=False)  # 'keystroke', 'mouse', 'mixed'
    window_duration = db.Column(db.Float, nullable=False)  # Window size in seconds
    
    # Raw behavioral data (JSON)
    keystroke_events = db.Column(db.Text, nullable=True)  # JSON array of keystroke events
    mouse_events = db.Column(db.Text, nullable=True)      # JSON array of mouse events
    
    # Extracted features (JSON)
    keystroke_features = db.Column(db.Text, nullable=True)  # JSON object with 20 features
    mouse_features = db.Column(db.Text, nullable=True)      # JSON object with 20 features
    
    # ML Analysis results
    anomaly_score = db.Column(db.Float, nullable=True)
    risk_level = db.Column(db.String(10), nullable=True)  # 'low', 'medium', 'high'
    model_predictions = db.Column(db.Text, nullable=True)  # JSON with all model outputs
    
    # Data quality metrics
    keystroke_count = db.Column(db.Integer, default=0)
    mouse_event_count = db.Column(db.Integer, default=0)
    data_quality_score = db.Column(db.Float, default=1.0)
    
    @hybrid_property
    def keystroke_events_data(self):
        """Parse keystroke events JSON"""
        if self.keystroke_events:
            return json.loads(self.keystroke_events)
        return []
    
    @keystroke_events_data.setter
    def keystroke_events_data(self, value):
        """Set keystroke events as JSON"""
        self.keystroke_events = json.dumps(value) if value else None
        self.keystroke_count = len(value) if value else 0
    
    @hybrid_property
    def mouse_events_data(self):
        """Parse mouse events JSON"""
        if self.mouse_events:
            return json.loads(self.mouse_events)
        return []
    
    @mouse_events_data.setter
    def mouse_events_data(self, value):
        """Set mouse events as JSON"""
        self.mouse_events = json.dumps(value) if value else None
        self.mouse_event_count = len(value) if value else 0
    
    @hybrid_property
    def keystroke_features_data(self):
        """Parse keystroke features JSON"""
        if self.keystroke_features:
            return json.loads(self.keystroke_features)
        return {}
    
    @keystroke_features_data.setter
    def keystroke_features_data(self, value):
        """Set keystroke features as JSON"""
        self.keystroke_features = json.dumps(value) if value else None
    
    @hybrid_property
    def mouse_features_data(self):
        """Parse mouse features JSON"""
        if self.mouse_features:
            return json.loads(self.mouse_features)
        return {}
    
    @mouse_features_data.setter
    def mouse_features_data(self, value):
        """Set mouse features as JSON"""
        self.mouse_features = json.dumps(value) if value else None

class AuthenticationLog(db.Model):
    """Log authentication events and anomaly detections"""
    __tablename__ = 'authentication_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    session_id = db.Column(db.String(64), nullable=True, index=True)
    
    # Event details
    timestamp = db.Column(db.DateTime(timezone=True), default=datetime.now(timezone.utc), index=True)
    event_type = db.Column(db.String(50), nullable=False)  # 'login', 'logout', 'anomaly', 'challenge', 'drift'
    event_status = db.Column(db.String(20), nullable=False)  # 'success', 'failure', 'pending'
    
    # Context information
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.Text, nullable=True)
    username_attempted = db.Column(db.String(80), nullable=True)
    
    # Risk and anomaly details
    risk_score = db.Column(db.Float, nullable=True)
    anomaly_type = db.Column(db.String(50), nullable=True)  # 'keystroke', 'mouse', 'combined'
    confidence_score = db.Column(db.Float, nullable=True)
    
    # Action taken
    action_taken = db.Column(db.String(100), nullable=True)  # 'blocked', 'challenged', 'logged', 'retrained'
    challenge_result = db.Column(db.String(20), nullable=True)  # 'passed', 'failed', 'timeout'
    
    # Additional metadata
    metadata = db.Column(db.Text, nullable=True)  # JSON for additional context
    
    @hybrid_property
    def metadata_data(self):
        """Parse metadata JSON"""
        if self.metadata:
            return json.loads(self.metadata)
        return {}
    
    @metadata_data.setter
    def metadata_data(self, value):
        """Set metadata as JSON"""
        self.metadata = json.dumps(value) if value else None

class CalibrationSession(db.Model):
    """Track user calibration sessions for initial model training"""
    __tablename__ = 'calibration_sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    session_id = db.Column(db.String(64), nullable=False, unique=True, index=True)
    
    # Session metadata
    started_at = db.Column(db.DateTime(timezone=True), default=datetime.now(timezone.utc))
    completed_at = db.Column(db.DateTime(timezone=True), nullable=True)
    status = db.Column(db.String(20), default='in_progress')  # 'in_progress', 'completed', 'failed'
    
    # Calibration tasks
    total_tasks = db.Column(db.Integer, default=0)
    completed_tasks = db.Column(db.Integer, default=0)
    task_data = db.Column(db.Text, nullable=True)  # JSON with task details
    
    # Data collection metrics
    keystroke_samples = db.Column(db.Integer, default=0)
    mouse_samples = db.Column(db.Integer, default=0)
    total_duration = db.Column(db.Float, default=0.0)  # Total time in seconds
    
    # Quality metrics
    data_quality_score = db.Column(db.Float, default=0.0)
    sufficient_data = db.Column(db.Boolean, default=False)
    
    # Model training results
    model_training_status = db.Column(db.String(20), default='pending')  # 'pending', 'training', 'completed', 'failed'
    model_accuracy = db.Column(db.Float, nullable=True)
    training_completion_time = db.Column(db.DateTime(timezone=True), nullable=True)
    
    @hybrid_property
    def task_data_parsed(self):
        """Parse task data JSON"""
        if self.task_data:
            return json.loads(self.task_data)
        return {}
    
    @task_data_parsed.setter
    def task_data_parsed(self, value):
        """Set task data as JSON"""
        self.task_data = json.dumps(value) if value else None
    
    @property
    def progress_percentage(self):
        """Calculate completion percentage"""
        if self.total_tasks == 0:
            return 0
        return (self.completed_tasks / self.total_tasks) * 100

def init_db():
    """Initialize database tables"""
    db.create_all()
    print("Database tables created successfully")