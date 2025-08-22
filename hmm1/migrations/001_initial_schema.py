# migrations/001_initial_schema.py
"""
Initial database schema migration for Continuous Authentication Agent
"""

from datetime import datetime, timezone
from app import db

def upgrade():
    """Create initial database tables"""
    
    # Users table
    db.engine.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username VARCHAR(80) UNIQUE NOT NULL,
            email VARCHAR(120) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            is_active BOOLEAN DEFAULT 1 NOT NULL,
            is_calibrated BOOLEAN DEFAULT 0 NOT NULL,
            failed_login_attempts INTEGER DEFAULT 0,
            locked_until DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_login DATETIME,
            last_activity DATETIME,
            model_version INTEGER DEFAULT 1,
            model_last_trained DATETIME,
            model_training_samples INTEGER DEFAULT 0,
            keystroke_baseline TEXT,
            mouse_baseline TEXT,
            current_risk_score REAL DEFAULT 0.0,
            anomaly_count_24h INTEGER DEFAULT 0
        );
    """)
    
    # Behavioral data table
    db.engine.execute("""
        CREATE TABLE IF NOT EXISTS behavioral_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            session_id VARCHAR(64) NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            data_type VARCHAR(20) NOT NULL,
            window_duration REAL NOT NULL,
            keystroke_events TEXT,
            mouse_events TEXT,
            keystroke_features TEXT,
            mouse_features TEXT,
            anomaly_score REAL,
            risk_level VARCHAR(10),
            model_predictions TEXT,
            keystroke_count INTEGER DEFAULT 0,
            mouse_event_count INTEGER DEFAULT 0,
            data_quality_score REAL DEFAULT 1.0,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    """)
    
    # Authentication logs table
    db.engine.execute("""
        CREATE TABLE IF NOT EXISTS authentication_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            session_id VARCHAR(64),
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            event_type VARCHAR(50) NOT NULL,
            event_status VARCHAR(20) NOT NULL,
            ip_address VARCHAR(45),
            user_agent TEXT,
            username_attempted VARCHAR(80),
            risk_score REAL,
            anomaly_type VARCHAR(50),
            confidence_score REAL,
            action_taken VARCHAR(100),
            challenge_result VARCHAR(20),
            metadata TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    """)
    
    # Calibration sessions table
    db.engine.execute("""
        CREATE TABLE IF NOT EXISTS calibration_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            session_id VARCHAR(64) UNIQUE NOT NULL,
            started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            completed_at DATETIME,
            status VARCHAR(20) DEFAULT 'in_progress',
            total_tasks INTEGER DEFAULT 0,
            completed_tasks INTEGER DEFAULT 0,
            task_data TEXT,
            keystroke_samples INTEGER DEFAULT 0,
            mouse_samples INTEGER DEFAULT 0,
            total_duration REAL DEFAULT 0.0,
            data_quality_score REAL DEFAULT 0.0,
            sufficient_data BOOLEAN DEFAULT 0,
            model_training_status VARCHAR(20) DEFAULT 'pending',
            model_accuracy REAL,
            training_completion_time DATETIME,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    """)
    
    # Create indexes for better performance
    db.engine.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")
    db.engine.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);")
    db.engine.execute("CREATE INDEX IF NOT EXISTS idx_behavioral_data_user_id ON behavioral_data(user_id);")
    db.engine.execute("CREATE INDEX IF NOT EXISTS idx_behavioral_data_timestamp ON behavioral_data(timestamp);")
    db.engine.execute("CREATE INDEX IF NOT EXISTS idx_auth_logs_user_id ON authentication_logs(user_id);")
    db.engine.execute("CREATE INDEX IF NOT EXISTS idx_auth_logs_timestamp ON authentication_logs(timestamp);")
    db.engine.execute("CREATE INDEX IF NOT EXISTS idx_calibration_sessions_user_id ON calibration_sessions(user_id);")
    
    print("Database schema created successfully")

def downgrade():
    """Drop all tables"""
    db.engine.execute("DROP TABLE IF EXISTS calibration_sessions;")
    db.engine.execute("DROP TABLE IF EXISTS authentication_logs;")
    db.engine.execute("DROP TABLE IF EXISTS behavioral_data;")
    db.engine.execute("DROP TABLE IF EXISTS users;")
    print("Database schema dropped")

# ==========================================
# Setup and Installation Guide
# ==========================================

"""
CONTINUOUS AUTHENTICATION AGENT - SETUP GUIDE
==============================================

This is a complete, production-ready continuous authentication system using 
behavioral biometrics for enhanced security.

## System Requirements

- Python 3.10+
- Modern web browser (Chrome, Firefox, Safari, Edge)
- 4GB+ RAM (for ML model training)
- SQLite (included) or PostgreSQL for production

## Project Structure

continuous-authentication-agent/
├── app/
│   ├── __init__.py                 # Flask app factory
│   ├── config.py                   # Configuration settings
│   ├── models/
│   │   ├── __init__.py
│   │   ├── database.py             # SQLAlchemy models
│   │   ├── ml_models.py            # ML model implementations
│   │   └── schemas.py              # Pydantic schemas
│   ├── core/
│   │   ├── __init__.py
│   │   ├── feature_extractor.py    # Behavioral feature extraction
│   │   ├── anomaly_detector.py     # Anomaly detection engine
│   │   ├── drift_detector.py       # Behavioral drift detection
│   │   └── security_manager.py     # Security assessment
│   ├── api/
│   │   ├── __init__.py
│   │   ├── auth.py                 # Authentication endpoints
│   │   ├── calibration.py          # Calibration endpoints
│   │   ├── dashboard.py            # Dashboard endpoints
│   │   ├── challenge.py            # Challenge endpoints
│   │   └── websockets.py           # WebSocket handlers
│   ├── services/
│   │   ├── __init__.py
│   │   ├── auth_service.py         # Authentication service
│   │   ├── monitoring_service.py   # Real-time monitoring
│   │   ├── challenge_service.py    # Challenge management
│   │   └── notification_service.py # Notification handling
│   └── utils/
│       ├── __init__.py
│       ├── security.py             # Security utilities
│       ├── helpers.py              # General utilities
│       └── validators.py           # Input validation
├── static/
│   ├── css/
│   │   └── styles.css              # Complete CSS framework
│   ├── js/
│   │   ├── login.js                # Login/registration logic
│   │   ├── calibration.js          # Calibration process
│   │   ├── dashboard.js            # Dashboard interface
│   │   └── challenge.js            # Security challenges
│   └── assets/
│       └── icons/
├── templates/
│   ├── login.html                  # Login/registration page
│   ├── calibration.html            # Behavioral calibration
│   ├── dashboard.html              # Main user interface
│   └── challenge.html              # Security verification
├── migrations/
│   └── 001_initial_schema.py       # Database migrations
├── requirements.txt                # Python dependencies
└── run.py                          # Application entry point

## Installation Steps

1. **Clone or create the project structure above**

2. **Create virtual environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set environment variables:**
   ```bash
   export SECRET_KEY="your-secret-key-here"
   export JWT_SECRET_KEY="your-jwt-secret-key"
   export FLASK_ENV="development"
   ```

5. **Initialize database:**
   ```bash
   python -c "from app.models.database import init_db; init_db()"
   ```

6. **Run the application:**
   ```bash
   python run.py
   ```

7. **Access the application:**
   Open http://localhost:5000 in your browser

## Core Features

### 🔐 Advanced Authentication
- Traditional username/password login
- Behavioral biometric verification
- Continuous session monitoring
- Adaptive security challenges

### 🧠 Machine Learning Engine
- Keystroke dynamics analysis (20 features)
- Mouse movement patterns (20 features)
- Neural networks (GRU, Autoencoder)
- Classical ML (Isolation Forest, One-Class SVM)
- Real-time anomaly detection

### 📊 Professional Dashboard
- Real-time security monitoring
- Behavioral analytics and charts
- Security event logging
- User settings and preferences

### 🔄 Continuous Monitoring
- Silent background data collection
- WebSocket real-time communication
- Behavioral drift detection
- Automatic model adaptation

### ⚡ Security Features
- JWT-based authentication
- Session management and timeouts
- Rate limiting and brute force protection
- IP-based risk assessment
- User agent analysis

## Usage Workflow

1. **Registration/Login** - New users register, existing users login
2. **Calibration** - New users complete behavioral profiling (5-10 minutes)
3. **Dashboard** - Main interface with real-time monitoring
4. **Challenges** - Security verification when anomalies detected
5. **Adaptation** - System learns and adapts to user behavior changes

## Configuration

### Security Settings (app/config.py)
```python
# Anomaly detection thresholds
ANOMALY_THRESHOLD = 0.7
DRIFT_DETECTION_WINDOW = 100

# Session management
SESSION_TIMEOUT = 24 * 3600  # 24 hours
MAX_LOGIN_ATTEMPTS = 5

# Feature collection
FEATURE_WINDOW_SIZE = 30  # seconds
```

### ML Model Configuration
- **Training**: Automatic background training after calibration
- **Updates**: Incremental learning with new behavioral data
- **Drift Detection**: Statistical tests (KS test, JS divergence)
- **Ensemble**: Multiple models for robust detection

## API Endpoints

### Authentication
- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User login
- `POST /api/auth/logout` - User logout
- `POST /api/auth/refresh` - Token refresh

### Calibration
- `POST /api/calibration/start` - Start calibration
- `POST /api/calibration/submit-data` - Submit behavioral data
- `GET /api/calibration/status/<session_id>` - Get status

### Dashboard
- `GET /api/dashboard/user-info` - Get user information
- `GET /api/dashboard/analytics` - Get behavioral analytics
- `GET /api/dashboard/security-events` - Get security events

### Challenge
- `POST /api/challenge/initiate` - Start security challenge
- `POST /api/challenge/submit` - Submit challenge response

## Security Considerations

### Data Protection
- All behavioral data encrypted at rest
- Secure WebSocket connections (WSS in production)
- JWT tokens with short expiration
- Password hashing with bcrypt

### Privacy
- Behavioral data stored locally only
- No external data transmission
- User consent for data collection
- Data retention policies

### Threat Mitigation
- Session hijacking prevention
- Insider threat detection
- Credential stuffing protection
- Advanced persistent threat detection

## Production Deployment

### Database
- Switch to PostgreSQL for production
- Set up connection pooling
- Configure database backups
- Monitor query performance

### Infrastructure
- Use HTTPS/WSS for all connections
- Deploy behind reverse proxy (nginx)
- Set up load balancing if needed
- Configure logging and monitoring

### Environment Variables
```bash
export FLASK_ENV="production"
export DATABASE_URL="postgresql://user:pass@localhost/authdb"
export SECRET_KEY="strong-random-key"
export JWT_SECRET_KEY="jwt-secret-key"
```

### Performance Optimization
- Enable Redis for caching
- Use Celery for background tasks
- Optimize ML model loading
- Implement connection pooling

## Monitoring & Maintenance

### System Health
- Monitor WebSocket connections
- Track ML model performance
- Alert on security events
- Performance metrics collection

### ML Model Maintenance
- Regular model retraining
- Performance degradation detection
- A/B testing for model updates
- Backup and versioning

## Troubleshooting

### Common Issues

**WebSocket Connection Fails:**
- Check firewall settings
- Verify JWT token validity
- Ensure proper CORS configuration

**ML Training Errors:**
- Verify sufficient memory (4GB+)
- Check TensorFlow installation
- Validate training data quality

**High CPU Usage:**
- Optimize data collection frequency
- Review ML model complexity
- Check for memory leaks

**Authentication Issues:**
- Verify database connection
- Check JWT configuration
- Review session management

### Debug Mode
```bash
export FLASK_ENV="development"
export FLASK_DEBUG=1
python run.py
```

## Support & Development

### Extending the System
- Add new behavioral features
- Implement additional ML models
- Create custom security policies
- Integrate with external systems

### Contributing
- Follow PEP 8 style guidelines
- Add comprehensive tests
- Update documentation
- Use type hints

### Testing
```bash
# Run unit tests
python -m pytest tests/

# Run integration tests
python -m pytest tests/integration/

# Test behavioral collection
python -m pytest tests/behavioral/
```

This system provides enterprise-grade continuous authentication using behavioral biometrics, with real-time monitoring, advanced ML models, and a professional user interface.
"""

# ==========================================
# .env.example - Environment Variables Template
# ==========================================

"""
# Flask Configuration
SECRET_KEY=your-secret-key-change-in-production
JWT_SECRET_KEY=your-jwt-secret-key-change-in-production
FLASK_ENV=development

# Database Configuration
DATABASE_URL=sqlite:///auth_agent.db
# For production use PostgreSQL:
# DATABASE_URL=postgresql://user:password@localhost:5432/auth_db

# ML Configuration
ML_MODEL_UPDATE_INTERVAL=3600
ANOMALY_THRESHOLD=0.7
DRIFT_DETECTION_WINDOW=100

# Security Configuration
PASSWORD_MIN_LENGTH=8
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_DURATION=300
SESSION_TIMEOUT=86400

# Feature Collection
FEATURE_WINDOW_SIZE=30
KEYSTROKE_FEATURES=20
MOUSE_FEATURES=20

# Logging
LOG_LEVEL=INFO
LOG_FILE=auth_agent.log

# External Services (Optional)
REDIS_URL=redis://localhost:6379
CELERY_BROKER_URL=redis://localhost:6379
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
EMAIL_USERNAME=your-email@example.com
EMAIL_PASSWORD=your-app-password
"""