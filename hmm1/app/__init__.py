# ==========================================
# app/__init__.py
"""
Application factory and configuration
"""
import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO
from flask_jwt_extended import JWTManager
from flask_cors import CORS

# Initialize extensions
db = SQLAlchemy()
socketio = SocketIO(cors_allowed_origins="*")
jwt = JWTManager()

def create_app(config_name='development'):
    """Create and configure Flask application"""
    app = Flask(__name__)
    
    # Load configuration
    from app.config import config
    app.config.from_object(config[config_name])
    
    # Initialize extensions
    db.init_app(app)
    socketio.init_app(app)
    jwt.init_app(app)
    CORS(app)
    
    # Register blueprints
    from app.api.auth import auth_bp
    from app.api.calibration import calibration_bp
    from app.api.dashboard import dashboard_bp
    from app.api.challenge import challenge_bp
    from app.api.websockets import register_websocket_handlers
    
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(calibration_bp, url_prefix='/api/calibration')
    app.register_blueprint(dashboard_bp, url_prefix='/api/dashboard')
    app.register_blueprint(challenge_bp, url_prefix='/api/challenge')
    
    # Register WebSocket handlers
    register_websocket_handlers(socketio)
    
    # Register template routes
    @app.route('/')
    def index():
        return app.send_static_file('login.html')
    
    @app.route('/login')
    def login():
        return app.send_static_file('login.html')
    
    @app.route('/calibration')
    def calibration():
        return app.send_static_file('calibration.html')
    
    @app.route('/dashboard')
    def dashboard():
        return app.send_static_file('dashboard.html')
    
    @app.route('/challenge')
    def challenge():
        return app.send_static_file('challenge.html')
    
    return app
