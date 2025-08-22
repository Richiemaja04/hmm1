# run.py
"""
Main application entry point for the Continuous Authentication Agent
"""
import os
import logging
from app import create_app, socketio
from app.models.database import init_db

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('auth_agent.log'),
        logging.StreamHandler()
    ]
)

app = create_app()

if __name__ == '__main__':
    # Initialize database
    with app.app_context():
        init_db()
    
    # Run the application with SocketIO support
    socketio.run(
        app,
        debug=False,
        host='127.0.0.1',
        port=5000,
        allow_unsafe_werkzeug=True
    )