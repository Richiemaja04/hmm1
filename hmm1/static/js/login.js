// static/js/login.js
/**
 * Login and Registration Page JavaScript
 * Handles authentication, form validation, and UI interactions
 */

class LoginManager {
    constructor() {
        this.currentForm = 'login';
        this.keystrokeData = [];
        this.mouseData = [];
        this.isCollectingData = false;
        
        this.init();
    }
    
    init() {
        this.bindEvents();
        this.startBehavioralCollection();
    }
    
    bindEvents() {
        // Form switching
        document.getElementById('registerBtn')?.addEventListener('click', () => this.switchToRegister());
        document.getElementById('backToLoginBtn')?.addEventListener('click', () => this.switchToLogin());
        
        // Form submissions
        document.getElementById('loginForm')?.addEventListener('submit', (e) => this.handleLogin(e));
        document.getElementById('registerForm')?.addEventListener('submit', (e) => this.handleRegister(e));
        
        // Password toggles
        document.getElementById('passwordToggle')?.addEventListener('click', () => this.togglePassword('password'));
        document.getElementById('regPasswordToggle')?.addEventListener('click', () => this.togglePassword('regPassword'));
        
        // Password strength checker
        document.getElementById('regPassword')?.addEventListener('input', (e) => this.checkPasswordStrength(e.target.value));
        
        // Confirm password validation
        document.getElementById('confirmPassword')?.addEventListener('input', (e) => this.validatePasswordConfirm(e.target.value));
        
        // Alert close
        document.getElementById('alertClose')?.addEventListener('click', () => this.hideAlert());
    }
    
    switchToRegister() {
        document.getElementById('loginForm').classList.add('hidden');
        document.getElementById('registerForm').classList.remove('hidden');
        this.currentForm = 'register';
    }
    
    switchToLogin() {
        document.getElementById('registerForm').classList.add('hidden');
        document.getElementById('loginForm').classList.remove('hidden');
        this.currentForm = 'login';
    }
    
    togglePassword(inputId) {
        const input = document.getElementById(inputId);
        const toggle = document.querySelector(`#${inputId} + .password-input .password-toggle i`);
        
        if (input.type === 'password') {
            input.type = 'text';
            toggle.className = 'fas fa-eye-slash';
        } else {
            input.type = 'password';
            toggle.className = 'fas fa-eye';
        }
    }
    
    checkPasswordStrength(password) {
        const strengthBar = document.querySelector('.strength-fill');
        const strengthText = document.querySelector('.strength-text');
        
        let score = 0;
        let feedback = '';
        
        // Length check
        if (password.length >= 8) score += 1;
        if (password.length >= 12) score += 1;
        
        // Character variety
        if (/[a-z]/.test(password)) score += 1;
        if (/[A-Z]/.test(password)) score += 1;
        if (/\d/.test(password)) score += 1;
        if (/[!@#$%^&*(),.?":{}|<>]/.test(password)) score += 1;
        
        // Set strength indicator
        const width = (score / 6) * 100;
        strengthBar.style.width = `${width}%`;
        
        if (score < 3) {
            strengthBar.style.background = '#dc2626';
            feedback = 'Weak password';
        } else if (score < 5) {
            strengthBar.style.background = '#d97706';
            feedback = 'Medium password';
        } else {
            strengthBar.style.background = '#059669';
            feedback = 'Strong password';
        }
        
        strengthText.textContent = feedback;
    }
    
    validatePasswordConfirm(confirmPassword) {
        const password = document.getElementById('regPassword').value;
        const confirmInput = document.getElementById('confirmPassword');
        
        if (password && confirmPassword) {
            if (password === confirmPassword) {
                confirmInput.style.borderColor = '#059669';
            } else {
                confirmInput.style.borderColor = '#dc2626';
            }
        }
    }
    
    async handleLogin(e) {
        e.preventDefault();
        
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        
        if (!username || !password) {
            this.showAlert('Please fill in all fields', 'error');
            return;
        }
        
        this.showLoading();
        
        try {
            const response = await fetch('/api/auth/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    username,
                    password
                })
            });
            
            const data = await response.json();
            
            if (response.ok) {
                // Store tokens
                localStorage.setItem('access_token', data.access_token);
                localStorage.setItem('refresh_token', data.refresh_token);
                localStorage.setItem('user_data', JSON.stringify(data.user));
                
                this.showAlert(data.message, 'success');
                
                // Redirect based on calibration status
                setTimeout(() => {
                    window.location.href = data.redirect || '/dashboard';
                }, 1000);
                
            } else {
                this.showAlert(data.error || 'Login failed', 'error');
            }
        } catch (error) {
            console.error('Login error:', error);
            this.showAlert('Network error. Please try again.', 'error');
        } finally {
            this.hideLoading();
        }
    }
    
    async handleRegister(e) {
        e.preventDefault();
        
        const username = document.getElementById('regUsername').value;
        const email = document.getElementById('regEmail').value;
        const password = document.getElementById('regPassword').value;
        const confirmPassword = document.getElementById('confirmPassword').value;
        const agreeTerms = document.getElementById('agreeTerms').checked;
        
        // Validation
        if (!username || !email || !password || !confirmPassword) {
            this.showAlert('Please fill in all fields', 'error');
            return;
        }
        
        if (password !== confirmPassword) {
            this.showAlert('Passwords do not match', 'error');
            return;
        }
        
        if (!agreeTerms) {
            this.showAlert('Please agree to the terms of service', 'error');
            return;
        }
        
        this.showLoading();
        
        try {
            const response = await fetch('/api/auth/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    username,
                    email,
                    password
                })
            });
            
            const data = await response.json();
            
            if (response.ok) {
                this.showAlert('Account created successfully! Please log in.', 'success');
                setTimeout(() => {
                    this.switchToLogin();
                    document.getElementById('username').value = username;
                }, 1500);
            } else {
                this.showAlert(data.error || 'Registration failed', 'error');
            }
        } catch (error) {
            console.error('Registration error:', error);
            this.showAlert('Network error. Please try again.', 'error');
        } finally {
            this.hideLoading();
        }
    }
    
    startBehavioralCollection() {
        this.isCollectingData = true;
        
        // Collect keystroke events
        document.addEventListener('keydown', (e) => this.recordKeystroke(e, 'keydown'));
        document.addEventListener('keyup', (e) => this.recordKeystroke(e, 'keyup'));
        
        // Collect mouse events
        document.addEventListener('mousemove', (e) => this.recordMouseEvent(e, 'mousemove'));
        document.addEventListener('click', (e) => this.recordMouseEvent(e, 'click'));
    }
    
    recordKeystroke(event, type) {
        if (!this.isCollectingData) return;
        
        this.keystrokeData.push({
            type,
            key: event.key,
            keyCode: event.keyCode,
            timestamp: Date.now(),
            ctrlKey: event.ctrlKey,
            shiftKey: event.shiftKey,
            altKey: event.altKey,
            metaKey: event.metaKey
        });
        
        // Keep only recent data (last 100 events)
        if (this.keystrokeData.length > 100) {
            this.keystrokeData = this.keystrokeData.slice(-100);
        }
    }
    
    recordMouseEvent(event, type) {
        if (!this.isCollectingData) return;
        
        this.mouseData.push({
            type,
            clientX: event.clientX,
            clientY: event.clientY,
            button: event.button,
            timestamp: Date.now()
        });
        
        // Keep only recent data (last 200 events)
        if (this.mouseData.length > 200) {
            this.mouseData = this.mouseData.slice(-200);
        }
    }
    
    showLoading() {
        document.getElementById('loadingOverlay').classList.remove('hidden');
    }
    
    hideLoading() {
        document.getElementById('loadingOverlay').classList.add('hidden');
    }
    
    showAlert(message, type = 'info') {
        const alertContainer = document.getElementById('alertContainer');
        const alert = document.getElementById('alert');
        const icon = alert.querySelector('.alert-icon');
        const messageEl = alert.querySelector('.alert-message');
        
        // Set icon and styling based on type
        alert.className = `alert alert-${type}`;
        
        switch (type) {
            case 'success':
                icon.className = 'fas fa-check-circle alert-icon';
                break;
            case 'error':
                icon.className = 'fas fa-exclamation-circle alert-icon';
                break;
            case 'warning':
                icon.className = 'fas fa-exclamation-triangle alert-icon';
                break;
            default:
                icon.className = 'fas fa-info-circle alert-icon';
        }
        
        messageEl.textContent = message;
        alertContainer.classList.remove('hidden');
        
        // Auto-hide after 5 seconds
        setTimeout(() => this.hideAlert(), 5000);
    }
    
    hideAlert() {
        document.getElementById('alertContainer').classList.add('hidden');
    }
}

// Initialize login manager when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new LoginManager();
});
