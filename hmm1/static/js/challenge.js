// ==========================================
// static/js/challenge.js
/**
 * Challenge Page JavaScript
 * Handles security challenge verification
 */

class ChallengeManager {
    constructor() {
        this.challengeId = null;
        this.challengeType = 'verification';
        this.keystrokeData = [];
        this.mouseData = [];
        this.isCollectingData = false;
        this.challengeStartTime = null;
        this.timerInterval = null;
        this.countdownInterval = null;
        
        this.init();
    }
    
    init() {
        this.bindEvents();
        this.initializeChallenge();
        this.startTimer();
    }
    
    bindEvents() {
        // Input monitoring
        document.getElementById('challengeInput')?.addEventListener('input', () => this.updateMetrics());
        document.getElementById('adaptiveInput')?.addEventListener('input', () => this.updateMetrics());
        
        // Keystroke collection
        document.getElementById('challengeInput')?.addEventListener('keydown', (e) => this.recordKeystroke(e, 'keydown'));
        document.getElementById('challengeInput')?.addEventListener('keyup', (e) => this.recordKeystroke(e, 'keyup'));
        document.getElementById('adaptiveInput')?.addEventListener('keydown', (e) => this.recordKeystroke(e, 'keydown'));
        document.getElementById('adaptiveInput')?.addEventListener('keyup', (e) => this.recordKeystroke(e, 'keyup'));
        
        // Mouse collection
        document.addEventListener('mousemove', (e) => this.recordMouseEvent(e, 'mousemove'));
        document.addEventListener('click', (e) => this.recordMouseEvent(e, 'click'));
        
        // Controls
        document.getElementById('submitChallengeBtn')?.addEventListener('click', () => this.submitChallenge());
        document.getElementById('cancelChallengeBtn')?.addEventListener('click', () => this.cancelChallenge());
        document.getElementById('copyTextBtn')?.addEventListener('click', () => this.copyReferenceText());
        
        // Result actions
        document.getElementById('continueBtn')?.addEventListener('click', () => this.continueToDashboard());
        document.getElementById('retryBtn')?.addEventListener('click', () => this.retryChallenge());
        document.getElementById('logoutBtn')?.addEventListener('click', () => this.logout());
        
        // Help
        document.getElementById('helpBtn')?.addEventListener('click', () => this.showHelp());
        document.getElementById('closeHelpModal')?.addEventListener('click', () => this.hideHelp());
        
        // Analysis panel toggle
        document.getElementById('analysisPanelToggle')?.addEventListener('click', () => this.toggleAnalysisPanel());
    }
    
    async initializeChallenge() {
        // Get challenge type from URL params or default
        const urlParams = new URLSearchParams(window.location.search);
        this.challengeType = urlParams.get('type') || 'verification';
        const reason = urlParams.get('reason') || 'security_check';
        
        try {
            // Initialize challenge
            const response = await this.apiCall('/api/challenge/initiate', 'POST', {
                challenge_type: this.challengeType,
                trigger_reason: reason
            });
            
            this.challengeId = response.challenge_id;
            
            // Setup UI based on challenge type
            this.setupChallengeUI(response);
            this.startBehavioralCollection();
            
        } catch (error) {
            console.error('Challenge initialization error:', error);
            this.showError('Failed to initialize security challenge');
        }
    }
    
    setupChallengeUI(challengeData) {
        // Show appropriate challenge type
        document.querySelectorAll('.challenge-type').forEach(el => {
            el.classList.remove('active');
        });
        
        if (this.challengeType === 'adaptive') {
            document.getElementById('adaptiveChallenge').classList.add('active');
            this.setupAdaptiveChallenge(challengeData);
        } else {
            document.getElementById('highRiskChallenge').classList.add('active');
            this.setupVerificationChallenge(challengeData);
        }
        
        // Update remaining attempts
        this.updateAttemptsRemaining(challengeData.max_attempts);
    }
    
    setupVerificationChallenge(data) {
        document.getElementById('challengeText').textContent = data.content.text;
        
        const input = document.getElementById('challengeInput');
        input.value = '';
        input.focus();
        
        this.updateMetrics();
    }
    
    setupAdaptiveChallenge(data) {
        document.getElementById('adaptiveParagraph').textContent = data.content.text;
        
        const input = document.getElementById('adaptiveInput');
        input.value = '';
        input.focus();
        
        this.updateMetrics();
    }
    
    startTimer() {
        this.challengeStartTime = Date.now();
        let timeLimit = 10 * 60; // 10 minutes in seconds
        
        this.timerInterval = setInterval(() => {
            const elapsed = Math.floor((Date.now() - this.challengeStartTime) / 1000);
            const remaining = Math.max(0, timeLimit - elapsed);
            
            const minutes = Math.floor(remaining / 60);
            const seconds = remaining % 60;
            
            document.getElementById('challengeTime').textContent = `${Math.floor(elapsed / 60)}:${(elapsed % 60).toString().padStart(2, '0')}`;
            document.getElementById('timeRemaining').textContent = `Time remaining: ${minutes}:${seconds.toString().padStart(2, '0')}`;
            
            if (remaining <= 0) {
                this.handleTimeout();
            }
        }, 1000);
    }
    
    startBehavioralCollection() {
        this.isCollectingData = true;
        this.keystrokeData = [];
        this.mouseData = [];
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
        
        // Real-time analysis feedback
        this.updateRealtimeAnalysis();
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
    }
    
    updateMetrics() {
        const isAdaptive = this.challengeType === 'adaptive';
        const input = document.getElementById(isAdaptive ? 'adaptiveInput' : 'challengeInput');
        const reference = document.getElementById(isAdaptive ? 'adaptiveParagraph' : 'challengeText');
        
        if (!input || !reference) return;
        
        const typed = input.value;
        const referenceText = reference.textContent;
        
        // Character count
        document.getElementById('charCount').textContent = `${typed.length} / ${referenceText.length}`;
        
        // Typing speed (WPM)
        const elapsed = (Date.now() - this.challengeStartTime) / 1000 / 60;
        const words = typed.split(' ').length;
        const wpm = elapsed > 0 ? Math.round(words / elapsed) : 0;
        document.getElementById('typingSpeed').textContent = `${wpm} WPM`;
        
        // Accuracy
        let correctChars = 0;
        const minLength = Math.min(typed.length, referenceText.length);
        
        for (let i = 0; i < minLength; i++) {
            if (typed[i] === referenceText[i]) {
                correctChars++;
            }
        }
        
        const accuracy = typed.length > 0 ? Math.round((correctChars / typed.length) * 100) : 100;
        document.getElementById('typingAccuracy').textContent = `${accuracy}%`;
        
        // Enable submit button when enough progress
        const progress = typed.length / referenceText.length;
        const submitBtn = document.getElementById('submitChallengeBtn');
        
        if (isAdaptive) {
            // Adaptive challenge requires more completion
            const adaptationProgress = Math.min(progress * 100, 100);
            document.getElementById('adaptationProgress').style.width = `${adaptationProgress}%`;
            document.getElementById('adaptationPercent').textContent = `${Math.round(adaptationProgress)}%`;
            
            submitBtn.disabled = progress < 0.8;
        } else {
            // Verification challenge requires high accuracy
            submitBtn.disabled = progress < 0.9 || accuracy < 85;
        }
    }
    
    updateRealtimeAnalysis() {
        // Simulate real-time behavioral analysis feedback
        const keystrokeCount = this.keystrokeData.length;
        
        if (keystrokeCount > 10) {
            document.getElementById('rhythmStatus').textContent = 'Normal';
            document.getElementById('rhythmStatus').className = 'metric-status status-good';
        }
        
        if (keystrokeCount > 20) {
            document.getElementById('timingStatus').textContent = 'Consistent';
            document.getElementById('timingStatus').className = 'metric-status status-good';
        }
        
        if (keystrokeCount > 30) {
            const confidence = Math.min(70 + keystrokeCount, 95);
            document.getElementById('patternStatus').textContent = 'Matching';
            document.getElementById('patternStatus').className = 'metric-status status-good';
            document.getElementById('confidenceStatus').textContent = `${confidence}%`;
            document.getElementById('confidenceStatus').className = 'metric-status status-good';
        }
    }
    
    async submitChallenge() {
        if (!this.challengeId) {
            this.showError('Invalid challenge session');
            return;
        }
        
        const isAdaptive = this.challengeType === 'adaptive';
        const input = document.getElementById(isAdaptive ? 'adaptiveInput' : 'challengeInput');
        const textContent = input.value;
        
        if (!textContent.trim()) {
            this.showError('Please complete the challenge text');
            return;
        }
        
        this.showLoading();
        
        try {
            const response = await this.apiCall('/api/challenge/submit', 'POST', {
                challenge_id: this.challengeId,
                text_content: textContent,
                keystroke_events: this.keystrokeData,
                mouse_events: this.mouseData
            });
            
            this.handleChallengeResult(response);
            
        } catch (error) {
            console.error('Challenge submission error:', error);
            this.showError('Failed to submit challenge response');
        } finally {
            this.hideLoading();
        }
    }
    
    handleChallengeResult(result) {
        this.isCollectingData = false;
        
        if (this.timerInterval) {
            clearInterval(this.timerInterval);
        }
        
        // Hide challenge content
        document.querySelector('.challenge-content').classList.add('hidden');
        document.querySelector('.challenge-controls').classList.add('hidden');
        
        // Show result
        const resultEl = document.getElementById('challengeResult');
        resultEl.classList.remove('hidden');
        
        if (result.result === 'passed') {
            this.showSuccessResult();
        } else if (result.result === 'failed') {
            this.showFailureResult(result);
        } else {
            this.showInconclusiveResult(result);
        }
    }
    
    showSuccessResult() {
        document.getElementById('successResult').classList.remove('hidden');
    }
    
    showFailureResult(result) {
        document.getElementById('failureResult').classList.remove('hidden');
        
        const message = result.details?.attempts_remaining > 0 
            ? `Verification failed. ${result.details.attempts_remaining} attempts remaining.`
            : 'Maximum attempts exceeded. Account will be temporarily locked.';
        
        document.getElementById('failureMessage').textContent = message;
        
        if (result.details?.attempts_remaining === 0) {
            setTimeout(() => this.showLockoutResult(), 2000);
        }
    }
    
    showInconclusiveResult(result) {
        document.getElementById('failureResult').classList.remove('hidden');
        document.getElementById('failureMessage').textContent = 'Verification was inconclusive. Please try again.';
    }
    
    showLockoutResult() {
        document.getElementById('failureResult').classList.add('hidden');
        document.getElementById('lockoutResult').classList.remove('hidden');
        
        // Start lockout countdown
        let remainingTime = 15 * 60; // 15 minutes
        
        this.countdownInterval = setInterval(() => {
            const minutes = Math.floor(remainingTime / 60);
            const seconds = remainingTime % 60;
            
            document.getElementById('lockoutCountdown').textContent = 
                `${minutes}:${seconds.toString().padStart(2, '0')}`;
            
            remainingTime--;
            
            if (remainingTime <= 0) {
                clearInterval(this.countdownInterval);
                window.location.href = '/login';
            }
        }, 1000);
    }
    
    handleTimeout() {
        this.isCollectingData = false;
        clearInterval(this.timerInterval);
        
        this.showError('Challenge timed out');
        setTimeout(() => this.logout(), 3000);
    }
    
    copyReferenceText() {
        const text = document.getElementById('challengeText').textContent;
        
        if (navigator.clipboard) {
            navigator.clipboard.writeText(text).then(() => {
                // Show feedback
                const btn = document.getElementById('copyTextBtn');
                const originalIcon = btn.innerHTML;
                btn.innerHTML = '<i class="fas fa-check"></i>';
                
                setTimeout(() => {
                    btn.innerHTML = originalIcon;
                }, 1000);
            });
        }
    }
    
    updateAttemptsRemaining(attempts) {
        document.getElementById('attemptsText').textContent = `${attempts} attempts remaining`;
        
        if (attempts <= 1) {
            document.getElementById('attemptsText').style.color = '#dc2626';
        } else if (attempts <= 2) {
            document.getElementById('attemptsText').style.color = '#d97706';
        }
    }
    
    toggleAnalysisPanel() {
        const panel = document.getElementById('analysisPanel');
        const toggle = document.getElementById('analysisPanelToggle');
        const content = panel.querySelector('.panel-content');
        
        if (content.style.display === 'none') {
            content.style.display = 'block';
            toggle.innerHTML = '<i class="fas fa-chevron-up"></i>';
        } else {
            content.style.display = 'none';
            toggle.innerHTML = '<i class="fas fa-chevron-down"></i>';
        }
    }
    
    showHelp() {
        document.getElementById('helpModal').classList.remove('hidden');
    }
    
    hideHelp() {
        document.getElementById('helpModal').classList.add('hidden');
    }
    
    continueToDashboard() {
        window.location.href = '/dashboard';
    }
    
    retryChallenge() {
        window.location.reload();
    }
    
    cancelChallenge() {
        if (confirm('Are you sure you want to cancel this security challenge?')) {
            window.location.href = '/dashboard';
        }
    }
    
    showLoading() {
        document.getElementById('challengeLoading')?.classList.remove('hidden');
    }
    
    hideLoading() {
        document.getElementById('challengeLoading')?.classList.add('hidden');
    }
    
    showError(message) {
        // Create or update error display
        let errorEl = document.querySelector('.challenge-error');
        
        if (!errorEl) {
            errorEl = document.createElement('div');
            errorEl.className = 'alert alert-danger challenge-error';
            document.querySelector('.challenge-container').prepend(errorEl);
        }
        
        errorEl.innerHTML = `
            <i class="fas fa-exclamation-circle"></i>
            <span>${message}</span>
        `;
        
        // Auto-hide after 5 seconds
        setTimeout(() => {
            errorEl?.remove();
        }, 5000);
    }
    
    async apiCall(endpoint, method = 'GET', data = null) {
        const token = localStorage.getItem('access_token');
        
        const config = {
            method,
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            }
        };
        
        if (data) {
            config.body = JSON.stringify(data);
        }
        
        const response = await fetch(endpoint, config);
        
        if (response.status === 401) {
            // Token expired, redirect to login
            this.logout();
            return;
        }
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        
        return await response.json();
    }
    
    logout() {
        localStorage.clear();
        window.location.href = '/login';
    }
}

// Initialize challenge manager when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new ChallengeManager();
});

// Global function for event details (referenced in dashboard)
function showEventDetails(eventId) {
    // Implementation for showing event details modal
    console.log('Show event details for:', eventId);
}
