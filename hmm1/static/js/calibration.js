// ==========================================
// static/js/calibration.js
/**
 * Calibration Page JavaScript
 * Handles behavioral profile creation and training
 */

class CalibrationManager {
    constructor() {
        this.sessionId = null;
        this.currentTaskIndex = 0;
        this.tasks = [];
        this.keystrokeData = [];
        this.mouseData = [];
        this.isCollectingData = false;
        this.taskStartTime = null;
        this.currentScreen = 'welcome';
        
        this.init();
    }
    
    init() {
        this.bindEvents();
        this.showScreen('welcome');
    }
    
    bindEvents() {
        // Navigation
        document.getElementById('startCalibrationBtn')?.addEventListener('click', () => this.startCalibration());
        document.getElementById('completeTaskBtn')?.addEventListener('click', () => this.completeCurrentTask());
        document.getElementById('skipTaskBtn')?.addEventListener('click', () => this.skipCurrentTask());
        document.getElementById('continueToApp')?.addEventListener('click', () => this.continueToApp());
        document.getElementById('retryCalibrationBtn')?.addEventListener('click', () => this.retryCalibration());
        document.getElementById('logoutBtn')?.addEventListener('click', () => this.logout());
        
        // Task input monitoring
        document.getElementById('typingArea')?.addEventListener('input', () => this.updateTaskMetrics());
        document.getElementById('typingArea')?.addEventListener('keydown', (e) => this.recordKeystroke(e, 'keydown'));
        document.getElementById('typingArea')?.addEventListener('keyup', (e) => this.recordKeystroke(e, 'keyup'));
        
        // Mouse event collection
        document.addEventListener('mousemove', (e) => this.recordMouseEvent(e, 'mousemove'));
        document.addEventListener('click', (e) => this.recordMouseEvent(e, 'click'));
    }
    
    showScreen(screenName) {
        // Hide all screens
        document.querySelectorAll('.calibration-screen').forEach(screen => {
            screen.classList.remove('active');
        });
        
        // Show target screen
        document.getElementById(`${screenName}Screen`).classList.add('active');
        this.currentScreen = screenName;
    }
    
    async startCalibration() {
        this.showLoadingOverlay('Initializing calibration...');
        
        try {
            const response = await this.apiCall('/api/calibration/start', 'POST');
            
            if (response.session_id) {
                this.sessionId = response.session_id;
                this.tasks = response.tasks;
                this.currentTaskIndex = 0;
                
                this.updateProgress();
                this.showNextTask();
                this.startBehavioralCollection();
            } else {
                this.showError('Failed to initialize calibration');
            }
        } catch (error) {
            console.error('Calibration start error:', error);
            this.showError('Network error during calibration setup');
        } finally {
            this.hideLoadingOverlay();
        }
    }
    
    showNextTask() {
        if (this.currentTaskIndex >= this.tasks.length) {
            this.processingPhase();
            return;
        }
        
        const task = this.tasks[this.currentTaskIndex];
        this.setupTask(task);
        this.showScreen('task');
        this.taskStartTime = Date.now();
        this.resetBehavioralData();
    }
    
    setupTask(task) {
        document.getElementById('taskNumber').textContent = `Task ${this.currentTaskIndex + 1} of ${this.tasks.length}`;
        document.getElementById('taskTitle').textContent = task.title;
        document.getElementById('taskInstruction').textContent = task.instruction;
        
        const typingArea = document.getElementById('typingArea');
        const referenceText = document.getElementById('referenceText');
        const mouseTaskArea = document.getElementById('mouseTaskArea');
        
        if (task.type === 'typing' || task.type === 'mixed') {
            referenceText.textContent = task.text;
            typingArea.value = '';
            typingArea.style.display = 'block';
            mouseTaskArea.classList.add('hidden');
            
            // Focus on typing area
            setTimeout(() => typingArea.focus(), 100);
        } else if (task.type === 'mouse') {
            this.setupMouseTask();
            typingArea.style.display = 'none';
            mouseTaskArea.classList.remove('hidden');
        }
        
        this.updateTaskMetrics();
        this.startTaskTimer();
    }
    
    setupMouseTask() {
        const clickSequence = document.getElementById('clickSequence');
        clickSequence.innerHTML = '';
        
        // Generate click targets
        const targets = ['Start', 'Navigate', 'Select', 'Confirm', 'Complete'];
        let clickOrder = 0;
        
        targets.forEach((text, index) => {
            const button = document.createElement('button');
            button.className = 'click-target btn btn-secondary';
            button.textContent = text;
            button.style.margin = '10px';
            
            button.addEventListener('click', () => {
                if (index === clickOrder) {
                    button.classList.remove('btn-secondary');
                    button.classList.add('btn-primary');
                    button.disabled = true;
                    clickOrder++;
                    
                    if (clickOrder >= targets.length) {
                        document.getElementById('completeTaskBtn').disabled = false;
                    }
                }
            });
            
            clickSequence.appendChild(button);
        });
    }
    
    updateTaskMetrics() {
        const typingArea = document.getElementById('typingArea');
        const referenceText = document.getElementById('referenceText');
        
        if (!typingArea || !referenceText) return;
        
        const typed = typingArea.value;
        const reference = referenceText.textContent;
        
        // Character count
        document.getElementById('charCount').textContent = typed.length;
        
        // WPM calculation
        const timeElapsed = (Date.now() - this.taskStartTime) / 1000 / 60; // minutes
        const wordsTyped = typed.split(' ').length;
        const wpm = timeElapsed > 0 ? Math.round(wordsTyped / timeElapsed) : 0;
        document.getElementById('wpmCount').textContent = wpm;
        
        // Accuracy calculation
        let correctChars = 0;
        const minLength = Math.min(typed.length, reference.length);
        
        for (let i = 0; i < minLength; i++) {
            if (typed[i] === reference[i]) {
                correctChars++;
            }
        }
        
        const accuracy = typed.length > 0 ? Math.round((correctChars / typed.length) * 100) : 100;
        document.getElementById('accuracyCount').textContent = `${accuracy}%`;
        
        // Enable complete button when sufficient progress
        const progress = typed.length / reference.length;
        const completeBtn = document.getElementById('completeTaskBtn');
        completeBtn.disabled = progress < 0.8; // 80% completion required
        
        // Update data quality
        this.updateDataQuality();
    }
    
    startTaskTimer() {
        const timerEl = document.getElementById('taskTimer');
        const startTime = Date.now();
        
        this.taskTimerInterval = setInterval(() => {
            const elapsed = Math.floor((Date.now() - startTime) / 1000);
            const minutes = Math.floor(elapsed / 60);
            const seconds = elapsed % 60;
            timerEl.textContent = `${minutes}:${seconds.toString().padStart(2, '0')}`;
        }, 1000);
    }
    
    async completeCurrentTask() {
        if (this.taskTimerInterval) {
            clearInterval(this.taskTimerInterval);
        }
        
        this.showLoadingOverlay('Processing task data...');
        
        try {
            const taskData = {
                session_id: this.sessionId,
                task_index: this.currentTaskIndex,
                keystroke_events: this.keystrokeData,
                mouse_events: this.mouseData,
                task_completion_time: (Date.now() - this.taskStartTime) / 1000
            };
            
            const response = await this.apiCall('/api/calibration/submit-data', 'POST', taskData);
            
            if (response.task_completed) {
                this.currentTaskIndex++;
                this.updateProgress();
                
                if (response.calibration_complete) {
                    if (response.training_started) {
                        this.processingPhase();
                    } else {
                        this.showError('Insufficient data quality. Please try again.');
                    }
                } else {
                    this.showNextTask();
                }
            } else {
                this.showError('Failed to complete task');
            }
        } catch (error) {
            console.error('Task completion error:', error);
            this.showError('Network error during task submission');
        } finally {
            this.hideLoadingOverlay();
        }
    }
    
    skipCurrentTask() {
        this.currentTaskIndex++;
        this.updateProgress();
        this.showNextTask();
    }
    
    async processingPhase() {
        this.showScreen('processing');
        this.updateProcessingSteps();
        
        // Poll for training completion
        this.pollTrainingStatus();
    }
    
    async pollTrainingStatus() {
        try {
            const response = await this.apiCall(`/api/calibration/status/${this.sessionId}`);
            
            if (response.training_status === 'completed') {
                this.showCompletion(response);
            } else if (response.training_status === 'failed') {
                this.showError('Model training failed');
            } else {
                // Continue polling
                setTimeout(() => this.pollTrainingStatus(), 2000);
            }
        } catch (error) {
            console.error('Status polling error:', error);
            setTimeout(() => this.pollTrainingStatus(), 5000);
        }
    }
    
    updateProcessingSteps() {
        const steps = [
            { id: 'step1', icon: 'fas fa-check', text: 'Data collection complete' },
            { id: 'step2', icon: 'fas fa-spinner fa-spin', text: 'Extracting behavioral features' },
            { id: 'step3', icon: 'fas fa-hourglass-half', text: 'Training machine learning models' },
            { id: 'step4', icon: 'fas fa-hourglass-half', text: 'Validating security profile' }
        ];
        
        let currentStep = 0;
        const interval = setInterval(() => {
            if (currentStep < steps.length - 1) {
                const step = document.getElementById(steps[currentStep].id);
                const nextStep = document.getElementById(steps[currentStep + 1].id);
                
                if (step) {
                    step.querySelector('i').className = 'fas fa-check';
                    step.classList.add('active');
                }
                
                if (nextStep) {
                    nextStep.querySelector('i').className = 'fas fa-spinner fa-spin';
                    nextStep.classList.add('active');
                }
                
                currentStep++;
            } else {
                clearInterval(interval);
            }
        }, 3000);
    }
    
    showCompletion(data) {
        this.showScreen('completion');
        
        // Update completion metrics
        if (data.model_accuracy) {
            document.getElementById('typingAccuracy').textContent = `${Math.round(data.model_accuracy * 100)}% accuracy`;
        }
    }
    
    continueToApp() {
        window.location.href = '/dashboard';
    }
    
    retryCalibration() {
        this.currentTaskIndex = 0;
        this.sessionId = null;
        this.resetBehavioralData();
        this.startCalibration();
    }
    
    updateProgress() {
        const progress = (this.currentTaskIndex / this.tasks.length) * 100;
        document.getElementById('progressFill').style.width = `${progress}%`;
        document.getElementById('progressText').textContent = `${Math.round(progress)}% Complete`;
    }
    
    startBehavioralCollection() {
        this.isCollectingData = true;
    }
    
    resetBehavioralData() {
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
    
    updateDataQuality() {
        const keystrokeCount = this.keystrokeData.length;
        const mouseCount = this.mouseData.length;
        
        // Calculate quality based on event counts and distribution
        let quality = 0.5; // Base quality
        
        if (keystrokeCount > 20) quality += 0.2;
        if (keystrokeCount > 50) quality += 0.1;
        if (mouseCount > 30) quality += 0.2;
        
        quality = Math.min(quality, 1.0);
        
        const qualityFill = document.getElementById('qualityFill');
        const qualityText = document.getElementById('qualityText');
        
        if (qualityFill) {
            qualityFill.style.width = `${quality * 100}%`;
        }
        
        if (qualityText) {
            if (quality > 0.8) {
                qualityText.textContent = 'Excellent';
                qualityFill.style.background = '#059669';
            } else if (quality > 0.6) {
                qualityText.textContent = 'Good';
                qualityFill.style.background = '#d97706';
            } else {
                qualityText.textContent = 'Fair';
                qualityFill.style.background = '#dc2626';
            }
        }
    }
    
    showError(message) {
        this.showScreen('error');
        document.getElementById('errorMessage').textContent = message;
    }
    
    showLoadingOverlay(message) {
        // Implementation depends on your loading overlay structure
        console.log('Loading:', message);
    }
    
    hideLoadingOverlay() {
        // Implementation depends on your loading overlay structure
        console.log('Loading complete');
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

// Initialize calibration manager when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new CalibrationManager();
});
