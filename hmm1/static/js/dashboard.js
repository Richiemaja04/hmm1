// ==========================================
// static/js/dashboard.js
/**
 * Dashboard Page JavaScript
 * Handles real-time monitoring, charts, and user interface
 */

class DashboardManager {
    constructor() {
        this.socket = null;
        this.charts = {};
        this.currentSection = 'overview';
        this.behavioralData = {
            keystroke: [],
            mouse: []
        };
        this.dataCollectionInterval = null;
        this.isMonitoring = false;
        this.sessionStartTime = Date.now();
        
        this.init();
    }
    
    init() {
        this.bindEvents();
        this.initializeCharts();
        this.connectWebSocket();
        this.loadUserInfo();
        this.startBehavioralCollection();
        this.showSection('overview');
    }
    
    bindEvents() {
        // Navigation
        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                const section = item.dataset.section;
                this.showSection(section);
            });
        });
        
        // User menu
        document.getElementById('userMenuBtn')?.addEventListener('click', () => this.toggleUserMenu());
        document.getElementById('logoutBtn')?.addEventListener('click', () => this.logout());
        
        // Controls
        document.getElementById('refreshBtn')?.addEventListener('click', () => this.refreshData());
        
        // Settings
        document.getElementById('saveSettingsBtn')?.addEventListener('click', () => this.saveSettings());
        document.getElementById('recalibrateBtn')?.addEventListener('click', () => this.startRecalibration());
        
        // Close dropdowns when clicking outside
        document.addEventListener('click', (e) => {
            if (!e.target.closest('.user-menu')) {
                document.getElementById('userDropdown')?.classList.add('hidden');
            }
        });
    }
    
    showSection(sectionName) {
        // Update navigation
        document.querySelectorAll('.nav-item').forEach(item => {
            item.classList.remove('active');
        });
        document.querySelector(`[data-section="${sectionName}"]`)?.classList.add('active');
        
        // Show section
        document.querySelectorAll('.dashboard-section').forEach(section => {
            section.classList.remove('active');
        });
        document.getElementById(`${sectionName}Section`)?.classList.add('active');
        
        this.currentSection = sectionName;
        
        // Load section-specific data
        this.loadSectionData(sectionName);
    }
    
    async loadSectionData(section) {
        switch (section) {
            case 'analytics':
                await this.loadAnalyticsData();
                break;
            case 'security':
                await this.loadSecurityEvents();
                break;
        }
    }
    
    connectWebSocket() {
        const token = localStorage.getItem('access_token');
        
        this.socket = io({
            auth: {
                token: token
            }
        });
        
        this.socket.on('connect', () => {
            console.log('WebSocket connected');
            this.updateMonitoringStatus(true);
        });
        
        this.socket.on('disconnect', () => {
            console.log('WebSocket disconnected');
            this.updateMonitoringStatus(false);
        });
        
        this.socket.on('analysis_result', (data) => {
            this.handleAnalysisResult(data);
        });
        
        this.socket.on('challenge_required', (data) => {
            this.handleChallengeRequired(data);
        });
        
        this.socket.on('session_blocked', (data) => {
            this.handleSessionBlocked(data);
        });
        
        this.socket.on('notification', (data) => {
            this.showNotification(data);
        });
    }
    
    startBehavioralCollection() {
        this.isMonitoring = true;
        
        // Collect keystroke events globally
        document.addEventListener('keydown', (e) => this.recordKeystroke(e, 'keydown'));
        document.addEventListener('keyup', (e) => this.recordKeystroke(e, 'keyup'));
        
        // Collect mouse events
        document.addEventListener('mousemove', (e) => this.recordMouseEvent(e, 'mousemove'));
        document.addEventListener('click', (e) => this.recordMouseEvent(e, 'click'));
        document.addEventListener('wheel', (e) => this.recordMouseEvent(e, 'wheel'));
        
        // Send data every 30 seconds
        this.dataCollectionInterval = setInterval(() => {
            this.sendBehavioralData();
        }, 30000);
        
        // Also send immediately for faster initial analysis
        setTimeout(() => this.sendBehavioralData(), 5000);
    }
    
    recordKeystroke(event, type) {
        if (!this.isMonitoring) return;
        
        // Skip if from hidden input or password fields
        if (event.target.type === 'password' || event.target.id === 'hiddenInput') return;
        
        this.behavioralData.keystroke.push({
            type,
            key: event.key,
            keyCode: event.keyCode,
            timestamp: Date.now(),
            ctrlKey: event.ctrlKey,
            shiftKey: event.shiftKey,
            altKey: event.altKey,
            metaKey: event.metaKey
        });
        
        // Keep only recent data
        if (this.behavioralData.keystroke.length > 200) {
            this.behavioralData.keystroke = this.behavioralData.keystroke.slice(-200);
        }
    }
    
    recordMouseEvent(event, type) {
        if (!this.isMonitoring) return;
        
        const eventData = {
            type,
            clientX: event.clientX,
            clientY: event.clientY,
            timestamp: Date.now()
        };
        
        if (type === 'click') {
            eventData.button = event.button;
        }
        
        if (type === 'wheel') {
            eventData.deltaY = event.deltaY;
            eventData.deltaX = event.deltaX;
        }
        
        this.behavioralData.mouse.push(eventData);
        
        // Keep only recent data
        if (this.behavioralData.mouse.length > 500) {
            this.behavioralData.mouse = this.behavioralData.mouse.slice(-500);
        }
    }
    
    sendBehavioralData() {
        if (!this.socket || !this.isMonitoring) return;
        
        if (this.behavioralData.keystroke.length < 5 && this.behavioralData.mouse.length < 10) {
            return; // Not enough data
        }
        
        const data = {
            keystroke_events: [...this.behavioralData.keystroke],
            mouse_events: [...this.behavioralData.mouse],
            window_duration: 30.0
        };
        
        this.socket.emit('behavioral_data', data);
        
        // Clear sent data
        this.behavioralData.keystroke = [];
        this.behavioralData.mouse = [];
    }
    
    handleAnalysisResult(data) {
        // Update risk indicator
        this.updateRiskIndicator(data.risk_level, data.anomaly_score);
        
        // Update real-time charts if on overview
        if (this.currentSection === 'overview') {
            this.updateRealtimeCharts(data);
        }
        
        // Show notification for high risk
        if (data.risk_level === 'high' || data.risk_level === 'critical') {
            this.showNotification({
                type: 'security_alert',
                data: {
                    message: 'High-risk behavioral pattern detected',
                    risk_level: data.risk_level
                }
            });
        }
    }
    
    handleChallengeRequired(data) {
        this.showNotification({
            type: 'challenge_required',
            data: {
                message: 'Security verification required',
                challenge_type: data.challenge_type
            }
        });
        
        // Redirect to challenge after a short delay
        setTimeout(() => {
            window.location.href = data.redirect_url || '/challenge';
        }, 2000);
    }
    
    handleSessionBlocked(data) {
        this.showNotification({
            type: 'session_blocked',
            data: {
                message: data.message,
                reason: data.reason
            }
        });
        
        // Force logout after showing message
        setTimeout(() => {
            this.logout();
        }, 3000);
    }
    
    updateRiskIndicator(riskLevel, score) {
        const riskIndicator = document.getElementById('riskIndicator');
        const riskLevelEl = document.getElementById('riskLevel');
        const riskScoreEl = document.getElementById('riskScore');
        const icon = riskIndicator.querySelector('.risk-icon i');
        
        // Update colors and text based on risk level
        let colorClass = 'status-good';
        let iconClass = 'fas fa-shield-check';
        let displayText = 'Low Risk';
        
        switch (riskLevel) {
            case 'medium':
                colorClass = 'status-warning';
                iconClass = 'fas fa-shield-alt';
                displayText = 'Medium Risk';
                break;
            case 'high':
                colorClass = 'status-danger';
                iconClass = 'fas fa-shield-exclamation';
                displayText = 'High Risk';
                break;
            case 'critical':
                colorClass = 'status-danger';
                iconClass = 'fas fa-ban';
                displayText = 'Critical Risk';
                break;
        }
        
        // Update indicator
        riskIndicator.className = `risk-indicator ${colorClass}`;
        icon.className = iconClass;
        riskLevelEl.textContent = displayText;
        riskScoreEl.textContent = `Security: ${Math.round((1 - score) * 100)}%`;
    }
    
    updateMonitoringStatus(connected) {
        const statusEl = document.getElementById('monitoringStatus');
        const indicator = statusEl.querySelector('.status-indicator');
        const text = statusEl.querySelector('.status-text');
        
        if (connected) {
            indicator.style.color = '#059669';
            text.textContent = 'Monitoring Active';
        } else {
            indicator.style.color = '#dc2626';
            text.textContent = 'Connection Lost';
        }
    }
    
    initializeCharts() {
        // Typing Speed Chart
        const typingCtx = document.getElementById('typingSpeedChart')?.getContext('2d');
        if (typingCtx) {
            this.charts.typingSpeed = new Chart(typingCtx, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'WPM',
                        data: [],
                        borderColor: '#2563eb',
                        backgroundColor: 'rgba(37, 99, 235, 0.1)',
                        fill: true,
                        tension: 0.4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            beginAtZero: true,
                            title: {
                                display: true,
                                text: 'Words per Minute'
                            }
                        },
                        x: {
                            title: {
                                display: true,
                                text: 'Time'
                            }
                        }
                    },
                    plugins: {
                        legend: {
                            display: false
                        }
                    }
                }
            });
        }
        
        // Anomaly Pie Chart
        const anomalyCtx = document.getElementById('anomalyPieChart')?.getContext('2d');
        if (anomalyCtx) {
            this.charts.anomalyPie = new Chart(anomalyCtx, {
                type: 'doughnut',
                data: {
                    labels: ['Normal', 'Low Risk', 'Medium Risk', 'High Risk'],
                    datasets: [{
                        data: [85, 10, 4, 1],
                        backgroundColor: ['#059669', '#d97706', '#dc2626', '#7c2d12']
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom'
                        }
                    }
                }
            });
        }
    }
    
    updateRealtimeCharts(data) {
        // Update typing speed chart
        if (this.charts.typingSpeed && data.typing_speed) {
            const chart = this.charts.typingSpeed;
            const now = new Date().toLocaleTimeString();
            
            chart.data.labels.push(now);
            chart.data.datasets[0].data.push(data.typing_speed);
            
            // Keep only last 20 data points
            if (chart.data.labels.length > 20) {
                chart.data.labels.shift();
                chart.data.datasets[0].data.shift();
            }
            
            chart.update('none'); // No animation for real-time
        }
    }
    
    async loadAnalyticsData() {
        try {
            const response = await this.apiCall('/api/dashboard/analytics');
            this.updateAnalyticsCharts(response);
        } catch (error) {
            console.error('Failed to load analytics:', error);
        }
    }
    
    updateAnalyticsCharts(data) {
        // Update feature deviation chart
        const featureCtx = document.getElementById('featureDeviationChart')?.getContext('2d');
        if (featureCtx && data.feature_deviations) {
            if (this.charts.featureDeviation) {
                this.charts.featureDeviation.destroy();
            }
            
            this.charts.featureDeviation = new Chart(featureCtx, {
                type: 'bar',
                data: {
                    labels: data.feature_deviations.map(f => f.feature),
                    datasets: [{
                        label: 'Deviation Score',
                        data: data.feature_deviations.map(f => f.deviation),
                        backgroundColor: 'rgba(37, 99, 235, 0.6)',
                        borderColor: '#2563eb'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    indexAxis: 'y',
                    plugins: {
                        legend: {
                            display: false
                        }
                    }
                }
            });
        }
    }
    
    async loadSecurityEvents() {
        try {
            const response = await this.apiCall('/api/dashboard/security-events');
            this.updateEventsTable(response.events);
        } catch (error) {
            console.error('Failed to load security events:', error);
        }
    }
    
    updateEventsTable(events) {
        const tbody = document.getElementById('eventsTableBody');
        if (!tbody) return;
        
        tbody.innerHTML = '';
        
        events.forEach(event => {
            const row = document.createElement('tr');
            
            const formatTime = (timestamp) => {
                return new Date(timestamp).toLocaleString();
            };
            
            const getRiskBadge = (risk) => {
                if (!risk) return '';
                const level = risk > 0.7 ? 'high' : risk > 0.4 ? 'medium' : 'low';
                return `<span class="risk-badge risk-${level}">${Math.round(risk * 100)}%</span>`;
            };
            
            row.innerHTML = `
                <td>${formatTime(event.timestamp)}</td>
                <td><span class="event-type">${event.event_type}</span></td>
                <td><span class="status-${event.event_status}">${event.event_status}</span></td>
                <td>${getRiskBadge(event.risk_score)}</td>
                <td>${event.action_taken || 'None'}</td>
                <td><button class="btn btn-sm" onclick="showEventDetails('${event.id}')">View</button></td>
            `;
            
            tbody.appendChild(row);
        });
    }
    
    async loadUserInfo() {
        try {
            const response = await this.apiCall('/api/dashboard/user-info');
            
            // Update welcome message
            document.getElementById('userWelcome').textContent = `Welcome, ${response.user.username}`;
            
            // Update session time
            this.updateSessionTime();
            setInterval(() => this.updateSessionTime(), 1000);
            
        } catch (error) {
            console.error('Failed to load user info:', error);
        }
    }
    
    updateSessionTime() {
        const elapsed = Date.now() - this.sessionStartTime;
        const hours = Math.floor(elapsed / 3600000);
        const minutes = Math.floor((elapsed % 3600000) / 60000);
        const seconds = Math.floor((elapsed % 60000) / 1000);
        
        const sessionTimeEl = document.getElementById('sessionTime');
        if (sessionTimeEl) {
            sessionTimeEl.textContent = `${hours}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
        }
    }
    
    toggleUserMenu() {
        const dropdown = document.getElementById('userDropdown');
        dropdown.classList.toggle('hidden');
    }
    
    showNotification(notification) {
        const toast = document.getElementById('notificationToast');
        const icon = toast.querySelector('.toast-icon');
        const title = toast.querySelector('.toast-title');
        const text = toast.querySelector('.toast-text');
        
        // Set icon and styling based on type
        switch (notification.type) {
            case 'security_alert':
                icon.className = 'fas fa-shield-exclamation toast-icon';
                title.textContent = 'Security Alert';
                break;
            case 'challenge_required':
                icon.className = 'fas fa-exclamation-triangle toast-icon';
                title.textContent = 'Verification Required';
                break;
            case 'session_blocked':
                icon.className = 'fas fa-ban toast-icon';
                title.textContent = 'Session Blocked';
                break;
            default:
                icon.className = 'fas fa-info-circle toast-icon';
                title.textContent = 'Notification';
        }
        
        text.textContent = notification.data.message;
        
        // Show toast
        toast.classList.remove('hidden');
        toast.classList.add('show');
        
        // Auto-hide after 5 seconds
        setTimeout(() => {
            toast.classList.remove('show');
            toast.classList.add('hidden');
        }, 5000);
        
        // Close button
        toast.querySelector('.toast-close').onclick = () => {
            toast.classList.remove('show');
            toast.classList.add('hidden');
        };
    }
    
    refreshData() {
        this.loadSectionData(this.currentSection);
        this.showNotification({
            type: 'info',
            data: { message: 'Data refreshed successfully' }
        });
    }
    
    startRecalibration() {
        if (confirm('This will start a new calibration process. Continue?')) {
            window.location.href = '/calibration';
        }
    }
    
    async saveSettings() {
        // Collect settings data
        const settings = {
            continuous_monitoring: document.getElementById('continuousMonitoring')?.checked,
            challenge_frequency: document.getElementById('challengeFrequency')?.value,
            risk_sensitivity: document.getElementById('riskSensitivity')?.value,
            security_alerts: document.getElementById('securityAlerts')?.checked,
            email_notifications: document.getElementById('emailNotifications')?.checked
        };
        
        try {
            // In a real implementation, you would save to backend
            console.log('Saving settings:', settings);
            this.showNotification({
                type: 'success',
                data: { message: 'Settings saved successfully' }
            });
        } catch (error) {
            console.error('Failed to save settings:', error);
            this.showNotification({
                type: 'error',
                data: { message: 'Failed to save settings' }
            });
        }
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
        // Stop monitoring
        this.isMonitoring = false;
        if (this.dataCollectionInterval) {
            clearInterval(this.dataCollectionInterval);
        }
        
        // Disconnect socket
        if (this.socket) {
            this.socket.disconnect();
        }
        
        // Clear storage and redirect
        localStorage.clear();
        window.location.href = '/login';
    }
}

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new DashboardManager();
});
