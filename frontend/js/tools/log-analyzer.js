const API_BASE_URL = 'http://127.0.0.1:5000/api';

class LogAnalyzer {
    constructor() {
        this.apiEndpoints = {
            analyze: '/logs/analyze',
            upload: '/logs/upload'
        };
        this.initializeElements();
        this.bindEvents();
        this.chartInstances = {};
        console.log('LogAnalyzer initialized');
    }

    async apiRequest(endpoint, method = 'POST', data = null, isFormData = false) {
        try {
            const headers = !isFormData ? {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            } : {};

            const response = await fetch(`${API_BASE_URL}${endpoint}`, {
                method,
                headers,
                body: isFormData ? data : JSON.stringify(data),
            });

            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`Server error (${response.status}): ${errorText}`);
            }

            return await response.json();
        } catch (error) {
            console.error('API Error:', error);
            throw error;
        }
    }

    initializeElements() {
        this.elements = {
            form: document.getElementById('log-analyzer-form'),
            fileInput: document.getElementById('log-file'),
            dropZone: document.querySelector('.file-drop-zone'),
            fileContent: document.querySelector('.file-drop-content p'),
            resultsPanel: document.getElementById('analysis-results'),
            summaryElements: {
                totalLines: document.getElementById('total-lines'),
                totalErrors: document.getElementById('total-errors'),
                securityEvents: document.getElementById('security-events'),
                timeRange: document.getElementById('time-range')
            },
            tabButtons: document.querySelectorAll('.tab-button'),
            tabContent: document.querySelector('.tab-content'),
            charts: {
                timeline: document.getElementById('activity-timeline'),
                distribution: document.getElementById('event-distribution')
            }
        };

        // Store original text for file drop zone
        this.originalDropText = this.elements.fileContent.textContent;
    }

    bindEvents() {
        // Form submission
        this.elements.form.addEventListener('submit', this.handleSubmit.bind(this));

        // File input change
        this.elements.fileInput.addEventListener('change', this.handleFileChange.bind(this));

        // File drop zone events
        this.setupDropZone();

        // Make the entire drop zone clickable
        this.elements.dropZone.addEventListener('click', () => {
            this.elements.fileInput.click();
        });

        // Prevent click on file input from bubbling to drop zone
        this.elements.fileInput.addEventListener('click', (e) => {
            e.stopPropagation();
        });

        // Tab switching
        this.elements.tabButtons.forEach(button => {
            button.addEventListener('click', () => this.switchTab(button.dataset.tab));
        });

        // Export buttons
        document.getElementById('export-pdf')?.addEventListener('click', () => this.exportPDF());
        document.getElementById('export-json')?.addEventListener('click', () => this.exportJSON());
    }

    setupDropZone() {
        const dropZone = this.elements.dropZone;
        if (!dropZone) return;

        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
            });
        });

        ['dragenter', 'dragover'].forEach(eventName => {
            dropZone.addEventListener(eventName, () => {
                dropZone.classList.add('drag-over');
            });
        });

        ['dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, () => {
                dropZone.classList.remove('drag-over');
            });
        });

        dropZone.addEventListener('drop', this.handleFileDrop.bind(this));
    }

    async handleSubmit(e) {
        e.preventDefault();
        if (!this.validateFile()) return;

        try {
            this.setLoading(true);
            const formData = new FormData();
            const file = this.elements.fileInput.files[0];
            
            // Correct file field name to match Flask's expectation
            formData.append('file', file);  // Changed from 'log_file' to 'file'
            
            // Add analysis options as JSON string
            const options = {
                analyze_errors: document.querySelector('input[value="errors"]').checked,
                analyze_security: document.querySelector('input[value="security"]').checked,
                analyze_patterns: document.querySelector('input[value="patterns"]').checked,
                analyze_auth: document.querySelector('input[value="auth"]').checked
            };
            formData.append('options', JSON.stringify(options));

            const response = await fetch(`${API_BASE_URL}/analyze-logs`, {
                method: 'POST',
                // Remove explicit headers to let browser handle multipart boundary
                body: formData,
                // Add credentials if needed
                credentials: 'include'
            });

            const contentType = response.headers.get('content-type');
            if (!response.ok) {
                const errorText = contentType?.includes('application/json') 
                    ? (await response.json()).message 
                    : await response.text();
                throw new Error(errorText || 'Analysis failed');
            }

            const result = await response.json();
            if (result.success) {
                this.displayResults(result.data);
            } else {
                throw new Error(result.message || 'Analysis failed');
            }
        } catch (error) {
            this.showError(error.message);
            console.error('Analysis error:', error);
        } finally {
            this.setLoading(false);
        }
    }

    handleFileChange(e) {
        const file = e.target.files[0];
        if (file) {
            this.elements.fileContent.textContent = `Selected: ${file.name}`;
            this.elements.dropZone.classList.add('has-file');
        } else {
            this.elements.fileContent.textContent = this.originalDropText;
            this.elements.dropZone.classList.remove('has-file');
        }
    }

    handleFileDrop(e) {
        const file = e.dataTransfer.files[0];
        if (file) {
            this.elements.fileInput.files = e.dataTransfer.files;
            this.handleFileChange({ target: { files: [file] } });
        }
    }

    validateFile() {
        const file = this.elements.fileInput.files[0];
        if (!file) {
            this.showError('Please select a log file');
            return false;
        }

        if (!file.name.match(/\.(log|txt)$/i)) {
            this.showError('Only .log and .txt files are supported');
            return false;
        }

        if (file.size > 10 * 1024 * 1024) {
            this.showError('File size exceeds 10MB limit');
            return false;
        }

        return true;
    }

    displayResults(data) {
        this.elements.resultsPanel.classList.remove('hidden');
        this.updateSummary(data);
        this.createCharts(data);
        this.displayDetails(data);
    }

    updateSummary(data) {
        const { summaryElements } = this.elements;
        summaryElements.totalLines.textContent = data.total_lines;
        summaryElements.totalErrors.textContent = data.patterns_found.error?.length || 0;
        summaryElements.securityEvents.textContent = Object.values(data.threats_detected).flat().length;

        if (data.timeline.length > 0) {
            const start = new Date(data.timeline[0].timestamp);
            const end = new Date(data.timeline[data.timeline.length - 1].timestamp);
            const duration = Math.round((end - start) / 1000 / 60);
            summaryElements.timeRange.textContent = `${duration} minutes`;
        }
    }

    createCharts(data) {
        // Destroy existing charts if they exist
        if (this.chartInstances.timeline) {
            this.chartInstances.timeline.destroy();
        }
        if (this.chartInstances.distribution) {
            this.chartInstances.distribution.destroy();
        }

        // Create new charts
        this.chartInstances.timeline = new Chart(
            document.getElementById('activity-timeline'),
            {
                type: 'line',
                data: this.prepareTimelineData(data.statistics.hourly_activity),
                options: {
                    responsive: true,
                    plugins: {
                        title: { 
                            display: true, 
                            text: 'Activity Timeline',
                            color: getComputedStyle(document.documentElement)
                                .getPropertyValue('--text')
                        }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            grid: {
                                color: getComputedStyle(document.documentElement)
                                    .getPropertyValue('--border')
                            }
                        }
                    }
                }
            }
        );

        // Event Distribution Chart
        this.chartInstances.distribution = new Chart(
            document.getElementById('event-distribution'),
            {
                type: 'doughnut',
                data: this.prepareDistributionData(data.statistics),
                options: {
                    responsive: true,
                    plugins: {
                        title: { display: true, text: 'Event Distribution' }
                    }
                }
            }
        );
    }

    prepareTimelineData(hourlyData) {
        const labels = Object.keys(hourlyData);
        const data = Object.values(hourlyData);

        return {
            labels,
            datasets: [{
                label: 'Events',
                data,
                borderColor: 'rgb(59, 130, 246)',
                tension: 0.1
            }]
        };
    }

    prepareDistributionData(statistics) {
        const data = {
            labels: ['Errors', 'Auth Events', 'Security Events', 'Other'],
            datasets: [{
                data: [
                    Object.values(statistics.error_types).reduce((a, b) => a + b, 0),
                    Object.values(statistics.auth_events).reduce((a, b) => a + b, 0),
                    Object.values(statistics.threats || {}).reduce((a, b) => a + b, 0),
                    statistics.total_lines - (
                        Object.values(statistics.error_types).reduce((a, b) => a + b, 0) +
                        Object.values(statistics.auth_events).reduce((a, b) => a + b, 0)
                    )
                ],
                backgroundColor: [
                    'rgb(239, 68, 68)',
                    'rgb(59, 130, 246)',
                    'rgb(245, 158, 11)',
                    'rgb(107, 114, 128)'
                ]
            }]
        };

        return data;
    }

    displayDetails(data) {
        const tabContent = document.querySelector('.tab-content');
        tabContent.innerHTML = this.generateDetailsTabs(data);
    }

    generateDetailsTabs(data) {
        return `
            <div class="tab-pane active" id="errors-tab">
                ${this.generateErrorsList(data.patterns_found.error || [])}
            </div>
            <div class="tab-pane" id="security-tab">
                ${this.generateSecurityList(data.threats_detected || {})}
            </div>
            <div class="tab-pane" id="patterns-tab">
                ${this.generatePatternsList(data.statistics || {})}
            </div>
            <div class="tab-pane" id="raw-tab">
                <pre class="log-preview">${this.formatRawLogs(data.timeline || [])}</pre>
            </div>
        `;
    }

    // Add missing helper methods
    generateErrorsList(errors) {
        if (!errors || errors.length === 0) {
            return '<p class="empty-state">No errors found</p>';
        }
        return `
            <ul class="error-list">
                ${errors.map(error => `
                    <li class="error-item">
                        <i class="ph-warning-circle"></i>
                        <span>${this.escapeHtml(error)}</span>
                    </li>
                `).join('')}
            </ul>
        `;
    }

    generateSecurityList(threats) {
        const entries = Object.entries(threats);
        if (entries.length === 0) {
            return '<p class="empty-state">No security events detected</p>';
        }
        return `
            <ul class="security-list">
                ${entries.map(([type, events]) => `
                    <li class="security-group">
                        <h4>${this.formatTitle(type)}</h4>
                        <ul>
                            ${events.map(event => `
                                <li class="security-item">
                                    <i class="ph-shield-warning"></i>
                                    <span>${this.escapeHtml(event.line || event)}</span>
                                </li>
                            `).join('')}
                        </ul>
                    </li>
                `).join('')}
            </ul>
        `;
    }

    generatePatternsList(statistics) {
        return `
            <div class="patterns-grid">
                ${this.generateStatisticsSection('Error Types', statistics.error_types)}
                ${this.generateStatisticsSection('Authentication Events', statistics.auth_events)}
                ${this.generateStatisticsSection('IP Addresses', statistics.ip_addresses)}
            </div>
        `;
    }

    generateStatisticsSection(title, data) {
        if (!data || Object.keys(data).length === 0) {
            return '';
        }
        return `
            <div class="statistics-section">
                <h4>${title}</h4>
                <ul class="statistics-list">
                    ${Object.entries(data).map(([key, value]) => `
                        <li class="pattern-item">
                            <span class="pattern-key">${this.escapeHtml(key)}</span>
                            <span class="pattern-value">${value}</span>
                        </li>
                    `).join('')}
                </ul>
            </div>
        `;
    }

    formatRawLogs(timeline) {
        if (!timeline || timeline.length === 0) {
            return 'No log entries available';
        }
        return timeline.map(entry => 
            `[${entry.timestamp}] ${this.escapeHtml(entry.message)}`
        ).join('\n');
    }

    formatTitle(str) {
        return str.split('_')
            .map(word => word.charAt(0).toUpperCase() + word.slice(1))
            .join(' ');
    }

    escapeHtml(unsafe) {
        return unsafe
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    showError(message) {
        const alert = document.createElement('div');
        alert.className = 'error-message';
        alert.innerHTML = `
            <i class="ph-warning-circle"></i>
            <span>${message}</span>
        `;
        this.elements.form.appendChild(alert);
        setTimeout(() => alert.remove(), 5000);
    }

    setLoading(isLoading) {
        const button = this.elements.form.querySelector('button[type="submit"]');
        button.disabled = isLoading;
        button.innerHTML = isLoading ? 
            '<i class="ph-spinner ph-spin"></i> Analyzing...' : 
            '<i class="ph-magnifying-glass"></i> Analyze Logs';
    }

    switchTab(tabId) {
        this.elements.tabButtons.forEach(btn => {
            btn.classList.toggle('active', btn.dataset.tab === tabId);
        });
        const panes = document.querySelectorAll('.tab-pane');
        panes.forEach(pane => {
            pane.classList.toggle('active', pane.id === `${tabId}-tab`);
        });
    }

    async exportPDF() {
        try {
            const { jsPDF } = window.jspdf;
            const doc = new jsPDF();
            let yOffset = 20;
            const lineHeight = 10;

            // Add title
            doc.setFontSize(20);
            doc.text('Log Analysis Report', 20, yOffset);
            yOffset += lineHeight * 2;

            // Add summary section
            doc.setFontSize(16);
            doc.text('Summary', 20, yOffset);
            yOffset += lineHeight * 1.5;

            // Add summary data
            doc.setFontSize(12);
            const summaryData = [
                `Total Lines: ${this.elements.summaryElements.totalLines.textContent}`,
                `Errors Found: ${this.elements.summaryElements.totalErrors.textContent}`,
                `Security Events: ${this.elements.summaryElements.securityEvents.textContent}`,
                `Time Range: ${this.elements.summaryElements.timeRange.textContent}`
            ];

            summaryData.forEach(line => {
                doc.text(line, 30, yOffset);
                yOffset += lineHeight;
            });
            yOffset += lineHeight;

            // Add charts as images
            doc.setFontSize(16);
            doc.text('Charts', 20, yOffset);
            yOffset += lineHeight * 1.5;

            // Convert charts to images
            const timelineCanvas = document.getElementById('activity-timeline');
            const distributionCanvas = document.getElementById('event-distribution');

            if (timelineCanvas) {
                const timelineImg = timelineCanvas.toDataURL('image/png');
                doc.addImage(timelineImg, 'PNG', 20, yOffset, 170, 80);
                yOffset += 90;
            }

            if (distributionCanvas) {
                const distributionImg = distributionCanvas.toDataURL('image/png');
                doc.addImage(distributionImg, 'PNG', 20, yOffset, 170, 80);
                yOffset += 90;
            }

            // Add timestamp
            doc.setFontSize(10);
            doc.setTextColor(128);
            doc.text(
                `Generated on ${new Date().toLocaleString()}`,
                20,
                doc.internal.pageSize.height - 10
            );

            // Save the PDF
            doc.save('log-analysis-report.pdf');
        } catch (error) {
            this.showError('Failed to generate PDF report');
            console.error('PDF generation error:', error);
        }
    }

    exportJSON() {
        try {
            // Gather all analysis data
            const exportData = {
                summary: {
                    totalLines: this.elements.summaryElements.totalLines.textContent,
                    totalErrors: this.elements.summaryElements.totalErrors.textContent,
                    securityEvents: this.elements.summaryElements.securityEvents.textContent,
                    timeRange: this.elements.summaryElements.timeRange.textContent
                },
                charts: {
                    timeline: this.chartInstances.timeline?.config.data,
                    distribution: this.chartInstances.distribution?.config.data
                },
                details: {
                    errors: Array.from(document.querySelectorAll('#errors-tab .error-item'))
                        .map(el => el.textContent),
                    security: Array.from(document.querySelectorAll('#security-tab .security-item'))
                        .map(el => el.textContent),
                    patterns: Array.from(document.querySelectorAll('#patterns-tab .pattern-item'))
                        .map(el => el.textContent)
                },
                metadata: {
                    exportDate: new Date().toISOString(),
                    toolVersion: '1.0.0'
                }
            };

            // Create and download JSON file
            const blob = new Blob([JSON.stringify(exportData, null, 2)], {
                type: 'application/json'
            });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `log-analysis-report-${new Date().toISOString().slice(0,10)}.json`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);

            // Show success message
            this.showSuccess('Analysis report exported successfully');
        } catch (error) {
            this.showError('Failed to export analysis report');
            console.error('JSON export error:', error);
        }
    }

    showSuccess(message) {
        const alert = document.createElement('div');
        alert.className = 'success-message';
        alert.innerHTML = `
            <i class="ph-check-circle"></i>
            <span>${message}</span>
        `;
        this.elements.form.appendChild(alert);
        setTimeout(() => alert.remove(), 3000);
    }
}

// Export the class properly
export default LogAnalyzer;
