export default class LogAnalyzer {
    constructor() {
        this.initializeElements();
        this.bindEvents();
        this.setupDropZone();
    }

    initializeElements() {
        this.elements = {
            form: document.getElementById('log-analyzer-form'),
            fileInput: document.getElementById('log-file'),
            resultsPanel: document.getElementById('analysis-results'),
            summaryElements: {
                totalLines: document.getElementById('total-lines'),
                totalErrors: document.getElementById('total-errors'),
                securityEvents: document.getElementById('security-events'),
                timeRange: document.getElementById('time-range')
            },
            charts: {
                timeline: document.getElementById('activity-timeline'),
                distribution: document.getElementById('event-distribution')
            },
            tabButtons: document.querySelectorAll('.tab-button'),
            tabContent: document.querySelector('.tab-content'),
            exportButtons: {
                pdf: document.getElementById('export-pdf'),
                json: document.getElementById('export-json')
            }
        };
    }

    bindEvents() {
        // Form submission
        this.elements.form.addEventListener('submit', async (e) => {
            e.preventDefault();
            await this.analyzeLog();
        });

        // Tab switching
        this.elements.tabButtons.forEach(button => {
            button.addEventListener('click', () => {
                this.switchTab(button.dataset.tab);
            });
        });

        // Export functions
        if (this.elements.exportButtons.pdf) {
            this.elements.exportButtons.pdf.addEventListener('click', () => this.exportResults('pdf'));
        }
        if (this.elements.exportButtons.json) {
            this.elements.exportButtons.json.addEventListener('click', () => this.exportResults('json'));
        }
    }

    setupDropZone() {
        const dropZone = document.querySelector('.file-drop-zone');
        const fileInput = document.getElementById('log-file');
        const contentText = dropZone.querySelector('p');
        const originalText = contentText.textContent;
        
        if (!dropZone || !fileInput) {
            console.error('Drop zone elements not found');
            return;
        }

        // Handle file selection
        fileInput.addEventListener('change', (e) => {
            const file = e.target.files[0];
            if (file) {
                contentText.textContent = `Selected: ${file.name}`;
                dropZone.classList.add('has-file');
            } else {
                contentText.textContent = originalText;
                dropZone.classList.remove('has-file');
            }
        });

        // Prevent default drag behaviors
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
            }, false);
        });

        // Handle drag states
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

        // Handle dropped files
        dropZone.addEventListener('drop', (e) => {
            const file = e.dataTransfer.files[0];
            if (file) {
                // Update the file input
                const dataTransfer = new DataTransfer();
                dataTransfer.items.add(file);
                fileInput.files = dataTransfer.files;
                
                // Trigger change event
                fileInput.dispatchEvent(new Event('change'));
            }
        });
    }

    async analyzeLog() {
        const fileInput = document.getElementById('log-file');
        
        if (!fileInput || !fileInput.files.length) {
            this.showError('Please select a log file');
            return;
        }

        const file = fileInput.files[0];
        
        // Validate file type
        if (!file.name.match(/\.(log|txt)$/i)) {
            this.showError('Only .log and .txt files are supported');
            return;
        }

        // Validate file size (10MB limit)
        if (file.size > 10 * 1024 * 1024) {
            this.showError('File size exceeds 10MB limit');
            return;
        }

        try {
            this.setLoading(true);
            const formData = new FormData();
            formData.append('file', file);

            const response = await fetch('http://127.0.0.1:5000/api/analyze-logs', {
                method: 'POST',
                body: formData
            });

            if (!response.ok) {
                throw new Error(`Analysis failed: ${response.statusText}`);
            }

            const result = await response.json();
            if (result.success) {
                this.displayResults(result.data);
            } else {
                throw new Error(result.error || 'Analysis failed');
            }
        } catch (error) {
            this.showError(error.message);
        } finally {
            this.setLoading(false);
        }
    }

    validateInput() {
        const file = this.elements.fileInput.files[0];
        if (!file) {
            this.showError('Please select a file to analyze');
            return false;
        }
        if (!file.name.match(/\.(log|txt)$/i)) {
            this.showError('Only .log and .txt files are supported');
            return false;
        }
        if (file.size > 10 * 1024 * 1024) { // 10MB limit
            this.showError('File size exceeds 10MB limit');
            return false;
        }
        return true;
    }

    exportResults(format = 'pdf') {
        if (format === 'pdf') {
            this.exportToPDF();
        } else {
            this.exportToJSON();
        }
    }

    async exportToPDF() {
        try {
            const { jsPDF } = await import('https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js');
            const doc = new jsPDF();
            
            // Add header
            doc.setFontSize(20);
            doc.text('Log Analysis Report', 20, 20);
            
            // Add summary
            doc.setFontSize(14);
            doc.text('Summary:', 20, 40);
            doc.setFontSize(12);
            doc.text([
                `Total Lines: ${this.elements.summaryElements.totalLines.textContent}`,
                `Total Errors: ${this.elements.summaryElements.totalErrors.textContent}`,
                `Security Events: ${this.elements.summaryElements.securityEvents.textContent}`,
                `Time Range: ${this.elements.summaryElements.timeRange.textContent}`
            ], 30, 50);

            // Save the PDF
            doc.save('log-analysis-report.pdf');
        } catch (error) {
            this.showError('Failed to generate PDF');
            console.error('PDF generation failed:', error);
        }
    }

    exportToJSON() {
        const data = {
            summary: {
                totalLines: this.elements.summaryElements.totalLines.textContent,
                totalErrors: this.elements.summaryElements.totalErrors.textContent,
                securityEvents: this.elements.summaryElements.securityEvents.textContent,
                timeRange: this.elements.summaryElements.timeRange.textContent
            },
            charts: this.chartData || {},
            details: this.analysisDetails || {}
        };

        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'log-analysis-report.json';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    showError(message) {
        const alert = document.createElement('div');
        alert.className = 'error-message';
        alert.innerHTML = `
            <i class="ph-warning-circle"></i>
            <span>${message}</span>
        `;
        
        this.elements.form.insertAdjacentElement('beforeend', alert);
        setTimeout(() => alert.remove(), 5000);
    }

    setLoading(isLoading) {
        const button = this.elements.form.querySelector('button[type="submit"]');
        button.disabled = isLoading;
        button.innerHTML = isLoading ? 
            '<i class="ph-spinner ph-spin"></i> Analyzing...' : 
            '<i class="ph-magnifying-glass"></i> Analyze Logs';
    }

    // ... Rest of the methods (validation, display, charts, etc.) ...
}
