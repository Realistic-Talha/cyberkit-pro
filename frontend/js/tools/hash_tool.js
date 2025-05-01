console.log('HashTool script loading...');

class HashTool {
    constructor() {
        this.state = {
            currentTab: 'text',
            forms: {},
            elements: {},
            isLoading: false
        };
        
        this.initializeElements();
        this.bindEvents();
    }

    initializeElements() {
        // Cache DOM elements
        this.state.elements = {
            tabButtons: Array.from(document.querySelectorAll('[data-tab]')),
            tabPanes: Array.from(document.querySelectorAll('.tab-pane')),
            resultsPanel: document.getElementById('hash-results'),
            copyButton: document.querySelector('[title="Copy to Clipboard"]')
        };

        // Cache forms
        this.state.forms = {
            text: document.getElementById('text-hash-form'),
            file: document.getElementById('file-hash-form'),
            verify: document.getElementById('verify-hash-form')
        };
    }

    bindEvents() {
        // Tab switching
        this.state.elements.tabButtons.forEach(button => {
            button.addEventListener('click', (e) => {
                e.preventDefault();
                this.switchTab(button.getAttribute('data-tab'));
            });
        });

        // Form submissions
        Object.values(this.state.forms).forEach(form => {
            if (form) form.addEventListener('submit', this.handleHashSubmit.bind(this));
        });

        // Copy button
        if (this.state.elements.copyButton) {
            this.state.elements.copyButton.addEventListener('click', this.handleCopy.bind(this));
        }
    }

    async handleHashSubmit(event) {
        event.preventDefault();
        
        try {
            this.setLoading(true);
            
            const form = event.target;
            const formId = form.id;
            let response;

            if (formId === 'file-hash-form') {
                const fileInput = form.querySelector('#file-input');
                const file = fileInput.files[0];
                if (!file) {
                    throw new Error('Please select a file');
                }

                if (file.size > 10 * 1024 * 1024) { // 10MB limit
                    throw new Error('File size exceeds 10MB limit');
                }

                const formData = new FormData();
                formData.append('file', file);
                formData.append('algorithm', form.querySelector('#file-algorithm').value);

                response = await fetch('http://localhost:5000/api/hash/file', {
                    method: 'POST',
                    body: formData,
                    // Remove Content-Type header to let browser set it with boundary
                });

            } else if (formId === 'verify-hash-form') {
                const text = form.querySelector('#verify-input').value;
                const hashValue = form.querySelector('#hash-value').value;
                const algorithm = form.querySelector('#verify-algorithm').value;

                response = await fetch('http://localhost:5000/api/hash/verify', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        text: text,
                        hash: hashValue,
                        algorithm: algorithm
                    })
                });
            } else {
                const textInput = form.querySelector('textarea, input[type="text"]')?.value;
                const algorithm = form.querySelector('select').value;

                if (!textInput) {
                    throw new Error('No input provided');
                }

                response = await fetch('http://127.0.0.1:5000/api/hash', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Accept': 'application/json',
                        'Origin': window.location.origin
                    },
                    mode: 'cors',
                    credentials: 'omit',
                    body: JSON.stringify({
                        text: textInput,
                        algorithm: algorithm
                    })
                });
            }

            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`Server error (${response.status}): ${errorText}`);
            }

            const result = await response.json();
            if (!result.success) {
                throw new Error(result.error || 'Operation failed');
            }

            this.displayResults(result.data);

        } catch (error) {
            this.handleError(error);
        } finally {
            this.setLoading(false);
        }
    }

    async readFileAsText(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = () => resolve(reader.result);
            reader.onerror = () => reject(new Error('Failed to read file'));
            reader.readAsText(file);
        });
    }

    switchTab(tabId) {
        // Update state
        this.state.currentTab = tabId;
        
        // Update UI
        this.state.elements.tabButtons.forEach(btn => {
            const isActive = btn.getAttribute('data-tab') === tabId;
            btn.classList.toggle('active', isActive);
            btn.setAttribute('aria-selected', isActive);
        });

        this.state.elements.tabPanes.forEach(pane => {
            const isActive = pane.id === `${tabId}-hash`;
            pane.classList.toggle('active', isActive);
            pane.hidden = !isActive;
        });

        // Clear results
        if (this.state.elements.resultsPanel) {
            this.state.elements.resultsPanel.classList.add('hidden');
        }
    }

    handleError(error) {
        console.error('HashTool Error:', error);
        this.showError(error.message || 'An error occurred');
    }

    showError(message) {
        const resultsPanel = this.state.elements.resultsPanel;
        if (resultsPanel) {
            resultsPanel.classList.remove('hidden');
            resultsPanel.querySelector('.results-container').innerHTML = `
                <div class="error-message">
                    <i class="ph-warning-circle"></i>
                    <span>${message}</span>
                </div>
            `;
        }
    }

    setLoading(loading) {
        this.state.isLoading = loading;
        const currentForm = this.state.forms[this.state.currentTab];
        const submitButton = currentForm?.querySelector('button[type="submit"]');
        
        if (submitButton) {
            submitButton.disabled = loading;
            submitButton.innerHTML = loading ? 
                '<i class="ph-spinner ph-spin"></i> Processing...' :
                `<i class="ph-${this.state.currentTab === 'verify' ? 'check' : 'hash'}"></i> ${this.state.currentTab === 'verify' ? 'Verify Hash' : 'Generate Hash'}`;
        }
    }

    displayResults(data) {
        const resultsPanel = this.state.elements.resultsPanel;
        if (!resultsPanel) return;

        resultsPanel.classList.remove('hidden');
        
        // Check if this is a verification result
        if ('matches' in data) {
            resultsPanel.querySelector('.results-container').innerHTML = `
                <div class="hash-result">
                    <div class="result-header">
                        <span class="algorithm">${data.algorithm.toUpperCase()}</span>
                        <span class="security-level ${data.security_level.toLowerCase()}">${data.security_level}</span>
                    </div>
                    <div class="verification-result ${data.matches ? 'success' : 'error'}">
                        <i class="ph-${data.matches ? 'check-circle' : 'x-circle'}"></i>
                        <h4>${data.matches ? 'Hash Verified' : 'Hash Mismatch'}</h4>
                    </div>
                    <div class="hash-details">
                        <div class="hash-row">
                            <span class="label">Provided Hash:</span>
                            <code>${data.provided_hash}</code>
                        </div>
                        <div class="hash-row">
                            <span class="label">Computed Hash:</span>
                            <code>${data.computed_hash}</code>
                        </div>
                    </div>
                </div>
            `;
        } else {
            // Regular hash generation result
            resultsPanel.querySelector('.results-container').innerHTML = `
                <div class="hash-result">
                    <div class="result-header">
                        <span class="algorithm">${data.algorithm.toUpperCase()}</span>
                        <span class="security-level ${data.security_level.toLowerCase()}">${data.security_level}</span>
                    </div>
                    <div class="hash-value"><code>${data.hash}</code></div>
                    <div class="hash-info">
                        <span>Length: ${data.hash_bytes * 2} characters</span>
                        <span>Bits: ${data.bits}</span>
                    </div>
                </div>
            `;
        }
    }

    async handleCopy() {
        try {
            const hashValue = document.querySelector('.hash-value code')?.textContent;
            if (hashValue) {
                await navigator.clipboard.writeText(hashValue);
                alert('Hash copied to clipboard');
            }
        } catch (error) {
            this.handleError(error);
        }
    }
}

// Factory function to create and initialize HashTool
function createHashTool() {
    try {
        return new HashTool();
    } catch (error) {
        console.error('Failed to create HashTool:', error);
        throw error;
    }
}

export default createHashTool;

// Initialize HashTool after document is fully loaded
document.addEventListener('DOMContentLoaded', () => {
    try {
        // Check if we're on the hash tool page
        const isHashToolPage = window.location.pathname.includes('hash-tool.html');
        if (!isHashToolPage) return;

        // Wait a bit to ensure all elements are ready
        setTimeout(() => {
            if (document.readyState === 'complete') {
                createHashTool();
                console.log('HashTool initialized successfully');
            }
        }, 100);
    } catch (error) {
        console.error('Failed to initialize HashTool:', error);
    }
});