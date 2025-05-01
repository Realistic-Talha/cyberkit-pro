import { apiRequest } from '../main.js';  // Add this import

class PasswordCracker {
    constructor() {
        this.form = document.getElementById('password-cracker-form');
        this.resultsDiv = document.getElementById('crack-results');
        this.progressBar = document.querySelector('.progress-fill');
        this.attemptCounter = document.getElementById('attempt-counter');
        this.timeElapsed = document.getElementById('time-elapsed');
        this.stopButton = document.getElementById('stop-crack');
        this.resultsContainer = document.querySelector('.results-container');
        
        this.isCracking = false;
        this.startTime = null;
        this.attemptCount = 0;
        this.timerInterval = null;
        this.eventSource = null;  // Add this line

        this.bindEvents();
    }

    bindEvents() {
        this.form.addEventListener('submit', (e) => {
            e.preventDefault();
            if (!this.isCracking) {
                this.startCracking();
            }
        });

        this.stopButton.addEventListener('click', () => {
            this.stopCracking();
        });

        // Show/hide bruteforce options based on attack method
        const attackMethodRadios = document.querySelectorAll('input[name="attack-method"]');
        const bruteforceOptions = document.getElementById('bruteforce-options');
        const maxLengthInput = document.getElementById('max-length');
        
        attackMethodRadios.forEach(radio => {
            radio.addEventListener('change', (e) => {
                const isBruteforce = e.target.value === 'bruteforce';
                bruteforceOptions.style.display = isBruteforce ? 'block' : 'none';
                
                // Show attempt estimation for brute force
                if (isBruteforce) {
                    this.updateBruteforceEstimation(parseInt(maxLengthInput.value));
                }
            });
        });

        // Add listener for max length change
        maxLengthInput.addEventListener('change', (e) => {
            if (document.querySelector('input[name="attack-method"]:checked').value === 'bruteforce') {
                this.updateBruteforceEstimation(parseInt(e.target.value));
            }
        });
    }

    async startCracking() {
        const hashValue = document.getElementById('hash-input').value;
        const hashType = document.getElementById('hash-type').value;
        const attackMethod = document.querySelector('input[name="attack-method"]:checked').value;
        const maxLength = document.getElementById('max-length').value;

        try {
            this.isCracking = true;
            this.startTime = Date.now();
            this.attemptCount = 0;
            this.updateProgress(0);
            this.stopButton.disabled = false;
            this.resultsContainer.innerHTML = ''; // Clear previous results

            console.log('Starting crack with:', { hashValue, hashType, attackMethod, maxLength });

            const response = await fetch('http://127.0.0.1:5000/api/crack-password', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    hash: hashValue,         // changed from hashValue
                    type: hashType,         // changed from hashType
                    method: attackMethod,    // changed from attackMethod
                    maxLength: parseInt(maxLength)
                })
            });

            if (!response.ok) {
                throw new Error('Server error');
            }

            // Create EventSource after successful start
            this.eventSource = new EventSource(`http://127.0.0.1:5000/api/crack-status`);
            
            this.eventSource.onmessage = (event) => {
                console.log('Progress update:', event.data);
                const data = JSON.parse(event.data);
                this.handleProgress(data);
            };

            this.eventSource.onerror = (error) => {
                console.error('EventSource error:', error);
                this.eventSource.close();
                this.stopCracking();
            };

        } catch (error) {
            console.error('Cracking error:', error);
            this.showError('Failed to start password cracking: ' + error.message);
            this.stopCracking();
        }
    }

    stopCracking() {
        this.isCracking = false;
        clearInterval(this.timerInterval);
        
        if (this.eventSource) {
            this.eventSource.close();
            this.eventSource = null;
        }

        fetch('http://127.0.0.1:5000/api/stop-crack', {
            method: 'POST'
        }).catch(console.error);
    }

    handleProgress(data) {
        console.log('Received progress data:', data);  // Keep this debug line

        // First check for errors
        if (data.error) {
            console.error('Error in progress:', data.error);
            this.showError(data.error);
            this.stopCracking();
            return;
        }

        // Update progress if there's attempt data
        if (data.attempts !== undefined) {
            this.attemptCount = data.attempts;
            this.updateProgress(data.progress || 0);
            this.updateAttempts();
            if (data.time) this.updateTimer(data.time);
        }

        // Check for found password
        if (data.found === true && data.password) {
            console.log('Password found:', data.password);
            this.showSuccess(data.password, data.attempts, data.time);
            this.stopCracking();
            return;
        }

        // Only check finished state if password wasn't found
        if (data.finished === true && !data.found) {
            console.log('Cracking finished without finding password');
            this.stopCracking();
            this.showError('Password not found');
        }
    }

    updateProgress(percent) {
        this.progressBar.style.width = `${percent}%`;
    }

    updateAttempts() {
        this.attemptCounter.textContent = this.attemptCount.toLocaleString();
    }

    updateTimer(time) {
        this.timeElapsed.textContent = time;
    }

    showSuccess(password, attempts, time) {
        this.resultsContainer.innerHTML = `
            <div class="success-result">
                <h4>Password Found!</h4>
                <p>Password: <strong>${password}</strong></p>
                <p>Attempts: ${attempts.toLocaleString()}</p>
                <p>Time: ${time}</p>
            </div>
        `;
    }

    showError(message) {
        this.resultsContainer.innerHTML = `
            <div class="error-result">
                <h4>Error</h4>
                <p>${message}</p>
            </div>
        `;
    }

    updateBruteforceEstimation(maxLength) {
        const charset = 94; // printable ASCII characters
        let totalAttempts = 0;
        
        for (let i = 1; i <= maxLength; i++) {
            totalAttempts += Math.pow(charset, i);
        }

        const estimation = document.createElement('div');
        estimation.className = 'help-text';
        estimation.innerHTML = `
            <p>Estimated maximum attempts: ${totalAttempts.toLocaleString()}</p>
            <p>Warning: Brute force attacks can take a very long time for longer passwords!</p>
        `;

        // Update or add the estimation to the bruteforce options
        const existingEstimation = document.querySelector('.brute-force-estimation');
        if (existingEstimation) {
            existingEstimation.replaceWith(estimation);
        } else {
            document.getElementById('bruteforce-options').appendChild(estimation);
        }
    }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new PasswordCracker();
});
