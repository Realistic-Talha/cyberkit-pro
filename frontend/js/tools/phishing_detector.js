class PhishingDetector {
    constructor() {
        this.form = document.getElementById('phishing-detector-form');
        this.resultsDiv = document.getElementById('phishing-results');
        this.resultsContainer = this.resultsDiv.querySelector('.results-container');
        this.copyButton = document.getElementById('copy-results');
        this.bindEvents();
    }

    bindEvents() {
        this.form.addEventListener('submit', async (e) => {
            e.preventDefault();
            await this.analyzeUrl();
        });

        this.copyButton.addEventListener('click', () => {
            this.copyResults();
        });
    }

    async analyzeUrl() {
        const url = document.getElementById('url-input').value;
        
        this.showLoading();

        try {
            const response = await fetch('http://localhost:5000/api/analyze-url', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url })
            });

            if (!response.ok) {
                throw new Error('Network response was not ok');
            }

            const data = await response.json();
            
            if (data.success) {
                this.displayResults(data.data);
            } else {
                throw new Error(data.error || 'Analysis failed');
            }
        } catch (error) {
            this.displayError(error.message);
        }
    }

    showLoading() {
        this.resultsDiv.classList.remove('hidden');
        this.resultsContainer.innerHTML = `
            <div class="loading-indicator">
                <div class="spinner"></div>
                <p>Analyzing URL...</p>
            </div>
        `;
    }

    displayResults(data) {
        this.resultsDiv.classList.remove('hidden');
        
        const riskLevelColors = {
            low: 'success',
            medium: 'warning',
            high: 'error'
        };

        const riskColor = riskLevelColors[data.risk_level] || 'warning';

        const resultHtml = `
            <div class="analysis-results">
                <div class="risk-score ${riskColor}">
                    <h4>Risk Level: ${data.risk_level.toUpperCase()}</h4>
                    <p>Risk Score: ${data.risk_score.toFixed(1)}%</p>
                </div>
                
                <div class="analysis-details">
                    <h4>Security Checks</h4>
                    <div class="checks-grid">
                        ${this.generateChecksHtml(data.analysis)}
                    </div>
                </div>

                <div class="recommendations">
                    <h4>Recommendations</h4>
                    <ul>
                        ${this.generateRecommendations(data.analysis)}
                    </ul>
                </div>
            </div>
        `;

        this.resultsContainer.innerHTML = resultHtml;
    }

    generateChecksHtml(analysis) {
        return Object.entries(analysis)
            .map(([key, value]) => `
                <div class="check-item">
                    <div class="check-label">
                        ${this.formatFeatureName(key)}
                    </div>
                    <div class="check-value ${this.getValueColor(key, value)}">
                        ${this.formatValue(value)}
                    </div>
                </div>
            `).join('');
    }

    generateRecommendations(analysis) {
        const recommendations = [];

        if (!analysis.uses_https) {
            recommendations.push('The website does not use HTTPS. Avoid entering sensitive information.');
        }
        if (analysis.has_suspicious_chars) {
            recommendations.push('URL contains suspicious characters. Exercise caution.');
        }
        if (!analysis.domain_age) {
            recommendations.push('Domain is relatively new. Verify the legitimacy of the website.');
        }
        if (!analysis.valid_ssl) {
            recommendations.push('Invalid or missing SSL certificate. Do not trust this website.');
        }
        if (analysis.has_login_form && analysis.suspicious_keywords > 2) {
            recommendations.push('Login form detected with suspicious content. Potential phishing attempt.');
        }

        return recommendations.length > 0 
            ? recommendations.map(rec => `<li>${rec}</li>`).join('')
            : '<li>No specific security concerns detected.</li>';
    }

    displayError(message) {
        this.resultsDiv.classList.remove('hidden');
        this.resultsContainer.innerHTML = `
            <div class="error-message">
                <i class="ph-x-circle"></i>
                <p>${message}</p>
            </div>
        `;
    }

    formatFeatureName(name) {
        return name.split('_')
            .map(word => word.charAt(0).toUpperCase() + word.slice(1))
            .join(' ');
    }

    formatValue(value) {
        if (typeof value === 'boolean') {
            return value ? 'Yes' : 'No';
        }
        if (typeof value === 'number') {
            return value.toString();
        }
        return value || 'N/A';
    }

    getValueColor(feature, value) {
        if (typeof value === 'boolean') {
            const positiveFeatures = ['uses_https', 'domain_age', 'valid_ssl'];
            const isPositive = positiveFeatures.includes(feature);
            return value === isPositive ? 'success' : 'error';
        }
        return '';
    }

    async copyResults() {
        try {
            const resultsText = this.resultsContainer.textContent;
            await navigator.clipboard.writeText(resultsText);
            this.showNotification('Results copied to clipboard', 'success');
        } catch (error) {
            this.showNotification('Failed to copy results', 'error');
        }
    }

    showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.innerHTML = `
            <i class="ph-${type === 'success' ? 'check' : 'x'}-circle"></i>
            <span>${message}</span>
        `;

        document.body.appendChild(notification);
        setTimeout(() => {
            notification.remove();
        }, 3000);
    }
}

// Initialize the PhishingDetector
document.addEventListener('DOMContentLoaded', () => {
    new PhishingDetector();
});

export default PhishingDetector;
