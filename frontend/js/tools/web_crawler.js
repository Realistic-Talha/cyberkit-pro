class WebCrawler {
    constructor() {
        this.form = document.getElementById('web-crawler-form');
        this.resultsDiv = document.getElementById('crawler-results');
        this.progressBar = document.querySelector('.progress-fill');
        this.pagesCounter = document.getElementById('pages-counter');
        this.linksCounter = document.getElementById('links-counter');
        this.stopButton = document.getElementById('stop-crawl');
        this.resultsContainer = document.querySelector('.results-container');
        
        this.isCrawling = false;
        this.eventSource = null;

        this.bindEvents();
    }

    bindEvents() {
        this.form.addEventListener('submit', (e) => {
            e.preventDefault();
            if (!this.isCrawling) {
                this.startCrawling();
            }
        });

        this.stopButton.addEventListener('click', () => {
            this.stopCrawling();
        });
    }

    async startCrawling() {
        const url = document.getElementById('url-input').value;
        const maxDepth = document.getElementById('max-depth').value;
        const maxPages = document.getElementById('max-pages').value;
        const respectRobots = document.getElementById('respect-robots').checked;

        try {
            this.isCrawling = true;
            this.stopButton.disabled = false;
            this.updateProgress(0);
            this.resultsContainer.innerHTML = '';

            console.log('Starting crawler:', { url, maxDepth, maxPages, respectRobots });

            const response = await fetch('http://127.0.0.1:5000/api/crawl', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    url: url,
                    max_depth: parseInt(maxDepth),
                    max_pages: parseInt(maxPages),
                    respect_robots: respectRobots
                })
            });

            if (!response.ok) {
                throw new Error('Server error');
            }

            this.eventSource = new EventSource('http://127.0.0.1:5000/api/crawl-status');
            
            this.eventSource.onmessage = (event) => {
                const data = JSON.parse(event.data);
                this.handleProgress(data);
            };

            this.eventSource.onerror = (error) => {
                console.error('EventSource error:', error);
                this.eventSource.close();
                this.stopCrawling();
            };

        } catch (error) {
            this.showError('Failed to start crawler: ' + error.message);
            this.stopCrawling();
        }
    }

    stopCrawling() {
        this.isCrawling = false;
        this.stopButton.disabled = true;
        
        if (this.eventSource) {
            this.eventSource.close();
            this.eventSource = null;
        }

        fetch('http://127.0.0.1:5000/api/stop-crawl', {
            method: 'POST'
        }).catch(console.error);
    }

    handleProgress(data) {
        if (data.error) {
            this.showError(data.error);
            this.stopCrawling();
            return;
        }

        if (data.finished) {
            this.showResults(data);
            this.stopCrawling();
            return;
        }

        // Update progress
        this.updateProgress(data.progress);
        this.pagesCounter.textContent = data.pages_crawled;
        this.linksCounter.textContent = data.links_found;
    }

    updateProgress(percent) {
        this.progressBar.style.width = `${percent}%`;
    }

    showResults(data) {
        const html = `
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value">${data.pages_crawled}</div>
                    <div class="stat-label">Pages Crawled</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">${data.links_found}</div>
                    <div class="stat-label">Links Found</div>
                </div>
            </div>

            <div class="results-section">
                <h4>Internal Links</h4>
                <div class="link-list">
                    ${data.internal_links.map(link => `
                        <div class="link-item">${link}</div>
                    `).join('')}
                </div>
            </div>

            <div class="results-section">
                <h4>External Links</h4>
                <div class="link-list">
                    ${data.external_links.map(link => `
                        <div class="link-item">${link}</div>
                    `).join('')}
                </div>
            </div>
        `;

        this.resultsContainer.innerHTML = html;
    }

    showError(message) {
        this.resultsContainer.innerHTML = `
            <div class="error-result">
                <h4>Error</h4>
                <p>${message}</p>
            </div>
        `;
    }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new WebCrawler();
});
