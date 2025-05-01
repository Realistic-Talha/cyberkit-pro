console.log('Port Scanner script loaded'); // Add this line at the top

class PortScanner {
    constructor() {
        console.log('Initializing Port Scanner'); // Add debugging
        this.form = document.getElementById('port-scanner-form');
        this.resultsDiv = document.getElementById('scan-results');
        this.resultsTable = this.resultsDiv.querySelector('.results-table');
        this.loadingIndicator = this.resultsDiv.querySelector('.loading-indicator');
        
        if (!this.form) {
            console.error('Port scanner form not found');
            return;
        }
        
        this.bindEvents();
    }

    bindEvents() {
        if (!this.form) {
            console.error('Form not found!');
            return;
        }
        
        console.log('Binding form submit event');
        this.form.onsubmit = async (e) => {
            e.preventDefault();
            console.log('Form submitted');
            await this.startScan();
            return false;
        };
        
        // Add export button handler
        const exportBtn = this.resultsDiv.querySelector('[title="Export Results"]');
        if (exportBtn) {
            exportBtn.addEventListener('click', () => this.exportResults());
        }

        // Add copy button handler
        const copyBtn = this.resultsDiv.querySelector('[title="Copy to Clipboard"]');
        if (copyBtn) {
            copyBtn.addEventListener('click', () => this.copyResults());
        }
    }

    showLoading(show) {
        if (show) {
            // Clear previous results first
            this.resultsTable.innerHTML = '';
            // Show loading indicator
            this.loadingIndicator.classList.remove('hidden');
        } else {
            // Hide loading indicator
            this.loadingIndicator.classList.add('hidden');
        }
    }

    async startScan() {
        const target = this.form.querySelector('#target').value;
        const portRange = this.form.querySelector('#port-range').value;
        
        console.log('Starting scan with:', { target, portRange });
        
        // Show loading state first
        this.showLoading(true);
        // Show results container
        this.resultsDiv.classList.remove('hidden');
        this.form.querySelector('button[type="submit"]').disabled = true;

        try {
            const response = await fetch('http://localhost:5000/api/port-scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Origin': 'http://localhost:8080'
                },
                body: JSON.stringify({
                    target: target,
                    portRange: portRange
                })
            });

            console.log('Response received:', response.status);
            const result = await response.json();
            console.log('Scan result:', result);

            // Hide loading indicator before processing results
            this.showLoading(false);

            if (!result.success) {
                throw new Error(result.error || 'Scan failed');
            }

            this.displayResults(result.data);
        } catch (error) {
            console.error('Scan error:', error);
            this.showLoading(false);
            this.showError(error.message);
        } finally {
            // Make sure loading is hidden in any case
            this.showLoading(false);
            this.form.querySelector('button[type="submit"]').disabled = false;
        }
    }

    displayResults(data) {
        // Ensure loading indicator is hidden
        this.loadingIndicator.classList.add('hidden');
        
        const table = `
            <table class="results-table">
                <thead>
                    <tr>
                        <th>Port</th>
                        <th>State</th>
                        <th>Service</th>
                        <th>Version</th>
                        <th>Product</th>
                    </tr>
                </thead>
                <tbody>
                    ${data.scan_results.map(port => `
                        <tr>
                            <td>${port.port}</td>
                            <td>
                                <span class="status-badge ${port.state === 'open' ? 'open' : 'closed'}">
                                    ${port.state}
                                </span>
                            </td>
                            <td>${port.service || 'unknown'}</td>
                            <td>${port.version || '-'}</td>
                            <td>${port.product || '-'}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
            <div class="scan-summary">
                <p>Target: ${data.target}</p>
                <p>Total ports scanned: ${data.ports_scanned}</p>
                <p>Open ports found: ${data.open_ports}</p>
            </div>
        `;
        
        this.resultsTable.innerHTML = table;
    }

    showError(message) {
        const errorHTML = `
            <div class="error-message">
                <i class="ph-warning-circle"></i>
                <span>${message}</span>
            </div>
        `;
        this.resultsTable.innerHTML = errorHTML;
    }

    exportResults() {
        try {
            const data = {
                target: this.resultsDiv.querySelector('.scan-summary p:first-child').textContent,
                results: Array.from(this.resultsTable.querySelectorAll('tbody tr')).map(row => {
                    const cells = row.querySelectorAll('td');
                    return {
                        port: cells[0].textContent,
                        state: cells[1].textContent.trim(),
                        service: cells[2].textContent,
                        version: cells[3].textContent,
                        product: cells[4].textContent
                    };
                })
            };

            const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `port-scan-${new Date().toISOString()}.json`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        } catch (error) {
            console.error('Export failed:', error);
            alert('Failed to export results');
        }
    }

    async copyResults() {
        try {
            const table = this.resultsTable.querySelector('table');
            await navigator.clipboard.writeText(table.outerText);
            alert('Results copied to clipboard');
        } catch (error) {
            console.error('Copy failed:', error);
            alert('Failed to copy results');
        }
    }
}

// Initialize immediately and handle errors - fix the duplicate initialization
document.addEventListener('DOMContentLoaded', () => {
    try {
        console.log('Creating PortScanner instance');
        new PortScanner();
    } catch (error) {
        console.error('Failed to initialize PortScanner:', error);
    }
});

