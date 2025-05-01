class FileIntegrityChecker {
    constructor() {
        this.form = document.getElementById('file-integrity-form');
        this.resultsDiv = document.getElementById('integrity-results');
        this.resultsContainer = this.resultsDiv.querySelector('.results-container');
        this.bindEvents();
    }

    bindEvents() {
        this.form.addEventListener('submit', async (e) => {
            e.preventDefault();
            await this.checkIntegrity();
        });
    }

    async checkIntegrity() {
        const fileInput = this.form.querySelector('#file-input');
        const algorithm = this.form.querySelector('#hash-algorithm').value;
        const spinner = this.form.querySelector('.spinner');
        
        if (!fileInput.files.length) {
            alert('Please select a file');
            return;
        }

        try {
            spinner.classList.remove('hidden');
            this.form.querySelector('button').disabled = true;

            const formData = new FormData();
            formData.append('file', fileInput.files[0]);
            formData.append('algorithm', algorithm);

            const response = await fetch(`${API_BASE_URL}/check-integrity`, {
                method: 'POST',
                body: formData
            });

            if (!response.ok) {
                throw new Error('Integrity check failed');
            }

            const result = await response.json();
            this.displayResults(result.data);
        } catch (error) {
            this.resultsContainer.innerHTML = `
                <div class="bg-red-500 text-white p-4 rounded-lg">
                    Error: ${error.message}
                </div>
            `;
        } finally {
            spinner.classList.add('hidden');
            this.form.querySelector('button').disabled = false;
        }
    }

    displayResults(data) {
        this.resultsDiv.classList.remove('hidden');
        
        const statusColors = {
            unchanged: 'bg-green-500',
            modified: 'bg-yellow-500'
        };

        const resultHtml = `
            <div class="space-y-4">
                <div class="${statusColors[data.status]} text-white p-4 rounded-lg">
                    <h4 class="font-bold">File Status: ${data.status.toUpperCase()}</h4>
                    <p class="mt-2">Filename: ${data.filename}</p>
                    <p>Size: ${this.formatFileSize(data.size)}</p>
                </div>
                <div class="bg-gray-700 p-4 rounded-lg">
                    <h4 class="font-bold mb-2">Current Hash (${data.algorithm}):</h4>
                    <p class="font-mono text-sm break-all">${data.hash}</p>
                    ${data.previous_hash ? `
                        <h4 class="font-bold mb-2 mt-4">Previous Hash:</h4>
                        <p class="font-mono text-sm break-all">${data.previous_hash}</p>
                        <p class="text-sm text-gray-400 mt-2">
                            Last modified: ${new Date(data.previous_timestamp).toLocaleString()}
                        </p>
                    ` : ''}
                </div>
            </div>
        `;

        this.resultsContainer.innerHTML = resultHtml;
    }

    formatFileSize(bytes) {
        const units = ['B', 'KB', 'MB', 'GB'];
        let size = bytes;
        let unitIndex = 0;
        
        while (size >= 1024 && unitIndex < units.length - 1) {
            size /= 1024;
            unitIndex++;
        }
        
        return `${size.toFixed(2)} ${units[unitIndex]}`;
    }
}

export default FileIntegrityChecker;
