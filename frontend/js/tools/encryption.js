class EncryptionTool {
    constructor() {
        this.API_BASE_URL = 'http://localhost:5000/api'; // Add this line
        this.initializeElements();
        this.bindEvents();
    }

    initializeElements() {
        // Add initial interface setup
        this.form = document.getElementById('text-crypto-form');
        this.resultsPanel = document.getElementById('crypto-results');
        this.outputField = this.resultsPanel?.querySelector('.output-field');
        this.modeSwitches = document.querySelectorAll('.mode-button');
        this.submitText = document.getElementById('submit-text');
        this.fileForm = document.getElementById('file-crypto-form');
        this.fileDropZone = document.querySelector('.file-drop-zone');
        this.fileInfo = document.querySelector('.file-info');
        this.textMode = document.getElementById('text-mode');
        this.fileMode = document.getElementById('file-mode');

        // Initialize interfaces for both modes
        const textKeySection = document.querySelector('#text-mode .key-section');
        const fileKeySection = document.querySelector('#file-mode .key-section');
        
        if (textKeySection) {
            this.setupDefaultKeyInterface(textKeySection, false);
        }
        if (fileKeySection) {
            this.setupDefaultKeyInterface(fileKeySection, true);
        }
    }

    bindEvents() {
        // Algorithm change handler
        document.getElementById('algorithm').addEventListener('change', (e) => {
            this.updateInterfaceForAlgorithm(e.target.value);
        });

        // Operation change handler
        document.getElementById('operation').addEventListener('change', (e) => {
            this.updateInterfaceForOperation(e.target.value);
        });

        // Key generation
        document.getElementById('generate-key').addEventListener('click', () => this.generateKey());

        // Form submission
        this.form.addEventListener('submit', async (e) => {
            e.preventDefault();
            await this.processData();
        });

        // Copy and download results
        document.getElementById('copy-result').addEventListener('click', () => this.copyResult());
        document.getElementById('download-result').addEventListener('click', () => this.downloadResult());

        // File form events
        this.fileForm?.addEventListener('submit', async (e) => {
            e.preventDefault();
            await this.processFile();
        });

        document.getElementById('file-algorithm')?.addEventListener('change', (e) => {
            this.updateInterfaceForAlgorithm(e.target.value, true);
        });

        document.getElementById('file-operation')?.addEventListener('change', (e) => {
            this.updateInterfaceForOperation(e.target.value, true);
        });

        document.getElementById('file-generate-key')?.addEventListener('click', () => {
            this.generateKey(true);
        });

        // File drop zone events
        this.fileDropZone?.addEventListener('dragover', (e) => {
            e.preventDefault();
            this.fileDropZone.classList.add('drag-over');
        });

        this.fileDropZone?.addEventListener('dragleave', () => {
            this.fileDropZone.classList.remove('drag-over');
        });

        this.fileDropZone?.addEventListener('drop', (e) => {
            e.preventDefault();
            this.fileDropZone.classList.remove('drag-over');
            const files = e.dataTransfer.files;
            if (files.length) {
                document.getElementById('input-file').files = files;
                this.updateFileInfo(files[0]);
            }
        });

        document.getElementById('input-file')?.addEventListener('change', (e) => {
            if (e.target.files.length) {
                this.updateFileInfo(e.target.files[0]);
            }
        });

        // Add mode switching event listeners
        this.modeSwitches.forEach(button => {
            button.addEventListener('click', () => {
                this.switchMode(button.dataset.mode);
            });
        });

        // Update initial interface states
        const algorithm = document.getElementById('algorithm')?.value || 'fernet';
        const operation = document.getElementById('operation')?.value || 'encrypt';
        this.updateInterfaceForAlgorithm(algorithm);
        this.updateInterfaceForOperation(operation);
    }

    updateInterfaceForOperation(operation, isFileMode = false) {
        const submitText = isFileMode ? 
            document.getElementById('file-submit-text') : 
            document.getElementById('submit-text');
        const algorithm = isFileMode ? 
            document.getElementById('file-algorithm').value : 
            document.getElementById('algorithm').value;
        const nonceGroup = isFileMode ? 
            document.getElementById('file-nonce-group') : 
            document.getElementById('nonce-group');

        if (submitText) {
            submitText.textContent = operation.charAt(0).toUpperCase() + operation.slice(1);
        }

        // Always try to recreate nonce group if it doesn't exist
        if (!nonceGroup && algorithm === 'aes') {
            const keySection = isFileMode ?
                document.querySelector('#file-mode .key-section') :
                document.querySelector('#text-mode .key-section');
            if (keySection) {
                this.setupDefaultKeyInterface(keySection, isFileMode);
            }
        }

        if (nonceGroup) {
            nonceGroup.classList.toggle('hidden', 
                !(operation === 'decrypt' && algorithm === 'aes'));
        }
    }

    updateInterfaceForAlgorithm(algorithm, isFileMode = false) {
        const keyInput = isFileMode ? 
            document.getElementById('file-key') : 
            document.getElementById('key');
        const nonceGroup = isFileMode ? 
            document.getElementById('file-nonce-group') : 
            document.getElementById('nonce-group');
        const keySection = isFileMode ?
            document.querySelector('#file-mode .key-section') :
            document.querySelector('#text-mode .key-section');

        if (!keySection) {
            console.error('Key section not found');
            return;
        }

        if (keyInput) {
            keyInput.value = '';
        }

        if (nonceGroup) {
            nonceGroup.classList.add('hidden');
        }
        
        if (algorithm === 'aes') {
            const operation = isFileMode ? 
                document.getElementById('file-operation')?.value : 
                document.getElementById('operation')?.value;
            if (operation === 'decrypt' && nonceGroup) {
                nonceGroup.classList.remove('hidden');
            }
            this.setupDefaultKeyInterface(keySection, isFileMode);
        } else if (algorithm === 'rsa') {
            this.setupRSAInterface(keySection, isFileMode);
        } else {
            this.setupDefaultKeyInterface(keySection, isFileMode);
        }
    }

    setupDefaultKeyInterface(keySection, isFileMode) {
        const prefix = isFileMode ? 'file-' : '';
        keySection.innerHTML = `
            <label for="${prefix}key">Encryption Key</label>
            <div class="key-input-group">
                <input type="text" id="${prefix}key" class="input-field" 
                    placeholder="Enter or generate key" required>
                <button type="button" id="${prefix}generate-key" class="button-secondary">
                    <i class="ph-key"></i>
                    Generate
                </button>
            </div>
            <div id="${prefix}nonce-group" class="hidden">
                <label for="${prefix}nonce">Nonce (for AES-GCM)</label>
                <input type="text" id="${prefix}nonce" class="input-field" 
                    placeholder="Required for AES decryption">
                <label for="${prefix}auth_tag">Authentication Tag</label>
                <input type="text" id="${prefix}auth_tag" class="input-field" 
                    placeholder="Required for AES decryption">
            </div>
        `;
        document.getElementById(`${prefix}generate-key`).addEventListener('click', 
            () => this.generateKey(isFileMode));
    }

    setupRSAInterface(keySection, isFileMode) {
        const prefix = isFileMode ? 'file-' : '';
        keySection.innerHTML = `
            <div class="rsa-key-section">
                <div class="key-pair-group">
                    <label>Public Key</label>
                    <textarea id="${prefix}public-key" class="input-field" 
                        placeholder="Enter public key for encryption"></textarea>
                    <label>Private Key</label>
                    <textarea id="${prefix}private-key" class="input-field" 
                        placeholder="Enter private key for decryption"></textarea>
                    <button type="button" id="${prefix}generate-keypair" class="button-secondary">
                        <i class="ph-key"></i>
                        Generate Key Pair
                    </button>
                </div>
            </div>
        `;
        document.getElementById(`${prefix}generate-keypair`).addEventListener('click', 
            () => this.generateRSAKeyPair(isFileMode));
    }

    async generateRSAKeyPair(isFileMode = false) {
        try {
            const response = await fetch(`${this.API_BASE_URL}/generate-key`, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify({ algorithm: 'rsa' }),
                credentials: 'include'
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const data = await response.json();
            console.log('RSA key generation response:', data); // Debug log

            if (!data.success || !data.data || !data.data.key) {
                throw new Error(data.error || 'Invalid key generation response');
            }

            const { private_key, public_key } = data.data.key;
            if (!private_key || !public_key) {
                throw new Error('Invalid RSA key pair received');
            }

            const prefix = isFileMode ? 'file-' : '';
            document.getElementById(`${prefix}public-key`).value = public_key;
            document.getElementById(`${prefix}private-key`).value = private_key;
            this.showNotification('RSA key pair generated successfully', 'success');
        } catch (error) {
            console.error('RSA key generation error:', error);
            this.showNotification(error.message, 'error');
        }
    }

    async generateKey(isFileMode = false) {
        const algorithm = isFileMode ? 
            document.getElementById('file-algorithm').value : 
            document.getElementById('algorithm').value;
        
        const keyInput = isFileMode ? 
            document.getElementById('file-key') : 
            document.getElementById('key');

        try {
            console.log('Generating key for:', algorithm, 'in', isFileMode ? 'file mode' : 'text mode');

            const response = await fetch(`${this.API_BASE_URL}/generate-key`, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ algorithm }),
                credentials: 'include'
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const data = await response.json();
            
            if (!data.success) {
                throw new Error(data.error || 'Key generation failed');
            }

            // Set the key in the correct input field
            keyInput.value = data.data.key;
            this.showNotification('Key generated successfully', 'success');
        } catch (error) {
            console.error('Key generation error:', error);
            this.showNotification(error.message, 'error');
        }
    }

    async handleApiError(response) {
        if (!response.ok) {
            let errorMessage;
            try {
                const errorData = await response.json();
                errorMessage = errorData.error || `HTTP error! status: ${response.status}`;
            } catch (e) {
                errorMessage = `HTTP error! status: ${response.status}`;
            }
            throw new Error(errorMessage);
        }
        return response;
    }

    async processData() {
        const operation = document.getElementById('operation')?.value;
        const algorithm = document.getElementById('algorithm')?.value;
        const text = document.getElementById('input-text')?.value;
        
        if (!operation || !algorithm || !text) {
            this.showNotification('Missing required fields', 'error');
            return;
        }

        try {
            const payload = {
                text,
                algorithm,
                key: null
            };

            // Get key based on algorithm
            if (algorithm === 'rsa') {
                const keyType = operation === 'encrypt' ? 'public' : 'private';
                const keyElement = document.getElementById(`${keyType}-key`);
                if (!keyElement?.value) {
                    throw new Error(`${keyType.charAt(0).toUpperCase() + keyType.slice(1)} key is required`);
                }
                payload.key = keyElement.value;
            } else {
                const keyElement = document.getElementById('key');
                if (!keyElement?.value) {
                    throw new Error('Encryption key is required');
                }
                payload.key = keyElement.value;
            }

            // Handle AES decryption requirements
            if (algorithm === 'aes' && operation === 'decrypt') {
                const nonceElement = document.getElementById('nonce');
                const authTagElement = document.getElementById('auth_tag'); // Changed from auth-tag to auth_tag

                // Debug log of elements and their values
                console.log('AES Decryption Elements:', {
                    nonceElement: nonceElement?.id,
                    nonceValue: nonceElement?.value,
                    authTagElement: authTagElement?.id,
                    authTagValue: authTagElement?.value
                });

                if (!nonceElement?.value || !authTagElement?.value) {
                    throw new Error('Both Nonce and Authentication Tag are required for AES decryption');
                }

                payload.nonce = nonceElement.value.trim();
                payload.auth_tag = authTagElement.value.trim();

                // Debug log the final payload
                console.log('Final AES Payload:', {
                    algorithm: payload.algorithm,
                    text: payload.text,
                    nonce: payload.nonce,
                    auth_tag: payload.auth_tag,
                    hasKey: Boolean(payload.key)
                });
            }

            const response = await fetch(`${this.API_BASE_URL}/${operation}`, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify(payload),
                credentials: 'include'
            });

            const data = await response.json();
            if (!response.ok || !data.success) {
                console.error('Server Response:', data);
                throw new Error(data.error || `${operation} failed`);
            }

            this.displayResults(data.data);
            this.showNotification(`${operation} completed successfully`, 'success');
        } catch (error) {
            console.error(`${operation} error:`, error);
            this.showNotification(error.message, 'error');
        }
    }

    handleError(error) {
        const errorDiv = document.createElement('div');
        errorDiv.className = 'error-message';
        errorDiv.innerHTML = `
            <i class="ph-warning-circle"></i>
            <span>${error.message || 'An error occurred'}</span>
        `;

        const resultsPanel = document.getElementById('results-panel');
        if (resultsPanel) {
            resultsPanel.innerHTML = '';
            resultsPanel.appendChild(errorDiv);
            resultsPanel.classList.remove('hidden');
        }
    }

    displayResults(data) {
        this.resultsPanel.classList.remove('hidden');
        
        let resultText = '';
        if (data.encrypted) {
            resultText = data.encrypted;
            if (data.nonce || data.auth_tag) {
                resultText += '\n\n=== SAVE FOR DECRYPTION ===';
                if (data.nonce) {
                    resultText += `\nNonce: ${data.nonce}`;
                }
                if (data.auth_tag) {
                    resultText += `\nAuthentication Tag: ${data.auth_tag}`;
                }
            }
        } else if (data.decrypted) {
            resultText = data.decrypted;
        }

        this.outputField.value = resultText;
    }

    showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.textContent = message;
        
        document.body.appendChild(notification);
        setTimeout(() => notification.remove(), 3000);
    }

    copyResult() {
        navigator.clipboard.writeText(this.outputField.value);
        this.showToast('Copied to clipboard!');
    }

    downloadResult() {
        const operation = document.getElementById('operation').value;
        const blob = new Blob([this.outputField.value], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${operation}-result.txt`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    switchMode(mode) {
        // Remove active class from all mode buttons and add to selected
        this.modeSwitches.forEach(btn => {
            btn.classList.toggle('active', btn.dataset.mode === mode);
        });

        // Show/hide appropriate mode pane
        if (mode === 'text') {
            this.textMode.classList.add('active');
            this.fileMode.classList.remove('active');
        } else {
            this.textMode.classList.remove('active');
            this.fileMode.classList.add('active');
        }
    }

    updateKeyInterface(algorithm) {
        const keySection = document.querySelector('.key-section');
        if (algorithm === 'rsa') {
            keySection.innerHTML = `
                <label>Key Pair</label>
                <div class="key-pair-group">
                    <textarea id="public-key" class="input-field" placeholder="Public Key" readonly></textarea>
                    <textarea id="private-key" class="input-field" placeholder="Private Key" readonly></textarea>
                    <button type="button" id="generate-keypair" class="button-secondary">
                        <i class="ph-key"></i>
                        Generate Key Pair
                    </button>
                </div>
            `;
            document.getElementById('generate-keypair').addEventListener('click', () => this.generateKeyPair());
        }
    }

    showToast(message) {
        const toast = document.createElement('div');
        toast.className = 'toast';
        toast.textContent = message;
        document.body.appendChild(toast);
        setTimeout(() => toast.remove(), 2000);
    }

    updateFileInfo(file) {
        this.fileInfo.textContent = `Selected: ${file.name} (${this.formatFileSize(file.size)})`;
    }

    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    async processFile() {
        const operation = document.getElementById('file-operation').value;
        const algorithm = document.getElementById('file-algorithm').value;
        const file = document.getElementById('input-file').files[0];

        if (!file) {
            this.showNotification('Please select a file', 'error');
            return;
        }

        let key;
        if (algorithm === 'rsa') {
            const prefix = operation === 'encrypt' ? 'public' : 'private';
            key = document.getElementById(`file-${prefix}-key`).value;
        } else {
            key = document.getElementById('file-key').value;
        }

        if (!key) {
            this.showNotification('Please provide an encryption key', 'error');
            return;
        }

        const formData = new FormData();
        formData.append('file', file);
        formData.append('algorithm', algorithm);
        formData.append('key', key);

        if (algorithm === 'aes' && operation === 'decrypt') {
            const nonce = document.getElementById('file-nonce').value;
            const authTag = document.getElementById('file-auth_tag').value; // Changed from file-auth-tag to file-auth_tag
            if (!nonce || !authTag) {
                this.showNotification('Nonce and Authentication Tag are required for AES decryption', 'error');
                return;
            }
            formData.append('nonce', nonce);
            formData.append('auth_tag', authTag);
        }

        try {
            const response = await fetch(`${this.API_BASE_URL}/file/${operation}`, {
                method: 'POST',
                body: formData
            });

            const data = await response.json();
            if (!data.success) {
                throw new Error(data.error || `File ${operation} failed`);
            }

            // Handle encrypted/decrypted file download
            const fileName = this.getOutputFileName(file.name, operation);
            await this.downloadProcessedFile(data.data, fileName, operation);
            
            this.showNotification(`File ${operation} completed successfully`, 'success');
        } catch (error) {
            console.error(`File ${operation} error:`, error);
            this.showNotification(error.message, 'error');
        }
    }

    getOutputFileName(originalName, operation) {
        return operation === 'encrypt' ? 
            `${originalName}.encrypted` : 
            originalName.replace('.encrypted', '');
    }

    async downloadProcessedFile(data, fileName, operation) {
        let binaryData;
        if (operation === 'decrypt') {
            binaryData = this.base64ToArrayBuffer(data.decrypted);
        } else {
            binaryData = new TextEncoder().encode(data.encrypted);
        }

        const blob = new Blob([binaryData], { 
            type: operation === 'decrypt' ? this.getMimeType(fileName) : 'application/octet-stream'
        });
        
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = fileName;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    base64ToArrayBuffer(base64) {
        const binaryString = atob(base64);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes;
    }

    getMimeType(filename) {
        const ext = filename.split('.').pop().toLowerCase();
        const mimeTypes = {
            'png': 'image/png',
            'jpg': 'image/jpeg',
            'jpeg': 'image/jpeg',
            'gif': 'image/gif',
            'pdf': 'application/pdf',
            // Add more as needed
            'default': 'application/octet-stream'
        };
        return mimeTypes[ext] || mimeTypes.default;
    }
}

// Initialize the tool
new EncryptionTool();

export default EncryptionTool;
