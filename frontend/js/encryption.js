class EncryptionTool {
    constructor() {
        // ...existing code...
        this.dropZone = document.getElementById('dropZone');
        this.fileInput = document.getElementById('input-file');
        this.fileName = document.querySelector('.file-name');
        this.initializeFileUpload();
    }

    initializeFileUpload() {
        // Prevent default drag behaviors
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            this.dropZone.addEventListener(eventName, preventDefaults, false);
            document.body.addEventListener(eventName, preventDefaults, false);
        });

        // Highlight drop zone when dragging over it
        ['dragenter', 'dragover'].forEach(eventName => {
            this.dropZone.addEventListener(eventName, highlight.bind(this), false);
        });

        ['dragleave', 'drop'].forEach(eventName => {
            this.dropZone.addEventListener(eventName, unhighlight.bind(this), false);
        });

        // Handle dropped files
        this.dropZone.addEventListener('drop', handleDrop.bind(this), false);
        
        // Handle click to select
        this.dropZone.addEventListener('click', () => {
            this.fileInput.click();
        });

        // Handle file selection
        this.fileInput.addEventListener('change', (e) => {
            handleFiles.call(this, e.target.files);
        });

        function preventDefaults(e) {
            e.preventDefault();
            e.stopPropagation();
        }

        function highlight() {
            this.dropZone.classList.add('drag-over');
        }

        function unhighlight() {
            this.dropZone.classList.remove('drag-over');
        }

        function handleDrop(e) {
            const dt = e.dataTransfer;
            const files = dt.files;
            handleFiles.call(this, files);
        }

        function handleFiles(files) {
            if (files.length) {
                this.selectedFile = files[0];
                this.fileName.textContent = files[0].name;
                this.dropZone.classList.add('has-file');
            }
        }
    }

    // ...existing code...

    attachEventListeners() {
        // ...existing code...

        // Update file input event handler
        this.fileInput.addEventListener('change', async (e) => {
            try {
                const file = e.target.files[0];
                if (file) {
                    this.selectedFile = file;
                    this.updateFileInfo(file.name);
                }
            } catch (error) {
                console.error('File selection error:', error);
                this.showError('Error selecting file: ' + error.message);
            }
        });

        // Update form submission for file encryption
        this.form.addEventListener('submit', async (e) => {
            e.preventDefault();
            const isFileMode = this.modeSelect.value === 'file';
            
            try {
                if (isFileMode) {
                    if (!this.selectedFile) {
                        throw new Error('Please select a file first');
                    }
                    await this.processFile();
                } else {
                    await this.processText();
                }
            } catch (error) {
                console.error('Processing error:', error);
                this.showError(error.message);
            }
        });
    }

    updateFileInfo(filename) {
        const fileInfo = document.getElementById('fileInfo');
        if (fileInfo) {
            fileInfo.textContent = `Selected file: ${filename}`;
            fileInfo.style.display = 'block';
        }
    }

    async processFile() {
        const formData = new FormData();
        formData.append('file', this.selectedFile);
        formData.append('algorithm', this.algorithmSelect.value);
        formData.append('key', this.keyInput.value);

        const endpoint = this.isEncrypt ? '/api/file/encrypt' : '/api/file/decrypt';
        
        if (!this.isEncrypt && this.nonceInput) {
            formData.append('nonce', this.nonceInput.value);
        }

        const response = await fetch(endpoint, {
            method: 'POST',
            body: formData
        });

        const result = await response.json();
        if (!result.success) {
            throw new Error(result.error || 'Processing failed');
        }

        this.handleFileResult(result);
    }

    handleFileResult(result) {
        // Handle the encrypted/decrypted file result
        const fileData = result.data;
        let filename = this.selectedFile.name;
        
        // Modify filename based on operation
        filename = this.isEncrypt ? 
            filename + '.encrypted' : 
            filename.replace('.encrypted', '');

        // Create download link
        const blob = this.createBlob(fileData);
        const downloadUrl = URL.createObjectURL(blob);
        this.downloadFile(downloadUrl, filename);

        // Show success message
        this.showSuccess(`File ${this.isEncrypt ? 'encrypted' : 'decrypted'} successfully!`);
    }

    createBlob(fileData) {
        const content = this.isEncrypt ? 
            fileData.encrypted :
            fileData.decrypted;
            
        const binaryData = this.base64ToArrayBuffer(content);
        return new Blob([binaryData], { type: 'application/octet-stream' });
    }

    base64ToArrayBuffer(base64) {
        const binaryString = window.atob(base64);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes.buffer;
    }

    downloadFile(url, filename) {
        const link = document.createElement('a');
        link.href = url;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
    }
}
