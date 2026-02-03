/**
 * IL2CPP Dumper - Alpine.js Application
 *
 * Features:
 * - Chunked file uploads with progress
 * - Real-time console output via SSE
 * - Job queue management
 * - Robust error handling
 */

// Constants
const CHUNK_SIZE = 10 * 1024 * 1024; // 10MB chunks (larger = fewer requests)
const MAX_FILE_SIZE = 500 * 1024 * 1024; // 500MB
const PARALLEL_CHUNKS = 4; // Upload 4 chunks in parallel
const DIRECT_UPLOAD_THRESHOLD = 50 * 1024 * 1024; // Files under 50MB upload directly

function dumperApp() {
    return {
        // State
        files: [],
        isDragging: false,
        isUploading: false,
        isProcessing: false,
        status: null, // null, 'uploading', 'processing', 'completed', 'failed'
        uploadProgress: 0,
        processProgress: 0,
        statusMessage: '',
        errorMessage: '',
        jobId: null,
        outputFiles: [],
        validationMessage: '',

        // Console
        consoleLines: [],
        consoleAutoScroll: true,
        showConsole: false,
        eventSource: null,

        // Computed
        get canStart() {
            return this.hasMetadata && this.hasBinary && !this.isUploading && !this.isProcessing;
        },

        get hasMetadata() {
            return this.files.some(f => f.type === 'metadata');
        },

        get hasBinary() {
            return this.files.some(f => f.type === 'binary');
        },

        get totalProgress() {
            if (this.status === 'uploading') {
                return this.uploadProgress * 0.3; // Upload is 30% of total
            } else if (this.status === 'processing') {
                return 30 + (this.processProgress * 0.7); // Processing is 70%
            } else if (this.status === 'completed') {
                return 100;
            }
            return 0;
        },

        // Lifecycle
        init() {
            this.log('system', 'IL2CPP Dumper initialized');
            this.log('info', 'Ready to accept files');
        },

        destroy() {
            this.closeEventSource();
        },

        // Console methods
        log(type, message) {
            const timestamp = new Date().toLocaleTimeString();
            this.consoleLines = [...this.consoleLines, { type, message, timestamp }];

            // Keep last 500 lines
            if (this.consoleLines.length > 500) {
                this.consoleLines = this.consoleLines.slice(-500);
            }

            // Auto-scroll
            if (this.consoleAutoScroll) {
                this.$nextTick(() => {
                    const console = document.getElementById('console-output');
                    if (console) {
                        console.scrollTop = console.scrollHeight;
                    }
                });
            }
        },

        clearConsole() {
            this.consoleLines = [];
            this.log('system', 'Console cleared');
        },

        getLineClass(type) {
            const classes = {
                'system': 'text-gray-500',
                'info': 'text-cyber-blue',
                'success': 'text-cyber-green',
                'warning': 'text-amber-400',
                'error': 'text-red-400',
                'progress': 'text-purple-400'
            };
            return classes[type] || 'text-gray-300';
        },

        // File handling
        handleDrop(event) {
            this.isDragging = false;
            const droppedFiles = event.dataTransfer.files;
            this.addFiles(droppedFiles);
        },

        handleFileSelect(event) {
            const selectedFiles = event.target.files;
            this.addFiles(selectedFiles);
            event.target.value = '';
        },

        async addFiles(fileList) {
            const newFiles = [];

            for (const file of fileList) {
                // Skip duplicates
                if (this.files.some(f => f.name === file.name)) {
                    this.log('warning', `Skipping duplicate: ${file.name}`);
                    continue;
                }

                // Check file size
                if (file.size > MAX_FILE_SIZE) {
                    this.log('error', `File too large: ${file.name} (${this.formatSize(file.size)} > ${this.formatSize(MAX_FILE_SIZE)})`);
                    continue;
                }

                // Validate file extension
                const ext = file.name.split('.').pop().toLowerCase();
                const validExts = ['so', 'dll', 'dat', 'dylib'];

                if (!validExts.includes(ext)) {
                    this.log('warning', `Invalid file type: .${ext}. Expected .so, .dll, .dat, or .dylib`);
                    this.validationMessage = `Invalid file type: .${ext}`;
                    continue;
                }

                // Detect file type by reading first 4 bytes
                const type = await this.detectFileType(file);

                this.log('info', `Added ${file.name} (${this.formatSize(file.size)}) - detected as ${type}`);

                newFiles.push({
                    file: file,
                    name: file.name,
                    size: file.size,
                    type: type,
                    uploaded: 0,
                    status: 'pending'
                });
            }

            if (newFiles.length > 0) {
                this.files = [...this.files, ...newFiles];
                this.showConsole = true;
            }

            this.updateValidation();
        },

        async detectFileType(file) {
            return new Promise((resolve) => {
                const reader = new FileReader();
                reader.onload = (e) => {
                    const buffer = new Uint8Array(e.target.result);
                    // Read as unsigned 32-bit little-endian
                    const magic = (buffer[0] | (buffer[1] << 8) | (buffer[2] << 16) | (buffer[3] << 24)) >>> 0;

                    // Metadata magic: 0xFAB11BAF
                    if (magic === 0xFAB11BAF) {
                        resolve('metadata');
                    } else {
                        resolve('binary');
                    }
                };
                reader.onerror = () => resolve('binary');
                reader.readAsArrayBuffer(file.slice(0, 4));
            });
        },

        removeFile(index) {
            const file = this.files[index];
            this.log('info', `Removed ${file.name}`);
            this.files = this.files.filter((_, i) => i !== index);
            this.updateValidation();
        },

        updateValidation() {
            if (this.files.length === 0) {
                this.validationMessage = '';
            } else if (!this.hasMetadata && !this.hasBinary) {
                this.validationMessage = 'Upload both an IL2CPP binary and metadata file';
            } else if (!this.hasMetadata) {
                this.validationMessage = 'Missing global-metadata.dat file';
            } else if (!this.hasBinary) {
                this.validationMessage = 'Missing IL2CPP binary file';
            } else {
                this.validationMessage = '';
            }
        },

        // Chunked upload
        async startDump() {
            if (!this.canStart) return;

            this.showConsole = true;
            this.isUploading = true;
            this.status = 'uploading';
            this.uploadProgress = 0;
            this.processProgress = 0;
            this.errorMessage = '';
            this.outputFiles = [];
            this.statusMessage = 'Creating job...';

            try {
                // Step 1: Create job
                this.log('info', 'Creating dump job...');
                const createResponse = await fetch('/api/jobs', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        files: this.files.map(f => ({ name: f.name, size: f.size, type: f.type }))
                    })
                });

                if (!createResponse.ok) {
                    const error = await createResponse.json();
                    throw new Error(error.error || 'Failed to create job');
                }

                const { job_id } = await createResponse.json();
                this.jobId = job_id;
                this.log('success', `Job created: ${job_id.slice(0, 8)}...`);

                // Step 2: Upload files with chunks
                await this.uploadFilesChunked();

                // Step 3: Start processing
                this.isUploading = false;
                this.isProcessing = true;
                this.status = 'processing';
                this.statusMessage = 'Starting dump process...';

                this.log('info', 'Starting IL2CPP dump...');
                const startResponse = await fetch(`/api/jobs/${this.jobId}/start`, {
                    method: 'POST'
                });

                if (!startResponse.ok) {
                    const error = await startResponse.json();
                    throw new Error(error.error || 'Failed to start job');
                }

                // Step 4: Connect to SSE for real-time updates
                this.connectEventSource();

            } catch (error) {
                this.handleError(error);
            }
        },

        async uploadFilesChunked() {
            const totalSize = this.files.reduce((sum, f) => sum + f.size, 0);
            let uploadedTotal = 0;

            // Check if all files are small enough for direct upload
            const allSmall = this.files.every(f => f.size <= DIRECT_UPLOAD_THRESHOLD);

            if (allSmall) {
                // Direct upload - faster for smaller files
                this.log('info', 'Using direct upload (files under 50MB)...');
                await this.uploadFilesDirect();
                return;
            }

            for (const fileObj of this.files) {
                this.log('info', `Uploading ${fileObj.name}...`);
                fileObj.status = 'uploading';

                const file = fileObj.file;
                const totalChunks = Math.ceil(file.size / CHUNK_SIZE);
                const chunksUploaded = new Set();

                // Upload chunks in parallel batches
                const uploadChunk = async (chunkIndex) => {
                    const start = chunkIndex * CHUNK_SIZE;
                    const end = Math.min(start + CHUNK_SIZE, file.size);
                    const chunk = file.slice(start, end);

                    const formData = new FormData();
                    formData.append('chunk', chunk);
                    formData.append('filename', file.name);
                    formData.append('chunk_index', chunkIndex);
                    formData.append('total_chunks', totalChunks);
                    formData.append('file_type', fileObj.type);

                    const response = await fetch(`/api/jobs/${this.jobId}/upload`, {
                        method: 'POST',
                        body: formData
                    });

                    if (!response.ok) {
                        const error = await response.json();
                        throw new Error(error.error || `Failed to upload chunk ${chunkIndex + 1}`);
                    }

                    chunksUploaded.add(chunkIndex);
                    uploadedTotal += (end - start);
                    fileObj.uploaded = chunksUploaded.size * CHUNK_SIZE;
                    this.uploadProgress = (uploadedTotal / totalSize) * 100;

                    return response.json();
                };

                // Process chunks in parallel batches
                const chunkIndices = Array.from({ length: totalChunks }, (_, i) => i);

                for (let i = 0; i < chunkIndices.length; i += PARALLEL_CHUNKS) {
                    const batch = chunkIndices.slice(i, i + PARALLEL_CHUNKS);
                    await Promise.all(batch.map(uploadChunk));

                    // Log progress every batch
                    const progress = Math.round((chunksUploaded.size / totalChunks) * 100);
                    this.log('progress', `${fileObj.name}: ${progress}% (${chunksUploaded.size}/${totalChunks} chunks)`);
                }

                fileObj.status = 'uploaded';
                this.log('success', `Uploaded ${fileObj.name}`);
                this.files = [...this.files];
            }

            this.log('success', 'All files uploaded');
        },

        async uploadFilesDirect() {
            // Direct upload without chunking - for smaller files
            const formData = new FormData();
            for (const fileObj of this.files) {
                formData.append('files', fileObj.file);
                fileObj.status = 'uploading';
            }

            this.files = [...this.files];
            this.uploadProgress = 10;

            const response = await fetch(`/api/jobs/${this.jobId}/upload-direct`, {
                method: 'POST',
                body: formData
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Direct upload failed');
            }

            const result = await response.json();

            for (const fileObj of this.files) {
                fileObj.status = 'uploaded';
                this.log('success', `Uploaded ${fileObj.name}`);
            }

            this.uploadProgress = 100;
            this.files = [...this.files];
            this.log('success', 'All files uploaded');
        },

        // SSE Connection for real-time updates
        connectEventSource() {
            this.closeEventSource();

            this.log('info', 'Connecting to job stream...');
            this.eventSource = new EventSource(`/api/jobs/${this.jobId}/stream`);

            this.eventSource.onopen = () => {
                this.log('success', 'Connected to job stream');
            };

            this.eventSource.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    this.handleStreamEvent(data);
                } catch (e) {
                    console.error('Failed to parse SSE event:', e);
                }
            };

            this.eventSource.onerror = (error) => {
                console.error('SSE Error:', error);
                if (this.status === 'processing') {
                    this.log('warning', 'Connection lost, reconnecting...');
                    // Will auto-reconnect
                }
            };
        },

        closeEventSource() {
            if (this.eventSource) {
                this.eventSource.close();
                this.eventSource = null;
            }
        },

        handleStreamEvent(data) {
            switch (data.type) {
                case 'log':
                    this.log(data.level || 'info', data.message);
                    break;

                case 'progress':
                    this.processProgress = data.progress;
                    this.statusMessage = data.message || 'Processing...';
                    break;

                case 'completed':
                    this.closeEventSource();
                    this.status = 'completed';
                    this.isProcessing = false;
                    this.processProgress = 100;
                    this.outputFiles = data.files || [];
                    this.log('success', '🎉 Dump completed successfully!');
                    this.statusMessage = 'Complete!';
                    break;

                case 'failed':
                    this.closeEventSource();
                    this.handleError(new Error(data.error || 'Dump failed'));
                    break;

                default:
                    console.log('Unknown event type:', data.type);
            }
        },

        handleError(error) {
            this.closeEventSource();
            this.status = 'failed';
            this.isUploading = false;
            this.isProcessing = false;
            this.errorMessage = error.message;
            this.log('error', `Error: ${error.message}`);
            this.statusMessage = 'Failed';
        },

        // Utilities
        formatSize(bytes) {
            if (bytes < 1024) return bytes + ' B';
            if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
            return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
        },

        getFileIcon(filename) {
            if (filename.endsWith('.cs')) return 'file-code-2';
            if (filename.endsWith('.h')) return 'file-text';
            if (filename.endsWith('.json')) return 'file-json';
            return 'file';
        },

        getFileDescription(filename) {
            const descriptions = {
                'dump.cs': 'C# type definitions and method signatures',
                'il2cpp.h': 'C header file for IDA/Ghidra',
                'script.json': 'Method addresses for scripting',
                'stringliteral.json': 'String literal values and indices'
            };
            return descriptions[filename] || '';
        },

        getUploadStatusIcon(status) {
            switch (status) {
                case 'pending': return '○';
                case 'uploading': return '◐';
                case 'uploaded': return '●';
                default: return '○';
            }
        },

        reset() {
            this.closeEventSource();
            this.files = [];
            this.status = null;
            this.uploadProgress = 0;
            this.processProgress = 0;
            this.outputFiles = [];
            this.errorMessage = '';
            this.validationMessage = '';
            this.jobId = null;
            this.log('system', 'Reset complete');
        }
    };
}
