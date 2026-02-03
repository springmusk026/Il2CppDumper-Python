"""
IL2CPP Dumper Flask Server

Features:
- Chunked file uploads
- Real-time SSE streaming for job progress
- Job queue management
- Robust error handling and validation
"""

import os
import re
import uuid
import shutil
import threading
import queue
import time
import json
from pathlib import Path
from typing import Dict, Optional, Generator
from dataclasses import dataclass, field
from flask import Flask, request, jsonify, send_file, render_template, send_from_directory, Response

from werkzeug.utils import secure_filename

# Import the dumper modules
from il2cpp_dumper_py.config import Config
from il2cpp_dumper_py.il2cpp.metadata import Metadata, NotSupportedError
from il2cpp_dumper_py.cli import create_il2cpp_parser, init, dump

app = Flask(__name__, template_folder='templates', static_folder='static')

# Configuration
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB max upload
app.config['UPLOAD_FOLDER'] = '/tmp/il2cpp_uploads'
app.config['OUTPUT_FOLDER'] = '/tmp/il2cpp_outputs'

# Security settings
ALLOWED_EXTENSIONS = {'so', 'dll', 'dat', 'dylib'}
MAX_TOTAL_SIZE = 500 * 1024 * 1024  # 500MB total
MAGIC_METADATA = 0xFAB11BAF


@dataclass
class Job:
    """Represents a dump job."""
    id: str
    status: str = 'created'  # created, uploading, processing, completed, failed
    progress: int = 0
    error: Optional[str] = None
    created: float = field(default_factory=time.time)
    files: list = field(default_factory=list)
    output_files: list = field(default_factory=list)
    upload_dir: str = ''
    output_dir: str = ''
    il2cpp_path: Optional[str] = None
    metadata_path: Optional[str] = None
    event_queue: queue.Queue = field(default_factory=queue.Queue)
    chunks_received: Dict[str, Dict[int, bool]] = field(default_factory=dict)

    def send_event(self, event_type: str, **data):
        """Send an event to connected SSE clients."""
        event = {'type': event_type, **data}
        try:
            self.event_queue.put_nowait(event)
        except queue.Full:
            pass  # Drop event if queue is full

    def log(self, level: str, message: str):
        """Send a log event."""
        self.send_event('log', level=level, message=message)

    def update_progress(self, progress: int, message: str = ''):
        """Update job progress."""
        self.progress = progress
        self.send_event('progress', progress=progress, message=message)


# Job storage
jobs: Dict[str, Job] = {}
jobs_lock = threading.Lock()


def ensure_dirs():
    """Ensure upload and output directories exist."""
    Path(app.config['UPLOAD_FOLDER']).mkdir(parents=True, exist_ok=True)
    Path(app.config['OUTPUT_FOLDER']).mkdir(parents=True, exist_ok=True)


def get_job(job_id: str) -> Optional[Job]:
    """Get a job by ID with validation."""
    try:
        uuid.UUID(job_id)
    except ValueError:
        return None

    with jobs_lock:
        return jobs.get(job_id)


def sanitize_filename(filename: str) -> str:
    """Sanitize filename to prevent path traversal."""
    filename = secure_filename(filename)
    filename = re.sub(r'[^\w\-_\.]', '_', filename)
    if len(filename) > 255:
        name, ext = os.path.splitext(filename)
        filename = name[:250] + ext
    return filename


def validate_file_magic(filepath: str) -> tuple[str | None, str | None]:
    """Validate file by checking magic bytes."""
    try:
        with open(filepath, 'rb') as f:
            data = f.read(4)
            if len(data) < 4:
                return None, "File too small"

            magic = int.from_bytes(data, 'little')

            if magic == MAGIC_METADATA:
                return 'metadata', None
            else:
                # Accept any other file as potential binary
                return 'binary', None
    except Exception as e:
        return None, str(e)


def process_dump_job(job: Job):
    """Process the dump in a background thread with streaming updates."""
    try:
        job.status = 'processing'
        job.log('info', 'Starting IL2CPP dump process...')

        if not job.il2cpp_path or not job.metadata_path:
            raise ValueError("Missing IL2CPP binary or metadata file")

        # Load config
        config = Config.load(None)
        job.update_progress(5, 'Loading configuration...')

        # Initialize
        job.log('info', 'Loading metadata file...')
        job.update_progress(10, 'Loading metadata...')

        metadata, il2cpp = init(job.il2cpp_path, job.metadata_path, config)

        job.log('success', f'Metadata loaded: version {metadata.version}')
        job.log('info', f'Found {len(metadata.type_defs)} type definitions')
        job.update_progress(30, 'Metadata loaded')

        # Search for IL2CPP structures
        job.log('info', 'Searching for IL2CPP code registration...')
        job.update_progress(40, 'Searching binary structures...')

        # Dump
        job.log('info', 'Generating output files...')
        job.update_progress(50, 'Generating dump.cs...')

        dump(metadata, il2cpp, job.output_dir, config)

        job.update_progress(90, 'Finalizing...')

        # Get output files
        job.output_files = [
            f for f in os.listdir(job.output_dir)
            if os.path.isfile(os.path.join(job.output_dir, f))
        ]

        job.log('success', f'Generated {len(job.output_files)} output files')
        for f in job.output_files:
            size = os.path.getsize(os.path.join(job.output_dir, f))
            job.log('info', f'  {f}: {size:,} bytes')

        job.status = 'completed'
        job.progress = 100
        job.send_event('completed', files=job.output_files)

    except Exception as e:
        job.status = 'failed'
        job.error = str(e)
        job.log('error', f'Dump failed: {e}')
        job.send_event('failed', error=str(e))


# ============== Routes ==============

@app.route('/')
def index():
    """Serve the main page."""
    return render_template('index.html')


@app.route('/static/<path:filename>')
def serve_static(filename):
    """Serve static files."""
    return send_from_directory(app.static_folder, filename)


# ============== Job API ==============

@app.route('/api/jobs', methods=['POST'])
def create_job():
    """Create a new dump job."""
    ensure_dirs()

    data = request.get_json()
    if not data or 'files' not in data:
        return jsonify({'error': 'No files specified'}), 400

    files = data['files']
    if len(files) < 2:
        return jsonify({'error': 'Need both IL2CPP binary and metadata file'}), 400

    # Validate total size
    total_size = sum(f.get('size', 0) for f in files)
    if total_size > MAX_TOTAL_SIZE:
        return jsonify({'error': f'Total size exceeds {MAX_TOTAL_SIZE // (1024*1024)}MB limit'}), 400

    # Create job
    job_id = str(uuid.uuid4())
    job = Job(
        id=job_id,
        status='uploading',
        files=files,
        upload_dir=str(Path(app.config['UPLOAD_FOLDER']) / job_id),
        output_dir=str(Path(app.config['OUTPUT_FOLDER']) / job_id)
    )

    # Create directories
    Path(job.upload_dir).mkdir(parents=True, exist_ok=True)
    Path(job.output_dir).mkdir(parents=True, exist_ok=True)

    # Initialize chunk tracking
    for f in files:
        job.chunks_received[f['name']] = {}

    with jobs_lock:
        jobs[job_id] = job

    return jsonify({'job_id': job_id})


@app.route('/api/jobs/<job_id>/upload', methods=['POST'])
def upload_chunk(job_id: str):
    """Upload a file chunk."""
    job = get_job(job_id)
    if not job:
        return jsonify({'error': 'Job not found'}), 404

    if job.status not in ('created', 'uploading'):
        return jsonify({'error': 'Job is not accepting uploads'}), 400

    # Get chunk data
    if 'chunk' not in request.files:
        return jsonify({'error': 'No chunk provided'}), 400

    chunk = request.files['chunk']
    filename = request.form.get('filename', '')
    chunk_index = int(request.form.get('chunk_index', 0))
    total_chunks = int(request.form.get('total_chunks', 1))
    file_type = request.form.get('file_type', 'binary')

    # Validate filename
    safe_filename = sanitize_filename(filename)
    if not safe_filename:
        return jsonify({'error': 'Invalid filename'}), 400

    # Ensure file is in expected list
    expected_file = next((f for f in job.files if f['name'] == filename), None)
    if not expected_file:
        return jsonify({'error': 'Unexpected file'}), 400

    # Write chunk to temp file
    chunk_dir = Path(job.upload_dir) / 'chunks' / safe_filename
    chunk_dir.mkdir(parents=True, exist_ok=True)
    chunk_path = chunk_dir / f'{chunk_index:05d}'

    chunk.save(str(chunk_path))

    # Track chunk
    job.chunks_received[filename][chunk_index] = True

    # Check if all chunks received
    if len(job.chunks_received[filename]) == total_chunks:
        # Assemble file
        final_path = Path(job.upload_dir) / safe_filename
        with open(final_path, 'wb') as outfile:
            for i in range(total_chunks):
                chunk_file = chunk_dir / f'{i:05d}'
                with open(chunk_file, 'rb') as infile:
                    outfile.write(infile.read())

        # Clean up chunks
        shutil.rmtree(chunk_dir, ignore_errors=True)

        # Validate and identify file
        file_type_detected, error = validate_file_magic(str(final_path))
        if error:
            return jsonify({'error': f'Invalid file: {error}'}), 400

        if file_type_detected == 'metadata':
            job.metadata_path = str(final_path)
        else:
            job.il2cpp_path = str(final_path)

        return jsonify({
            'status': 'complete',
            'filename': safe_filename,
            'type': file_type_detected
        })

    return jsonify({
        'status': 'partial',
        'chunk': chunk_index,
        'received': len(job.chunks_received[filename]),
        'total': total_chunks
    })


@app.route('/api/jobs/<job_id>/upload-direct', methods=['POST'])
def upload_direct(job_id: str):
    """Direct upload of complete files (for smaller files)."""
    job = get_job(job_id)
    if not job:
        return jsonify({'error': 'Job not found'}), 404

    if job.status not in ('created', 'uploading'):
        return jsonify({'error': 'Job is not accepting uploads'}), 400

    if 'files' not in request.files:
        return jsonify({'error': 'No files provided'}), 400

    uploaded = []
    for file in request.files.getlist('files'):
        if not file.filename:
            continue

        safe_filename = sanitize_filename(file.filename)
        if not safe_filename:
            continue

        filepath = Path(job.upload_dir) / safe_filename
        file.save(str(filepath))

        # Validate and identify file
        file_type, error = validate_file_magic(str(filepath))
        if error:
            filepath.unlink(missing_ok=True)
            continue

        if file_type == 'metadata':
            job.metadata_path = str(filepath)
        else:
            job.il2cpp_path = str(filepath)

        uploaded.append({'filename': safe_filename, 'type': file_type})

    return jsonify({'status': 'complete', 'files': uploaded})


@app.route('/api/jobs/<job_id>/start', methods=['POST'])
def start_job(job_id: str):
    """Start processing a job."""
    job = get_job(job_id)
    if not job:
        return jsonify({'error': 'Job not found'}), 404

    if job.status != 'uploading':
        return jsonify({'error': f'Job cannot be started (status: {job.status})'}), 400

    # Verify files are uploaded
    if not job.il2cpp_path:
        return jsonify({'error': 'IL2CPP binary not uploaded'}), 400
    if not job.metadata_path:
        return jsonify({'error': 'Metadata file not uploaded'}), 400

    # Start processing thread
    thread = threading.Thread(target=process_dump_job, args=(job,), daemon=True)
    thread.start()

    return jsonify({'status': 'started'})


@app.route('/api/jobs/<job_id>/stream')
def stream_job(job_id: str):
    """SSE endpoint for job events."""
    job = get_job(job_id)
    if not job:
        return jsonify({'error': 'Job not found'}), 404

    from flask import stream_with_context

    def generate():
        """Generate SSE events."""
        # Send initial status immediately
        yield f"data: {json.dumps({'type': 'status', 'status': job.status, 'progress': job.progress})}\n\n"

        # If already completed/failed, send that and close
        if job.status == 'completed':
            yield f"data: {json.dumps({'type': 'completed', 'files': job.output_files})}\n\n"
            return
        elif job.status == 'failed':
            yield f"data: {json.dumps({'type': 'failed', 'error': job.error})}\n\n"
            return

        # Stream events
        while True:
            try:
                event = job.event_queue.get(timeout=1.0)
                yield f"data: {json.dumps(event)}\n\n"

                if event.get('type') in ('completed', 'failed'):
                    break

            except queue.Empty:
                # Send comment as keepalive
                yield ":keepalive\n\n"

                # Check if job finished without sending event
                if job.status == 'completed':
                    yield f"data: {json.dumps({'type': 'completed', 'files': job.output_files})}\n\n"
                    break
                elif job.status == 'failed':
                    yield f"data: {json.dumps({'type': 'failed', 'error': job.error})}\n\n"
                    break

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
            'Connection': 'keep-alive',
        }
    )


@app.route('/api/jobs/<job_id>')
def get_job_status(job_id: str):
    """Get job status."""
    job = get_job(job_id)
    if not job:
        return jsonify({'error': 'Job not found'}), 404

    return jsonify({
        'id': job.id,
        'status': job.status,
        'progress': job.progress,
        'error': job.error,
        'files': job.output_files,
        'created': job.created
    })


@app.route('/api/download/<job_id>/<filename>')
def download_file(job_id: str, filename: str):
    """Download an output file."""
    job = get_job(job_id)
    if not job:
        return jsonify({'error': 'Job not found'}), 404

    if job.status != 'completed':
        return jsonify({'error': 'Job not completed'}), 400

    safe_filename = sanitize_filename(filename)
    if safe_filename not in job.output_files:
        return jsonify({'error': 'File not found'}), 404

    filepath = Path(job.output_dir) / safe_filename

    # Prevent path traversal
    try:
        filepath = filepath.resolve()
        if not str(filepath).startswith(str(Path(job.output_dir).resolve())):
            return jsonify({'error': 'Invalid path'}), 400
    except Exception:
        return jsonify({'error': 'Invalid path'}), 400

    if not filepath.exists():
        return jsonify({'error': 'File not found'}), 404

    return send_file(str(filepath), as_attachment=True)


@app.route('/api/download/<job_id>/all.zip')
def download_all_zip(job_id: str):
    """Download all output files as a ZIP archive."""
    import zipfile
    import io

    job = get_job(job_id)
    if not job:
        return jsonify({'error': 'Job not found'}), 404

    if job.status != 'completed':
        return jsonify({'error': 'Job not completed'}), 400

    if not job.output_files:
        return jsonify({'error': 'No output files'}), 404

    # Create ZIP in memory
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        for filename in job.output_files:
            filepath = Path(job.output_dir) / filename
            if filepath.exists():
                zf.write(filepath, filename)

    zip_buffer.seek(0)

    return send_file(
        zip_buffer,
        mimetype='application/zip',
        as_attachment=True,
        download_name=f'il2cpp_dump_{job_id[:8]}.zip'
    )


# ============== Legacy API (for backwards compatibility) ==============

@app.route('/api/dump', methods=['POST'])
def api_dump_legacy():
    """Legacy single-request dump endpoint."""
    ensure_dirs()

    if 'files' not in request.files:
        return jsonify({'error': 'No files uploaded'}), 400

    uploaded_files = request.files.getlist('files')
    if len(uploaded_files) < 2:
        return jsonify({'error': 'Need both IL2CPP binary and metadata file'}), 400

    job_id = str(uuid.uuid4())
    job = Job(
        id=job_id,
        upload_dir=str(Path(app.config['UPLOAD_FOLDER']) / job_id),
        output_dir=str(Path(app.config['OUTPUT_FOLDER']) / job_id)
    )

    Path(job.upload_dir).mkdir(parents=True, exist_ok=True)
    Path(job.output_dir).mkdir(parents=True, exist_ok=True)

    for file in uploaded_files:
        if not file.filename:
            continue

        filename = sanitize_filename(file.filename)
        filepath = Path(job.upload_dir) / filename
        file.save(str(filepath))

        file_type, _ = validate_file_magic(str(filepath))
        if file_type == 'metadata':
            job.metadata_path = str(filepath)
        else:
            job.il2cpp_path = str(filepath)

    if not job.il2cpp_path or not job.metadata_path:
        shutil.rmtree(job.upload_dir, ignore_errors=True)
        return jsonify({'error': 'Could not identify files'}), 400

    with jobs_lock:
        jobs[job_id] = job

    # Start processing
    thread = threading.Thread(target=process_dump_job, args=(job,), daemon=True)
    thread.start()

    return jsonify({'job_id': job_id})


@app.route('/api/status/<job_id>')
def api_status_legacy(job_id: str):
    """Legacy status endpoint."""
    job = get_job(job_id)
    if not job:
        return jsonify({'error': 'Job not found'}), 404

    return jsonify({
        'status': job.status,
        'progress': job.progress,
        'files': job.output_files,
        'error': job.error,
        'created': job.created
    })


@app.route('/api/docs')
def api_docs():
    """API documentation."""
    return jsonify({
        'name': 'IL2CPP Dumper API',
        'version': '2.0.0',
        'endpoints': {
            'POST /api/jobs': {
                'description': 'Create a new dump job',
                'body': {'files': [{'name': 'string', 'size': 'number', 'type': 'binary|metadata'}]},
                'response': {'job_id': 'uuid'}
            },
            'POST /api/jobs/{id}/upload': {
                'description': 'Upload a file chunk',
                'content_type': 'multipart/form-data',
                'fields': {
                    'chunk': 'file blob',
                    'filename': 'original filename',
                    'chunk_index': 'chunk number (0-based)',
                    'total_chunks': 'total number of chunks',
                    'file_type': 'binary or metadata'
                }
            },
            'POST /api/jobs/{id}/start': {
                'description': 'Start processing the job'
            },
            'GET /api/jobs/{id}/stream': {
                'description': 'SSE stream for real-time job events',
                'events': ['log', 'progress', 'completed', 'failed']
            },
            'GET /api/jobs/{id}': {
                'description': 'Get job status'
            },
            'GET /api/download/{id}/{filename}': {
                'description': 'Download output file'
            },
            'GET /api/download/{id}/all.zip': {
                'description': 'Download all output files as ZIP'
            }
        },
        'limits': {
            'max_upload_size': '500 MB',
            'job_retention': '30 minutes'
        },
        'legacy_endpoints': {
            'POST /api/dump': 'Single-request upload (no chunking)',
            'GET /api/status/{id}': 'Get job status'
        }
    })


# ============== Cleanup ==============

# Cleanup settings
JOB_RETENTION_SECONDS = 30 * 60  # 30 minutes
CLEANUP_INTERVAL_SECONDS = 60  # Check every minute


def cleanup_old_jobs():
    """Clean up jobs older than JOB_RETENTION_SECONDS."""
    while True:
        time.sleep(CLEANUP_INTERVAL_SECONDS)
        current_time = time.time()
        to_delete = []

        with jobs_lock:
            for job_id, job in jobs.items():
                age = current_time - job.created
                if age > JOB_RETENTION_SECONDS:
                    to_delete.append(job_id)

            for job_id in to_delete:
                del jobs[job_id]

        for job_id in to_delete:
            shutil.rmtree(Path(app.config['UPLOAD_FOLDER']) / job_id, ignore_errors=True)
            shutil.rmtree(Path(app.config['OUTPUT_FOLDER']) / job_id, ignore_errors=True)
            print(f"🧹 Cleaned up job {job_id[:8]}...")

        if to_delete:
            print(f"🧹 Cleaned up {len(to_delete)} old job(s)")


if __name__ == '__main__':
    ensure_dirs()

    # Start cleanup thread
    cleanup_thread = threading.Thread(target=cleanup_old_jobs, daemon=True)
    cleanup_thread.start()

    print("=" * 60)
    print("🎮 IL2CPP Dumper Server v2.0")
    print("=" * 60)
    print("📍 Web Interface: http://localhost:5000")
    print("📚 API Docs: http://localhost:5000/api/docs")
    print("=" * 60)

    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
