# IL2CPP Dumper API Documentation v2.0

## Base URL

```
http://localhost:5000
```

## Overview

The IL2CPP Dumper API provides two ways to interact with the service:

1. **Modern API (v2.0)** - Chunked uploads with real-time SSE streaming
2. **Legacy API** - Simple single-request uploads (backwards compatible)

---

## Modern API (Recommended)

### Workflow

1. Create a job with file metadata
2. Upload files in chunks
3. Start the job
4. Connect to SSE stream for real-time updates
5. Download results when complete

---

### POST /api/jobs

Create a new dump job.

**Request:**
```json
{
  "files": [
    { "name": "libil2cpp.so", "size": 178409192, "type": "binary" },
    { "name": "global-metadata.dat", "size": 21471640, "type": "metadata" }
  ]
}
```

**Response:**
```json
{
  "job_id": "8913d65b-342e-4e98-b929-7eb997a71ae7"
}
```

---

### POST /api/jobs/{job_id}/upload

Upload a file chunk. Files are uploaded in 2MB chunks.

**Request:**
- Content-Type: `multipart/form-data`
- Fields:
  - `chunk`: File blob (2MB max per chunk)
  - `filename`: Original filename
  - `chunk_index`: Chunk number (0-based)
  - `total_chunks`: Total number of chunks
  - `file_type`: `binary` or `metadata`

**Response (partial):**
```json
{
  "status": "partial",
  "chunk": 5,
  "received": 6,
  "total": 85
}
```

**Response (complete):**
```json
{
  "status": "complete",
  "filename": "libil2cpp.so",
  "type": "binary"
}
```

---

### POST /api/jobs/{job_id}/start

Start processing the job after all files are uploaded.

**Response:**
```json
{
  "status": "started"
}
```

---

### GET /api/jobs/{job_id}/stream

Server-Sent Events (SSE) endpoint for real-time job updates.

**Event Types:**

```javascript
// Status update
{ "type": "status", "status": "processing", "progress": 0 }

// Log message
{ "type": "log", "level": "info", "message": "Loading metadata..." }

// Progress update
{ "type": "progress", "progress": 50, "message": "Generating output..." }

// Job completed
{ "type": "completed", "files": ["dump.cs", "il2cpp.h", "script.json", "stringliteral.json"] }

// Job failed
{ "type": "failed", "error": "Error message" }
```

**Log Levels:** `info`, `success`, `warning`, `error`, `progress`

**Example:**
```javascript
const eventSource = new EventSource('/api/jobs/{job_id}/stream');
eventSource.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log(data);
};
```

---

### GET /api/jobs/{job_id}

Get current job status (non-streaming).

**Response:**
```json
{
  "id": "8913d65b-342e-4e98-b929-7eb997a71ae7",
  "status": "completed",
  "progress": 100,
  "error": null,
  "files": ["dump.cs", "il2cpp.h", "script.json", "stringliteral.json"],
  "created": 1234567890.123
}
```

**Status Values:**
- `created` - Job created, awaiting uploads
- `uploading` - Files being uploaded
- `processing` - Dump in progress
- `completed` - Dump finished successfully
- `failed` - Dump failed (check `error` field)

---

### GET /api/download/{job_id}/{filename}

Download an output file from a completed job.

**Response:** File download with `Content-Disposition: attachment`

---

## Legacy API

For simple use cases or backwards compatibility.

### POST /api/dump

Upload files and start dump in a single request.

**Request:**
- Content-Type: `multipart/form-data`
- Files:
  - `files`: IL2CPP binary
  - `files`: global-metadata.dat

**Response:**
```json
{
  "job_id": "8913d65b-342e-4e98-b929-7eb997a71ae7"
}
```

---

### GET /api/status/{job_id}

Get job status (legacy format).

**Response:**
```json
{
  "status": "completed",
  "progress": 100,
  "files": ["dump.cs", "il2cpp.h", "script.json", "stringliteral.json"],
  "error": null,
  "created": 1234567890.123
}
```

---

## Output Files

| File | Description |
|------|-------------|
| `dump.cs` | C#-like pseudocode with type definitions, methods, fields, and addresses |
| `il2cpp.h` | C header file with struct definitions for use in IDA/Ghidra |
| `script.json` | JSON file with method addresses and signatures for scripting |
| `stringliteral.json` | JSON file with string literal values and indices |

---

## Limits

- Maximum file size: 500 MB total
- Maximum chunk size: 10 MB (recommended: 2 MB)
- Jobs automatically cleaned up after 1 hour

---

## Complete Example (JavaScript)

```javascript
async function dumpIL2CPP(binaryFile, metadataFile) {
  const CHUNK_SIZE = 2 * 1024 * 1024; // 2MB

  // 1. Create job
  const createRes = await fetch('/api/jobs', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      files: [
        { name: binaryFile.name, size: binaryFile.size, type: 'binary' },
        { name: metadataFile.name, size: metadataFile.size, type: 'metadata' }
      ]
    })
  });
  const { job_id } = await createRes.json();

  // 2. Upload files in chunks
  for (const file of [binaryFile, metadataFile]) {
    const totalChunks = Math.ceil(file.size / CHUNK_SIZE);
    const fileType = file.name.includes('metadata') ? 'metadata' : 'binary';

    for (let i = 0; i < totalChunks; i++) {
      const chunk = file.slice(i * CHUNK_SIZE, (i + 1) * CHUNK_SIZE);
      const formData = new FormData();
      formData.append('chunk', chunk);
      formData.append('filename', file.name);
      formData.append('chunk_index', i);
      formData.append('total_chunks', totalChunks);
      formData.append('file_type', fileType);

      await fetch(`/api/jobs/${job_id}/upload`, {
        method: 'POST',
        body: formData
      });
    }
  }

  // 3. Start processing
  await fetch(`/api/jobs/${job_id}/start`, { method: 'POST' });

  // 4. Connect to SSE stream
  return new Promise((resolve, reject) => {
    const eventSource = new EventSource(`/api/jobs/${job_id}/stream`);

    eventSource.onmessage = (event) => {
      const data = JSON.parse(event.data);

      if (data.type === 'completed') {
        eventSource.close();
        resolve({ job_id, files: data.files });
      } else if (data.type === 'failed') {
        eventSource.close();
        reject(new Error(data.error));
      } else if (data.type === 'log') {
        console.log(`[${data.level}] ${data.message}`);
      }
    };

    eventSource.onerror = () => {
      eventSource.close();
      reject(new Error('Connection lost'));
    };
  });
}

// Usage
const result = await dumpIL2CPP(binaryFile, metadataFile);
console.log('Output files:', result.files);

// Download files
for (const file of result.files) {
  window.open(`/api/download/${result.job_id}/${file}`);
}
```

---

## cURL Examples

### Legacy Single-Request Upload

```bash
curl -X POST \
  -F "files=@libil2cpp.so" \
  -F "files=@global-metadata.dat" \
  http://localhost:5000/api/dump
```

### Check Status

```bash
curl http://localhost:5000/api/status/{job_id}
```

### Download File

```bash
curl -O http://localhost:5000/api/download/{job_id}/dump.cs
```
