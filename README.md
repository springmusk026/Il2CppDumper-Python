# IL2CPP Dumper - Python Port

A high-performance Python port of [IL2CPP Dumper](https://github.com/Perfare/Il2CppDumper), a tool for extracting metadata from Unity IL2CPP compiled games.

[![GitHub](https://img.shields.io/badge/GitHub-springmusk026-black.svg)](https://github.com/springmusk026/Il2CppDumper-Python)
![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-3.0+-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

## ✨ Features

- **Multi-format support**: ELF (Android), PE (Windows), Mach-O (iOS/macOS), NSO (Nintendo Switch), WebAssembly
- **Full metadata extraction**: Types, methods, fields, properties, events, generics
- **Web Interface**: Modern UI with Tailwind CSS, real-time console, chunked uploads
- **REST API**: Full API with SSE streaming for real-time progress
- **Output formats**:
  - `dump.cs` - C#-like pseudocode with addresses and offsets
  - `il2cpp.h` - C header file with struct definitions for IDA/Ghidra
  - `script.json` - Method addresses for scripting
  - `stringliteral.json` - String literal data

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/springmusk026/Il2CppDumper-Python.git
cd Il2CppDumper-Python

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Command Line Usage

```bash
python -m il2cpp_dumper_py <il2cpp-binary> <global-metadata.dat> [output-directory]
```

Example:
```bash
python -m il2cpp_dumper_py libil2cpp.so global-metadata.dat ./output
```

### Web Server

```bash
python server.py
```

Then visit `http://localhost:5000` to use the web interface.

## 🌐 API

### Modern API (v2.0)

| Endpoint | Description |
|----------|-------------|
| `POST /api/jobs` | Create a new dump job |
| `POST /api/jobs/{id}/upload` | Upload file chunks |
| `POST /api/jobs/{id}/upload-direct` | Direct upload (files < 50MB) |
| `POST /api/jobs/{id}/start` | Start processing |
| `GET /api/jobs/{id}/stream` | SSE stream for real-time updates |
| `GET /api/jobs/{id}` | Get job status |
| `GET /api/download/{id}/{filename}` | Download output file |
| `GET /api/download/{id}/all.zip` | Download all files as ZIP |

### Legacy API

| Endpoint | Description |
|----------|-------------|
| `POST /api/dump` | Upload files and start dump |
| `GET /api/status/{id}` | Check job status |

See [API.md](API.md) for full documentation.

## 📊 Supported Versions

- IL2CPP versions 16 to 31
- Sub-versions: 24.1, 24.2, 24.3, 24.4, 24.5, 27.1, 27.2, 29.1

## ⚡ Performance

Optimized Python implementation with batch operations and caching:

| Phase | Time |
|-------|------|
| Metadata loading | ~3.7s |
| Binary loading | ~5.2s |
| Search/Init | ~5.4s |
| Decompile | ~14s |
| Struct Generation | ~6.4s |
| **Total** | **~35s** |

## 📁 Project Structure

```
├── server.py                 # Flask web server
├── requirements.txt          # Python dependencies
├── templates/                # HTML templates
│   └── index.html           # Web UI (Tailwind + Alpine.js)
├── static/
│   └── js/app.js            # Frontend JavaScript
├── il2cpp_dumper_py/         # Core dumper package
│   ├── cli.py               # Command-line interface
│   ├── config.py            # Configuration
│   ├── executor/            # Type resolution
│   ├── formats/             # Binary parsers (ELF, PE, Mach-O, NSO, WASM)
│   ├── il2cpp/              # IL2CPP structures and metadata
│   ├── io/                  # Binary stream reading
│   ├── output/              # Output generators
│   ├── search/              # Registration search
│   └── utils/               # Utilities
├── API.md                   # API documentation
├── DEVELOPMENT.md           # Development notes
└── VIBE.md                  # The vibe coding manifesto 🎭
```

## 🔧 Configuration

The server uses these default settings:

- **Port**: 5000
- **Max upload size**: 500 MB
- **Job retention**: 30 minutes
- **Chunk size**: 10 MB

## 🛠️ Development

```bash
# Run development server
./devserver.sh

# Or manually
source .venv/bin/activate
python -u server.py
```

## 📜 License

MIT License

## 🙏 Credits

- Original C# implementation: [Perfare/Il2CppDumper](https://github.com/Perfare/Il2CppDumper)
- Python port & web interface: This project
- UI: Tailwind CSS, Alpine.js, Lucide Icons

---

**⚠️ Disclaimer**: This tool is for educational and research purposes. Respect game developers' rights and terms of service.
