# IL2CPP Dumper - Python Port

A Python port of the [Il2CppDumper](https://github.com/Perfare/Il2CppDumper) tool for extracting metadata from Unity IL2CPP compiled games.

## Features

- Parse global-metadata.dat files (versions 16-31)
- Parse IL2CPP binaries:
  - ✅ ELF32 (Android 32-bit)
  - ✅ ELF64 (Android 64-bit, Linux)
  - ✅ PE (Windows)
  - ✅ Mach-O 32-bit (iOS/macOS)
  - ✅ Mach-O 64-bit (iOS/macOS)
  - ✅ FAT/Universal Mach-O (iOS/macOS)
  - ✅ NSO (Nintendo Switch)
  - ✅ WebAssembly (WebGL)
- Generate dump.cs with all types, methods, and fields
- Generate script.json for IDA/Ghidra
- Generate il2cpp.h C header file
- Version-aware structure parsing
- Automatic registration structure detection

## Requirements

- Python 3.8+
- Optional: `lz4` package for Nintendo Switch NSO files (`pip install lz4`)

## Installation

```bash
# Clone or copy the il2cpp_dumper_py directory
cd il2cpp_dumper_py

# Install (optional)
pip install -e .

# For NSO support (optional)
pip install lz4
```

## Usage

### Command Line

```bash
# Basic usage
python -m il2cpp_dumper_py.cli libil2cpp.so global-metadata.dat output/

# Or if installed
il2cpp-dumper libil2cpp.so global-metadata.dat output/

# Windows PE
il2cpp-dumper GameAssembly.dll global-metadata.dat output/

# iOS/macOS
il2cpp-dumper UnityFramework global-metadata.dat output/

# Nintendo Switch
il2cpp-dumper main.nso global-metadata.dat output/

# WebGL
il2cpp-dumper build.wasm global-metadata.dat output/
```

### Python API

```python
from il2cpp_dumper_py import Metadata, Config
from il2cpp_dumper_py.formats.elf import Elf, Elf64
from il2cpp_dumper_py.executor import Il2CppExecutor
from il2cpp_dumper_py.output import Il2CppDecompiler

# Load metadata
with open('global-metadata.dat', 'rb') as f:
    metadata = Metadata(f.read())

print(f"Metadata version: {metadata.version}")
print(f"Types: {len(metadata.type_defs)}")
print(f"Methods: {len(metadata.method_defs)}")

# Load IL2CPP binary
with open('libil2cpp.so', 'rb') as f:
    data = f.read()

# Detect 32/64 bit
if data[4] == 2:
    il2cpp = Elf64(data)
else:
    il2cpp = Elf(data)

# Initialize
il2cpp.set_properties(metadata.version, metadata.metadata_usages_count)

# Search for registration
method_count = sum(1 for m in metadata.method_defs if m.method_index >= 0)
il2cpp.plus_search(method_count, len(metadata.type_defs), len(metadata.image_defs))

# Dump
executor = Il2CppExecutor(metadata, il2cpp)
config = Config()
decompiler = Il2CppDecompiler(executor)
decompiler.decompile(config, 'output/')
```

## Project Structure

```
il2cpp_dumper_py/
├── __init__.py           # Package init
├── cli.py                # Command-line interface
├── config.py             # Configuration handling
├── config.json           # Default configuration
│
├── io/                   # Binary I/O utilities
│   ├── binary_stream.py  # Binary stream reader
│   └── version_aware.py  # Version-conditional fields
│
├── il2cpp/               # IL2CPP core
│   ├── base.py           # Abstract IL2CPP parser
│   ├── metadata.py       # Metadata parser
│   ├── structures.py     # Data structures
│   └── enums.py          # Enumerations
│
├── formats/              # Executable format parsers
│   ├── elf.py            # ELF32/ELF64 parser
│   ├── elf_structures.py # ELF structures
│   ├── pe.py             # Windows PE parser
│   ├── pe_structures.py  # PE structures
│   ├── macho.py          # Mach-O parser (32/64/FAT)
│   ├── macho_structures.py # Mach-O structures
│   ├── nso.py            # Nintendo Switch NSO parser
│   ├── nso_structures.py # NSO structures
│   ├── wasm.py           # WebAssembly parser
│   └── wasm_structures.py # WASM structures
│
├── search/               # Registration search
│   └── section_helper.py # Section search helper
│
├── executor/             # Type resolution
│   └── il2cpp_executor.py
│
├── output/               # Output generation
│   ├── decompiler.py     # dump.cs generator
│   ├── struct_generator.py # il2cpp.h and script.json
│   └── script_json.py    # JSON output structures
│
└── utils/                # Utilities
    ├── pattern_search.py # Pattern matching
    └── string_utils.py   # String utilities
```

## Compared to C# Version

| Feature | C# Version | Python Port |
|---------|------------|-------------|
| Metadata parsing | ✅ | ✅ |
| ELF format | ✅ | ✅ |
| PE format | ✅ | ✅ |
| Mach-O format | ✅ | ✅ |
| NSO format | ✅ | ✅ |
| WebAssembly | ✅ | ✅ |
| dump.cs generation | ✅ | ✅ |
| script.json | ✅ | ✅ |
| il2cpp.h | ✅ | ✅ |
| DummyDLL generation | ✅ | ❌ (requires .NET) |
| Custom attributes (v29+) | ✅ | 🚧 |

## Output Files

- `dump.cs` - C# pseudo-code with all types, methods, and fields
- `script.json` - JSON file with method addresses for IDA/Ghidra scripts
- `il2cpp.h` - C header file with type definitions

## License

MIT License - Based on the original Il2CppDumper by Perfare.
