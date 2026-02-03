# IL2CPP Dumper CLI Documentation

## Usage

```bash
python -m il2cpp_dumper_py <il2cpp-binary> <global-metadata.dat> [output-directory]
```

## Arguments

| Argument | Description | Required |
|----------|-------------|----------|
| `il2cpp-binary` | Path to IL2CPP binary file (libil2cpp.so, GameAssembly.dll, etc.) | Yes |
| `global-metadata.dat` | Path to global-metadata.dat file | Yes |
| `output-directory` | Directory for output files (default: current directory) | No |

## Examples

### Basic Usage

```bash
# Android (ELF)
python -m il2cpp_dumper_py libil2cpp.so global-metadata.dat

# Windows (PE)
python -m il2cpp_dumper_py GameAssembly.dll global-metadata.dat

# iOS (Mach-O)
python -m il2cpp_dumper_py UnityFramework global-metadata.dat

# With custom output directory
python -m il2cpp_dumper_py libil2cpp.so global-metadata.dat ./output
```

### Using the Package Directly

```python
from il2cpp_dumper_py.cli import init, dump
from il2cpp_dumper_py.config import Config

# Load config
config = Config.load(None)

# Initialize
metadata, il2cpp = init('libil2cpp.so', 'global-metadata.dat', config)

# Dump
dump(metadata, il2cpp, './output', config)
```

## Output Files

After running, the following files are generated:

| File | Description |
|------|-------------|
| `dump.cs` | C#-like pseudocode with type definitions, methods, fields, and RVA addresses |
| `il2cpp.h` | C header file with struct definitions for use in IDA Pro or Ghidra |
| `script.json` | JSON file with method addresses and signatures for scripting |
| `stringliteral.json` | JSON file with string literal values and their indices |

## Supported Binary Formats

| Format | Extension | Platform |
|--------|-----------|----------|
| ELF | `.so` | Android, Linux |
| PE | `.dll`, `.exe` | Windows |
| Mach-O | (no extension), `.dylib` | iOS, macOS |
| NSO | `.nso` | Nintendo Switch |
| WebAssembly | `.wasm` | Web |

## Supported IL2CPP Versions

- Version 16 to 31
- Sub-versions: 24.1, 24.2, 24.3, 24.4, 24.5, 27.1, 27.2, 29.1

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success |
| 1 | Error (missing files, unsupported version, etc.) |

## Troubleshooting

### "Metadata version X not supported"

The IL2CPP version is not supported. Check if you have the latest version of the tool.

### "Could not find CodeRegistration"

The binary format might not be recognized correctly, or the IL2CPP structures are obfuscated.

### Slow performance

- Make sure you're using Python 3.11+
- The first run might be slower due to Python JIT warmup
- Large games with many types will take longer

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `IL2CPP_CONFIG` | Path to custom config.json | `./config.json` |

## Configuration File

Create a `config.json` to customize behavior:

```json
{
  "DumpMethod": true,
  "DumpField": true,
  "DumpProperty": true,
  "DumpAttribute": true,
  "DumpFieldOffset": true,
  "DumpMethodOffset": true,
  "DumpTypeDefIndex": true,
  "GenerateDummyDll": false,
  "GenerateScript": true,
  "RequireAnyKey": false,
  "ForceIl2CppVersion": null,
  "ForceVersion": null
}
```

## Performance Tips

1. **Use SSD**: Reading large binaries is I/O bound
2. **Python 3.11+**: Significant performance improvements
3. **Sufficient RAM**: Large games may need 4GB+ RAM
4. **Close other applications**: Reduces memory pressure

## See Also

- [API.md](API.md) - REST API documentation
- [README.md](README.md) - Project overview
- [DEVELOPMENT.md](DEVELOPMENT.md) - Development notes
