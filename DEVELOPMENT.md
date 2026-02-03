# IL2CPP Dumper Python Port - Development Journey

This document describes the complete journey of porting IL2CPP Dumper from C# to Python, including all challenges faced and optimizations applied.

## Overview

The goal was to port [Perfare's IL2CPP Dumper](https://github.com/Perfare/Il2CppDumper) from C# to Python while maintaining correctness and achieving reasonable performance.

## Initial Challenges

### 1. Structure Size Mismatches (64-bit)

**Problem**: The original Python port used 4-byte integers for all fields, but 64-bit binaries require 8-byte pointers.

**Solution**: Created helper functions for field definitions:
```python
def ptr_field(default: int = 0):
    """Create a pointer field (8 bytes) for 64-bit structures."""
    return field(default=default, metadata={'binary_size': 8, 'unsigned': True})

def ptr_version_field(min_ver: float = 0, max_ver: float = 99, default: int = 0):
    """Create a pointer field (8 bytes) with version constraints."""
    return version_field(min_ver=min_ver, max_ver=max_ver, default=default, binary_size=8, unsigned=True)
```

**Affected structures**:
- `Il2CppCodeRegistration` - All pointer fields changed to 8 bytes
- `Il2CppMetadataRegistration` - All pointer fields changed to 8 bytes
- `Il2CppCodeGenModule` - Pointer and count fields
- `Il2CppGenericClass`, `Il2CppGenericContext`, `Il2CppGenericInst` - All fields
- `Il2CppType` - `datapoint` field is 8 bytes (ulong)

### 2. Search Algorithm Offset Errors

**Problem**: The PlusSearch algorithm was finding wrong addresses for v29.1+.

**Root cause**: Field count offset was 14 instead of 16 for v29.1+.

**Fix in `section_helper.py`**:
```python
if self._il2cpp.version >= 29.1:
    return ref_va3 - ptr_size * 16
elif self._il2cpp.version >= 29:
    return ref_va3 - ptr_size * 14
return ref_va3 - ptr_size * 13
```

### 3. Method Definition Field Sizes

**Problem**: `Il2CppMethodDefinition` had wrong field sizes causing misalignment.

**Solution**: Changed `flags`, `iflags`, `slot`, `parameter_count` to use `ushort_field()` (2 bytes each).

### 4. Type Resolution Returning UnknownType(0)

**Problem**: All types were showing as `UnknownType(0)` because `Il2CppType.bits` was always 0.

**Root cause**: `Il2CppType.datapoint` was 4 bytes instead of 8, causing `bits` to be read at wrong offset.

**Fix**: Changed `datapoint` to `ulong_field(0)` (8 bytes).

## Performance Optimization Journey

### Initial Performance: ~2.5 minutes

The initial working port was extremely slow, with metadata loading alone taking ~30 seconds.

### Optimization 1: Batch Array Reading

**Problem**: Array reading used Python loops calling `read_uint32()` for each element.

**Solution**: Use `struct.unpack` with batch reads:
```python
def read_uint32_array(self, addr: Optional[int], count: int) -> List[int]:
    if count <= 0:
        return []
    if addr is not None:
        self.position = addr
    data = self.read_bytes(count * 4)
    return list(struct.unpack(f'<{count}I', data))
```

**Impact**: Reduced array reading from O(n) function calls to single unpack.

### Optimization 2: Fast Class Reading

**Problem**: `read_class()` used reflection (`get_type_hints()`, `fields()`) for every structure read.

**Solution**: Created `read_class_fast()` that pre-compiles struct formats and caches them:
```python
_STRUCT_CACHE: Dict[Tuple[type, float], Tuple[str, List[str], int, Dict[str, type]]] = {}

def read_class_array_fast(self, cls, count):
    format_str, field_names, struct_size, nested_fields = self._get_struct_format(cls)
    if not nested_fields and struct_size > 0:
        total_data = self.read_bytes(struct_size * count)
        results = []
        for i in range(count):
            offset = i * struct_size
            values = struct.unpack(format_str, total_data[offset:offset + struct_size])
            instance = cls()
            for name, value in zip(field_names, values):
                setattr(instance, name, value)
            results.append(instance)
        return results
```

**Impact**: Metadata loading dropped from ~30s to ~3s.

### Optimization 3: Direct Struct Unpacking for Hot Paths

**Problem**: Generic method loading was slow due to many structure reads.

**Solution**: Direct `struct.unpack` for known structures:
```python
# Il2CppMethodSpec is 12 bytes: 3 x int32
data = self.read_bytes(mr.method_specs_count * 12)
for i in range(mr.method_specs_count):
    offset = i * 12
    values = struct.unpack('<iii', data[offset:offset + 12])
    ms = Il2CppMethodSpec()
    ms.method_definition_index = values[0]
    ms.class_index_index = values[1]
    ms.method_index_index = values[2]
    self.method_specs.append(ms)
```

**Impact**: Search/init phase dropped from ~45s to ~5s.

### Optimization 4: Enum to Plain Int Constants

**Problem**: Python's `IntFlag` enum has extremely slow `__and__` operations (called 2.2M times).

**Solution**: Changed from `IntFlag` to plain classes with int constants:
```python
# Before (slow)
class MethodAttributes(IntFlag):
    METHOD_ATTRIBUTE_STATIC = 0x0010

# After (fast)
class MethodAttributes:
    METHOD_ATTRIBUTE_STATIC = 0x0010
```

**Impact**: Decompiler phase dropped from ~47s to ~14s.

### Optimization 5: Chunked String Reading

**Problem**: `read_string_to_null` read byte-by-byte (2.9M calls to `read_byte()`).

**Solution**: Read in 256-byte chunks:
```python
def read_string_to_null(self, addr=None):
    if addr is not None:
        self.position = addr
    chunks = []
    while True:
        chunk = self._stream.read(256)
        if not chunk:
            break
        null_pos = chunk.find(b'\x00')
        if null_pos != -1:
            chunks.append(chunk[:null_pos])
            self._stream.seek(self._stream.tell() - len(chunk) + null_pos + 1)
            break
        chunks.append(chunk)
    return b''.join(chunks).decode('utf-8', errors='replace')
```

### Optimization 6: Aggressive Caching

Added caching for frequently computed values:
- `_type_name_cache` - Type name strings
- `_generic_class_cache` - Parsed generic class structures
- `_generic_inst_cache` - Parsed generic instantiation structures
- `_generic_inst_params_cache` - Generic parameter strings like `<T, U>`
- `_generic_container_params_cache` - Container parameter strings
- `_method_spec_name_cache` - Method specification names
- `_type_def_name_cache` - Type definition names
- `_MODIFIER_CACHE` - Method modifier strings (keyed by flags value)

### Optimization 7: StringIO Buffering

**Problem**: Direct file writes are slow due to I/O overhead.

**Solution**: Buffer output in `StringIO`, write once at end:
```python
buffer = StringIO()
# ... write to buffer ...
with open(output_path, 'w', encoding='utf-8') as f:
    f.write(buffer.getvalue())
```

## Final Performance: ~35 seconds

| Phase | Before | After | Improvement |
|-------|--------|-------|-------------|
| Metadata | ~30s | ~3.7s | 8x faster |
| Binary | ~4s | ~5.2s | Same |
| Search/Init | ~45s | ~5.4s | 8x faster |
| Decompile | ~47s | ~14s | 3.4x faster |
| Struct Gen | ~15s | ~6.4s | 2.3x faster |
| **Total** | **~150s** | **~35s** | **4.3x faster** |

## Lessons Learned

1. **Profile before optimizing** - cProfile revealed unexpected hotspots like enum operations
2. **Avoid Python reflection in hot paths** - `get_type_hints()` is expensive
3. **Batch I/O operations** - Single large read + unpack beats many small reads
4. **Cache aggressively** - Many values are computed multiple times
5. **Use plain ints over IntFlag** - Enum overhead is significant at scale
6. **Buffer writes** - StringIO is much faster than direct file I/O

## Architecture Notes

### Version-Aware Field Parsing

The port maintains C# semantics for version-conditional fields:
```python
@dataclass
class Il2CppTypeDefinition:
    name_index: int = 0
    # Only present in versions <= 24
    custom_attribute_index: int = version_field(max_ver=24, default=0)
    # Only present in versions 19+
    token: int = version_field(min_ver=19, default=0)
```

### Binary Format Detection

Auto-detects format from magic bytes:
- `0x464C457F` - ELF (Android)
- `0x905A4D` - PE (Windows)
- `0xFEEDFACF` - Mach-O 64-bit (iOS/macOS)
- `0xCAFEBABE` - FAT Mach-O (Universal binary)
- `0x304F534E` - NSO (Nintendo Switch)
- `0x6D736100` - WebAssembly
