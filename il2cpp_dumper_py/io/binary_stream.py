"""
Binary stream reader with version-aware struct parsing.

This module provides a BinaryStream class that can read binary data
with support for version-conditional fields, similar to the C# implementation.
"""

import struct
from io import BytesIO
from typing import (
    TypeVar, Type, List, Optional, Any, Dict, Union, Tuple,
    get_type_hints, get_origin, get_args, Callable
)
from dataclasses import fields, is_dataclass, MISSING
import sys

from .version_aware import (
    should_read_field, get_version_range, VersionRange,
    PRIMITIVE_SIZES, STRUCT_FORMAT
)

T = TypeVar('T')

# Cache for compiled struct reading strategies
# Key: (dataclass_type, version) -> (struct_format, field_names, struct_size, nested_fields)
_STRUCT_CACHE: Dict[Tuple[type, float], Tuple[str, List[str], int, Dict[str, type]]] = {}

# Cache for struct sizes
# Key: (dataclass_type, version) -> size
_SIZE_CACHE: Dict[Tuple[type, float], int] = {}


class BinaryStream:
    """
    Binary stream reader with version-aware deserialization.

    This class provides methods to read binary data from a stream,
    supporting version-conditional field parsing similar to the C# implementation.

    Attributes:
        version: The IL2CPP version being parsed
        is_32bit: Whether the binary is 32-bit (affects pointer size)
        image_base: Base address for memory-mapped files
    """

    def __init__(self, data: Union[bytes, BytesIO]):
        """
        Initialize a BinaryStream.

        Args:
            data: Either raw bytes or a BytesIO stream
        """
        if isinstance(data, bytes):
            self._stream = BytesIO(data)
        else:
            self._stream = data

        self.version: float = 24.0
        self.is_32bit: bool = True
        self.image_base: int = 0

        # Cache for type reading methods
        self._type_readers: Dict[type, Callable] = {}

    def _get_struct_format(self, cls: Type[T]) -> Tuple[str, List[str], int, Dict[str, type]]:
        """
        Get or compute the struct format for a dataclass at the current version.

        Returns:
            Tuple of (struct_format, field_names, struct_size, nested_field_types)
        """
        cache_key = (cls, self.version)
        if cache_key in _STRUCT_CACHE:
            return _STRUCT_CACHE[cache_key]

        format_parts = ['<']  # Little endian
        field_names = []
        nested_fields: Dict[str, type] = {}

        try:
            hints = get_type_hints(cls)
        except Exception:
            hints = {}

        for field_info in fields(cls):
            if not should_read_field(field_info, self.version):
                continue

            field_type = hints.get(field_info.name, field_info.type)

            # Check for explicit binary_size first
            binary_size = None
            unsigned = True
            if hasattr(field_info, 'metadata') and field_info.metadata:
                binary_size = field_info.metadata.get('binary_size')
                unsigned = field_info.metadata.get('unsigned', True)

            if binary_size is not None:
                # Explicit size specified
                if binary_size == 1:
                    format_parts.append('B' if unsigned else 'b')
                elif binary_size == 2:
                    format_parts.append('H' if unsigned else 'h')
                elif binary_size == 4:
                    format_parts.append('I' if unsigned else 'i')
                elif binary_size == 8:
                    format_parts.append('Q' if unsigned else 'q')
                field_names.append(field_info.name)
            elif field_type in (int, 'int'):
                format_parts.append('i')
                field_names.append(field_info.name)
            elif field_type in (bool, 'bool'):
                format_parts.append('?')
                field_names.append(field_info.name)
            elif field_type in (float, 'float'):
                format_parts.append('f')
                field_names.append(field_info.name)
            elif is_dataclass(field_type):
                # Nested dataclass - will be read separately
                nested_fields[field_info.name] = field_type
            elif field_type is bytes:
                # Fixed-size byte array
                length = 0
                if hasattr(field_info, 'metadata') and field_info.metadata:
                    length = field_info.metadata.get('array_length', 0)
                if length > 0:
                    format_parts.append(f'{length}s')
                    field_names.append(field_info.name)
            # Handle Optional types
            elif get_origin(field_type) is Union:
                args = get_args(field_type)
                non_none = [t for t in args if t is not type(None)]
                if len(non_none) == 1 and is_dataclass(non_none[0]):
                    nested_fields[field_info.name] = non_none[0]

        format_str = ''.join(format_parts)
        struct_size = struct.calcsize(format_str) if len(format_parts) > 1 else 0

        result = (format_str, field_names, struct_size, nested_fields)
        _STRUCT_CACHE[cache_key] = result
        return result

    def read_class_fast(self, cls: Type[T], addr: Optional[int] = None) -> T:
        """
        Fast version of read_class using pre-compiled struct format.

        This is optimized for reading many instances of the same dataclass
        by caching the struct format and avoiding reflection per-read.
        """
        if addr is not None:
            self.position = addr

        if not is_dataclass(cls):
            return self._read_primitive(cls)

        format_str, field_names, struct_size, nested_fields = self._get_struct_format(cls)

        # Read all primitive fields at once
        instance = cls()

        if struct_size > 0:
            data = self.read_bytes(struct_size)
            values = struct.unpack(format_str, data)
            for name, value in zip(field_names, values):
                setattr(instance, name, value)

        # Read nested dataclass fields
        for name, nested_type in nested_fields.items():
            setattr(instance, name, self.read_class_fast(nested_type))

        return instance

    def read_class_array_fast(
        self,
        cls: Type[T],
        addr: Optional[int] = None,
        count: Optional[int] = None
    ) -> List[T]:
        """
        Fast version of read_class_array using optimized struct reading.
        """
        if addr is not None:
            self.position = addr

        if count is None or count <= 0:
            return []

        if not is_dataclass(cls):
            return [self._read_primitive(cls) for _ in range(count)]

        format_str, field_names, struct_size, nested_fields = self._get_struct_format(cls)

        # If no nested fields, we can read all at once
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
        else:
            # Fall back to per-element reading for nested types
            return [self.read_class_fast(cls) for _ in range(count)]

    # ========== Position and Length ==========

    @property
    def position(self) -> int:
        """Get current stream position."""
        return self._stream.tell()

    @position.setter
    def position(self, value: int) -> None:
        """Set stream position."""
        self._stream.seek(value)

    @property
    def length(self) -> int:
        """Get stream length."""
        current = self._stream.tell()
        self._stream.seek(0, 2)  # Seek to end
        length = self._stream.tell()
        self._stream.seek(current)  # Restore position
        return length

    @property
    def pointer_size(self) -> int:
        """Get pointer size based on architecture."""
        return 4 if self.is_32bit else 8

    # ========== Primitive Readers ==========

    def read_bytes(self, count: int) -> bytes:
        """Read raw bytes."""
        return self._stream.read(count)

    def read_bool(self) -> bool:
        """Read a boolean (1 byte)."""
        return struct.unpack('<?', self.read_bytes(1))[0]

    def read_byte(self) -> int:
        """Read an unsigned byte."""
        return struct.unpack('<B', self.read_bytes(1))[0]

    def read_sbyte(self) -> int:
        """Read a signed byte."""
        return struct.unpack('<b', self.read_bytes(1))[0]

    def read_int16(self) -> int:
        """Read a signed 16-bit integer."""
        return struct.unpack('<h', self.read_bytes(2))[0]

    def read_uint16(self) -> int:
        """Read an unsigned 16-bit integer."""
        return struct.unpack('<H', self.read_bytes(2))[0]

    def read_int32(self) -> int:
        """Read a signed 32-bit integer."""
        return struct.unpack('<i', self.read_bytes(4))[0]

    def read_uint32(self) -> int:
        """Read an unsigned 32-bit integer."""
        return struct.unpack('<I', self.read_bytes(4))[0]

    def read_int64(self) -> int:
        """Read a signed 64-bit integer."""
        return struct.unpack('<q', self.read_bytes(8))[0]

    def read_uint64(self) -> int:
        """Read an unsigned 64-bit integer."""
        return struct.unpack('<Q', self.read_bytes(8))[0]

    def read_float(self) -> float:
        """Read a 32-bit float."""
        return struct.unpack('<f', self.read_bytes(4))[0]

    def read_double(self) -> float:
        """Read a 64-bit double."""
        return struct.unpack('<d', self.read_bytes(8))[0]

    def read_int_ptr(self) -> int:
        """Read a pointer-sized signed integer."""
        return self.read_int32() if self.is_32bit else self.read_int64()

    def read_uint_ptr(self) -> int:
        """Read a pointer-sized unsigned integer."""
        return self.read_uint32() if self.is_32bit else self.read_uint64()

    # ========== String Readers ==========

    def read_string_to_null(self, addr: Optional[int] = None) -> str:
        """
        Read a null-terminated UTF-8 string.

        Args:
            addr: Optional address to seek to before reading

        Returns:
            The decoded string
        """
        if addr is not None:
            self.position = addr

        # Read in chunks for better performance
        chunks = []
        while True:
            chunk = self._stream.read(256)
            if not chunk:
                break
            null_pos = chunk.find(b'\x00')
            if null_pos != -1:
                chunks.append(chunk[:null_pos])
                # Seek back to position after null
                self._stream.seek(self._stream.tell() - len(chunk) + null_pos + 1)
                break
            chunks.append(chunk)

        return b''.join(chunks).decode('utf-8', errors='replace')

    def read_string(self, length: int) -> str:
        """Read a fixed-length UTF-8 string."""
        return self.read_bytes(length).decode('utf-8', errors='replace')

    # ========== Compressed Integer Readers ==========

    def read_compressed_uint32(self) -> int:
        """
        Read a compressed unsigned 32-bit integer.

        Uses .NET's compressed integer format:
        - 1 byte for values 0-127
        - 2 bytes for values 128-16383
        - 4 bytes for values 16384-536870911
        """
        b = self.read_byte()
        if (b & 0x80) == 0:
            return b
        elif (b & 0x40) == 0:
            return ((b & 0x3F) << 8) | self.read_byte()
        else:
            return (
                ((b & 0x1F) << 24) |
                (self.read_byte() << 16) |
                (self.read_byte() << 8) |
                self.read_byte()
            )

    def read_compressed_int32(self) -> int:
        """Read a compressed signed 32-bit integer."""
        encoded = self.read_compressed_uint32()
        # Decode signed value
        if encoded & 1:
            return -(encoded >> 1) - 1
        else:
            return encoded >> 1

    def read_uleb128(self) -> int:
        """Read an unsigned LEB128 encoded integer."""
        result = 0
        shift = 0
        while True:
            b = self.read_byte()
            result |= (b & 0x7F) << shift
            if (b & 0x80) == 0:
                break
            shift += 7
        return result

    # ========== Write Methods ==========

    def write_bytes(self, data: bytes) -> None:
        """Write raw bytes."""
        self._stream.write(data)

    def write_int32(self, value: int) -> None:
        """Write a signed 32-bit integer."""
        self.write_bytes(struct.pack('<i', value))

    def write_uint32(self, value: int) -> None:
        """Write an unsigned 32-bit integer."""
        self.write_bytes(struct.pack('<I', value))

    def write_int64(self, value: int) -> None:
        """Write a signed 64-bit integer."""
        self.write_bytes(struct.pack('<q', value))

    def write_uint64(self, value: int) -> None:
        """Write an unsigned 64-bit integer."""
        self.write_bytes(struct.pack('<Q', value))

    # ========== Class/Struct Reading ==========

    def read_class(self, cls: Type[T], addr: Optional[int] = None) -> T:
        """
        Read a dataclass instance from the stream.

        This method uses reflection to read fields based on their types
        and respects version constraints specified via version_field().

        Args:
            cls: The dataclass type to read
            addr: Optional address to seek to before reading

        Returns:
            An instance of the dataclass with fields populated from the stream
        """
        if addr is not None:
            self.position = addr

        if not is_dataclass(cls):
            # Handle primitive types
            return self._read_primitive(cls)

        # Create instance with defaults
        instance = cls()

        # Get type hints for the class
        try:
            hints = get_type_hints(cls)
        except Exception:
            hints = {}

        for field_info in fields(cls):
            # Check version constraints
            if not should_read_field(field_info, self.version):
                continue

            # Get field type
            field_type = hints.get(field_info.name, field_info.type)

            # Read the field value
            value = self._read_field_value(field_type, field_info)
            setattr(instance, field_info.name, value)

        return instance

    def _read_field_value(self, field_type: Any, field_info: Any = None) -> Any:
        """Read a field value based on its type."""
        # Handle string type annotations
        if isinstance(field_type, str):
            field_type = self._resolve_string_type(field_type)

        # Get the origin type for generics (e.g., List, Optional)
        origin = get_origin(field_type)
        args = get_args(field_type)

        # Handle Optional types
        if origin is Union:
            # Optional[X] is Union[X, None]
            non_none_types = [t for t in args if t is not type(None)]
            if len(non_none_types) == 1:
                field_type = non_none_types[0]
                origin = get_origin(field_type)
                args = get_args(field_type)

        # Handle List types
        if origin is list:
            # Need array length from metadata
            if field_info and hasattr(field_info, 'metadata'):
                array_len = field_info.metadata.get('array_length', 0)
                if array_len > 0:
                    element_type = args[0] if args else int
                    return [self._read_field_value(element_type) for _ in range(array_len)]
            return []

        # Handle bytes type (fixed-size byte array)
        if field_type is bytes:
            if field_info and hasattr(field_info, 'metadata'):
                length = field_info.metadata.get('array_length', 0)
                return self.read_bytes(length)
            return b''

        # Handle primitive types
        # First check for explicit binary_size metadata
        if field_info and hasattr(field_info, 'metadata'):
            binary_size = field_info.metadata.get('binary_size')
            unsigned = field_info.metadata.get('unsigned', False)
            if binary_size is not None:
                if binary_size == 1:
                    return self.read_byte() if unsigned else self.read_sbyte()
                elif binary_size == 2:
                    return self.read_uint16() if unsigned else self.read_int16()
                elif binary_size == 4:
                    return self.read_uint32() if unsigned else self.read_int32()
                elif binary_size == 8:
                    return self.read_uint64() if unsigned else self.read_int64()

        if field_type in (int, 'int'):
            return self.read_int32()
        elif field_type in (bool, 'bool'):
            return self.read_bool()
        elif field_type in (float, 'float'):
            return self.read_float()

        # Handle specific integer types via type name
        type_name = getattr(field_type, '__name__', str(field_type))

        if type_name in ('uint32', 'uint'):
            return self.read_uint32()
        elif type_name in ('int32', 'int'):
            return self.read_int32()
        elif type_name in ('uint64', 'ulong'):
            return self.read_uint64()
        elif type_name in ('int64', 'long'):
            return self.read_int64()
        elif type_name in ('uint16', 'ushort'):
            return self.read_uint16()
        elif type_name in ('int16', 'short'):
            return self.read_int16()
        elif type_name in ('uint8', 'byte'):
            return self.read_byte()
        elif type_name in ('int8', 'sbyte'):
            return self.read_sbyte()

        # Handle dataclass types (nested structs)
        if is_dataclass(field_type):
            return self.read_class(field_type)

        # Default to int32
        return self.read_int32()

    def _read_primitive(self, type_: type) -> Any:
        """Read a primitive type."""
        if type_ is int:
            return self.read_int32()
        elif type_ is bool:
            return self.read_bool()
        elif type_ is float:
            return self.read_float()
        elif type_ is bytes:
            raise ValueError("bytes type requires length")
        else:
            return self.read_int32()

    def _resolve_string_type(self, type_str: str) -> type:
        """Resolve a string type annotation to an actual type."""
        type_map = {
            'int': int,
            'bool': bool,
            'float': float,
            'bytes': bytes,
            'str': str,
        }
        return type_map.get(type_str, int)

    def read_class_at(self, cls: Type[T], addr: int) -> T:
        """Read a class at a specific address."""
        return self.read_class(cls, addr)

    def read_class_array(
        self,
        cls: Type[T],
        addr: Optional[int] = None,
        count: Optional[int] = None
    ) -> List[T]:
        """
        Read an array of dataclass instances.

        Args:
            cls: The dataclass type
            addr: Optional address to seek to
            count: Number of elements to read

        Returns:
            A list of dataclass instances
        """
        if addr is not None:
            self.position = addr

        if count is None or count <= 0:
            return []

        return [self.read_class(cls) for _ in range(count)]

    def read_array(
        self,
        read_func: Callable[[], T],
        count: int,
        addr: Optional[int] = None
    ) -> List[T]:
        """
        Read an array using a custom read function.

        Args:
            read_func: Function to read each element
            count: Number of elements
            addr: Optional address to seek to

        Returns:
            List of read elements
        """
        if addr is not None:
            self.position = addr

        return [read_func() for _ in range(count)]

    def read_uint32_array(self, addr: Optional[int], count: int) -> List[int]:
        """Read an array of uint32 values."""
        if count <= 0:
            return []
        if addr is not None:
            self.position = addr
        data = self.read_bytes(count * 4)
        return list(struct.unpack(f'<{count}I', data))

    def read_uint64_array(self, addr: Optional[int], count: int) -> List[int]:
        """Read an array of uint64 values."""
        if count <= 0:
            return []
        if addr is not None:
            self.position = addr
        data = self.read_bytes(count * 8)
        return list(struct.unpack(f'<{count}Q', data))

    def read_int32_array(self, addr: Optional[int], count: int) -> List[int]:
        """Read an array of int32 values."""
        if count <= 0:
            return []
        if addr is not None:
            self.position = addr
        data = self.read_bytes(count * 4)
        return list(struct.unpack(f'<{count}i', data))

    def read_ptr_array(self, addr: Optional[int], count: int) -> List[int]:
        """Read an array of pointer-sized values."""
        if count <= 0:
            return []
        if addr is not None:
            self.position = addr
        if self.is_32bit:
            data = self.read_bytes(count * 4)
            return list(struct.unpack(f'<{count}I', data))
        else:
            data = self.read_bytes(count * 8)
            return list(struct.unpack(f'<{count}Q', data))

    # ========== Utility Methods ==========

    def size_of(self, cls: Type) -> int:
        """
        Calculate the size of a dataclass for the current version.

        This accounts for version-conditional fields.

        Args:
            cls: The dataclass type

        Returns:
            Size in bytes
        """
        if not is_dataclass(cls):
            return self._primitive_size(cls)

        # Check cache first
        cache_key = (cls, self.version)
        if cache_key in _SIZE_CACHE:
            return _SIZE_CACHE[cache_key]

        size = 0
        try:
            hints = get_type_hints(cls)
        except Exception:
            hints = {}

        for field_info in fields(cls):
            if not should_read_field(field_info, self.version):
                continue

            field_type = hints.get(field_info.name, field_info.type)
            size += self._field_size(field_type, field_info)

        _SIZE_CACHE[cache_key] = size
        return size

    def _field_size(self, field_type: Any, field_info: Any = None) -> int:
        """Calculate the size of a field."""
        # Check for explicit binary_size metadata first
        if field_info and hasattr(field_info, 'metadata'):
            binary_size = field_info.metadata.get('binary_size')
            if binary_size is not None:
                return binary_size

        # Handle string annotations
        if isinstance(field_type, str):
            field_type = self._resolve_string_type(field_type)

        origin = get_origin(field_type)
        args = get_args(field_type)

        # Handle Optional
        if origin is Union:
            non_none = [t for t in args if t is not type(None)]
            if len(non_none) == 1:
                return self._field_size(non_none[0], field_info)

        # Handle List
        if origin is list:
            if field_info and hasattr(field_info, 'metadata'):
                length = field_info.metadata.get('array_length', 0)
                elem_type = args[0] if args else int
                return length * self._field_size(elem_type)
            return 0

        # Handle bytes
        if field_type is bytes:
            if field_info and hasattr(field_info, 'metadata'):
                return field_info.metadata.get('array_length', 0)
            return 0

        # Handle nested dataclass
        if is_dataclass(field_type):
            return self.size_of(field_type)

        return self._primitive_size(field_type)

    def _primitive_size(self, type_: type) -> int:
        """Get size of a primitive type."""
        type_name = getattr(type_, '__name__', str(type_))

        size_map = {
            'int': 4, 'int32': 4,
            'uint': 4, 'uint32': 4,
            'long': 8, 'int64': 8,
            'ulong': 8, 'uint64': 8,
            'short': 2, 'int16': 2,
            'ushort': 2, 'uint16': 2,
            'byte': 1, 'uint8': 1,
            'sbyte': 1, 'int8': 1,
            'bool': 1,
            'float': 4, 'float32': 4,
            'double': 8, 'float64': 8,
        }

        return size_map.get(type_name, 4)

    def get_data(self) -> bytes:
        """Get the underlying data."""
        current = self.position
        self.position = 0
        data = self._stream.read()
        self.position = current
        return data

    def dispose(self) -> None:
        """Close the stream."""
        self._stream.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.dispose()
