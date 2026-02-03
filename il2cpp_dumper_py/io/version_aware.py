"""
Version-aware field decorators and utilities.

This module provides decorators and utilities for defining dataclass fields
that are conditionally present based on IL2CPP version.
"""

from dataclasses import field
from typing import Any, Optional, TypeVar, Type, Dict, Tuple
from enum import Enum


class VersionRange:
    """Represents a version range for conditional fields."""

    def __init__(self, min_ver: float = 0, max_ver: float = 99):
        self.min = min_ver
        self.max = max_ver

    def contains(self, version: float) -> bool:
        """Check if version is within this range."""
        return self.min <= version <= self.max

    def __repr__(self) -> str:
        return f"VersionRange({self.min}, {self.max})"


def version_field(
    min_ver: float = 0,
    max_ver: float = 99,
    default: Any = None,
    default_factory: Any = None,
    binary_size: int = None,
    unsigned: bool = True
):
    """
    Create a dataclass field with version metadata.

    This is used to mark fields that are only present in certain IL2CPP versions.

    Args:
        min_ver: Minimum IL2CPP version (inclusive)
        max_ver: Maximum IL2CPP version (inclusive)
        default: Default value for the field
        default_factory: Factory function for default value
        binary_size: Explicit size in bytes (1, 2, 4, or 8)
        unsigned: Whether to read as unsigned (default True)

    Returns:
        A dataclass field with version metadata

    Example:
        @dataclass
        class Il2CppTypeDefinition:
            name_index: int = 0
            # Only present in versions 16-24
            custom_attribute_index: int = version_field(max_ver=24, default=0)
            # Only present in versions 19+
            token: int = version_field(min_ver=19, default=0)
    """
    metadata = {
        'version': VersionRange(min_ver, max_ver),
        'versioned': True
    }

    if binary_size is not None:
        metadata['binary_size'] = binary_size
        metadata['unsigned'] = unsigned

    if default_factory is not None:
        return field(default_factory=default_factory, metadata=metadata)
    else:
        return field(default=default if default is not None else 0, metadata=metadata)


def get_version_range(field_info) -> Optional[VersionRange]:
    """Get the version range from a field's metadata."""
    if hasattr(field_info, 'metadata') and field_info.metadata:
        return field_info.metadata.get('version')
    return None


def is_versioned_field(field_info) -> bool:
    """Check if a field has version constraints."""
    if hasattr(field_info, 'metadata') and field_info.metadata:
        return field_info.metadata.get('versioned', False)
    return False


def should_read_field(field_info, version: float) -> bool:
    """
    Determine if a field should be read for the given version.

    Args:
        field_info: The dataclass field info
        version: The IL2CPP version

    Returns:
        True if the field should be read, False otherwise
    """
    version_range = get_version_range(field_info)
    if version_range is None:
        return True  # No version constraint, always read
    return version_range.contains(version)


# Type size mappings for primitive types
PRIMITIVE_SIZES: Dict[str, int] = {
    'int8': 1,
    'uint8': 1,
    'int16': 2,
    'uint16': 2,
    'int32': 4,
    'uint32': 4,
    'int64': 8,
    'uint64': 8,
    'float32': 4,
    'float64': 8,
    'bool': 1,
    'byte': 1,
    'sbyte': 1,
    'short': 2,
    'ushort': 2,
    'int': 4,
    'uint': 4,
    'long': 8,
    'ulong': 8,
    'float': 4,
    'double': 8,
}


# C# to Python struct format mappings
STRUCT_FORMAT: Dict[str, str] = {
    'int8': 'b',
    'uint8': 'B',
    'int16': 'h',
    'uint16': 'H',
    'int32': 'i',
    'uint32': 'I',
    'int64': 'q',
    'uint64': 'Q',
    'float32': 'f',
    'float64': 'd',
    'bool': '?',
    'byte': 'B',
    'sbyte': 'b',
    'short': 'h',
    'ushort': 'H',
    'int': 'i',
    'uint': 'I',
    'long': 'q',
    'ulong': 'Q',
    'float': 'f',
    'double': 'd',
}
