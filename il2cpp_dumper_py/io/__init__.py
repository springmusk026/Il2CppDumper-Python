"""
IO module for binary stream handling.
"""

from .binary_stream import BinaryStream
from .version_aware import version_field, VersionRange

__all__ = ['BinaryStream', 'version_field', 'VersionRange']
