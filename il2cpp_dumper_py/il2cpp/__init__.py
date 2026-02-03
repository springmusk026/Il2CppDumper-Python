"""
IL2CPP core module.
"""

from .metadata import Metadata
from .base import Il2Cpp
from .structures import *
from .enums import *

__all__ = [
    'Metadata',
    'Il2Cpp',
    # Re-export structures and enums
    'Il2CppGlobalMetadataHeader',
    'Il2CppImageDefinition',
    'Il2CppTypeDefinition',
    'Il2CppMethodDefinition',
    'Il2CppFieldDefinition',
    'Il2CppTypeEnum',
    'Il2CppMetadataUsage',
]
