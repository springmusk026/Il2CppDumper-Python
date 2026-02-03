"""
IL2CPP Dumper - Python Port
A tool for extracting metadata from Unity IL2CPP compiled games.

Ported from the original C# implementation by Perfare.
"""

__version__ = "0.1.0"
__author__ = "Python Port"

from .config import Config
from .il2cpp.metadata import Metadata
from .il2cpp.base import Il2Cpp

__all__ = ['Config', 'Metadata', 'Il2Cpp', '__version__']
