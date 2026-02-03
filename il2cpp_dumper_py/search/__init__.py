"""
Search utilities for finding IL2CPP registration structures.

This module provides:
- SectionHelper: Main class for finding CodeRegistration and MetadataRegistration
- SearchSection: Data class representing a searchable memory region
- Pattern matching utilities for binary search
"""

from .section_helper import SectionHelper, SearchSection

__all__ = ['SectionHelper', 'SearchSection']
