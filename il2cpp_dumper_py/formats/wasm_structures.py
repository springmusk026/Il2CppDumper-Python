"""
WebAssembly format structure definitions.
"""

from dataclasses import dataclass
from enum import IntEnum


# WebAssembly Magic and version
WASM_MAGIC = 0x6D736100  # "\0asm"
WASM_VERSION = 1


class WasmSectionId(IntEnum):
    """WebAssembly section IDs."""
    CUSTOM = 0
    TYPE = 1
    IMPORT = 2
    FUNCTION = 3
    TABLE = 4
    MEMORY = 5
    GLOBAL = 6
    EXPORT = 7
    START = 8
    ELEMENT = 9
    CODE = 10
    DATA = 11
    DATA_COUNT = 12


@dataclass
class WasmSection:
    """WebAssembly section."""
    id: int = 0
    size: int = 0
    offset: int = 0  # File offset where section content starts
    name: str = ""   # For custom sections


@dataclass
class WasmDataSegment:
    """WebAssembly data segment."""
    memory_index: int = 0
    offset: int = 0  # Memory offset (evaluated from init expr)
    size: int = 0
    data_offset: int = 0  # File offset where data starts
