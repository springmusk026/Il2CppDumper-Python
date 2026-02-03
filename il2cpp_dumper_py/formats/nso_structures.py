"""
NSO format structure definitions for Nintendo Switch binaries.
"""

from dataclasses import dataclass


# NSO Magic
NSO_MAGIC = 0x304F534E  # "NSO0"


@dataclass
class NsoHeader:
    """NSO file header."""
    magic: int = 0
    version: int = 0
    reserved: int = 0
    flags: int = 0
    # .text segment
    text_file_offset: int = 0
    text_memory_offset: int = 0
    text_decompressed_size: int = 0
    # Module name offset
    module_name_offset: int = 0
    # .rodata segment
    rodata_file_offset: int = 0
    rodata_memory_offset: int = 0
    rodata_decompressed_size: int = 0
    # Module name size
    module_name_size: int = 0
    # .data segment
    data_file_offset: int = 0
    data_memory_offset: int = 0
    data_decompressed_size: int = 0
    # BSS size
    bss_size: int = 0


@dataclass
class NsoSegmentHeader:
    """NSO segment header (extended)."""
    file_offset: int = 0
    memory_offset: int = 0
    decompressed_size: int = 0
    compressed_size: int = 0
