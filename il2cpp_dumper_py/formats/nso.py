"""
NSO format parser for Nintendo Switch IL2CPP binaries.

NSO is the executable format used on Nintendo Switch. The binaries
are typically compressed with LZ4.
"""

from typing import List, Optional
from io import BytesIO

from ..il2cpp.base import Il2Cpp
from ..search.section_helper import SectionHelper, SearchSection
from .nso_structures import NsoHeader, NsoSegmentHeader, NSO_MAGIC


class NSO(Il2Cpp):
    """
    Nintendo Switch NSO format parser.

    Note: This parser assumes decompressed data or will attempt LZ4 decompression.
    """

    def __init__(self, data: bytes):
        # First check if we need to decompress
        self._original_data = data
        self._header: Optional[NsoHeader] = None

        # Parse header to check compression flags
        self._parse_header_only(data)

        # Decompress if needed
        decompressed_data = self._decompress_if_needed(data)

        super().__init__(decompressed_data)
        self.is_32bit = False  # Switch is 64-bit
        self._text_start = 0
        self._text_end = 0
        self._rodata_start = 0
        self._rodata_end = 0
        self._data_start = 0
        self._data_end = 0
        self._bss_end = 0
        self._load()

    def _parse_header_only(self, data: bytes) -> None:
        """Parse just the header to check compression flags."""
        stream = BytesIO(data)

        self._header = NsoHeader()
        self._header.magic = int.from_bytes(stream.read(4), 'little')

        if self._header.magic != NSO_MAGIC:
            raise ValueError("Invalid NSO magic")

        self._header.version = int.from_bytes(stream.read(4), 'little')
        self._header.reserved = int.from_bytes(stream.read(4), 'little')
        self._header.flags = int.from_bytes(stream.read(4), 'little')

        # Text segment info
        self._header.text_file_offset = int.from_bytes(stream.read(4), 'little')
        self._header.text_memory_offset = int.from_bytes(stream.read(4), 'little')
        self._header.text_decompressed_size = int.from_bytes(stream.read(4), 'little')

        self._header.module_name_offset = int.from_bytes(stream.read(4), 'little')

        # Rodata segment info
        self._header.rodata_file_offset = int.from_bytes(stream.read(4), 'little')
        self._header.rodata_memory_offset = int.from_bytes(stream.read(4), 'little')
        self._header.rodata_decompressed_size = int.from_bytes(stream.read(4), 'little')

        self._header.module_name_size = int.from_bytes(stream.read(4), 'little')

        # Data segment info
        self._header.data_file_offset = int.from_bytes(stream.read(4), 'little')
        self._header.data_memory_offset = int.from_bytes(stream.read(4), 'little')
        self._header.data_decompressed_size = int.from_bytes(stream.read(4), 'little')

        self._header.bss_size = int.from_bytes(stream.read(4), 'little')

    def _decompress_if_needed(self, data: bytes) -> bytes:
        """Decompress segments if compression flags are set."""
        if not self._header:
            return data

        flags = self._header.flags

        # Flags: bit 0 = .text compressed, bit 1 = .rodata compressed, bit 2 = .data compressed
        text_compressed = (flags & 1) != 0
        rodata_compressed = (flags & 2) != 0
        data_compressed = (flags & 4) != 0

        if not (text_compressed or rodata_compressed or data_compressed):
            return data

        # Try to import LZ4
        try:
            import lz4.block
        except ImportError:
            print("WARNING: LZ4 not available. Install with: pip install lz4")
            print("Attempting to continue with raw data (may fail)...")
            return data

        # Build decompressed image
        # We need to read compressed sizes from the extended header
        stream = BytesIO(data)
        stream.seek(0x60)  # Skip to segment sizes section

        text_compressed_size = int.from_bytes(stream.read(4), 'little')
        rodata_compressed_size = int.from_bytes(stream.read(4), 'little')
        data_compressed_size = int.from_bytes(stream.read(4), 'little')

        # Calculate total decompressed size
        total_size = (self._header.data_memory_offset +
                      self._header.data_decompressed_size +
                      self._header.bss_size)

        result = bytearray(total_size)

        # Decompress text segment
        if text_compressed:
            stream.seek(self._header.text_file_offset)
            compressed = stream.read(text_compressed_size)
            decompressed = lz4.block.decompress(
                compressed,
                uncompressed_size=self._header.text_decompressed_size
            )
            result[self._header.text_memory_offset:
                   self._header.text_memory_offset + len(decompressed)] = decompressed
        else:
            stream.seek(self._header.text_file_offset)
            raw = stream.read(self._header.text_decompressed_size)
            result[self._header.text_memory_offset:
                   self._header.text_memory_offset + len(raw)] = raw

        # Decompress rodata segment
        if rodata_compressed:
            stream.seek(self._header.rodata_file_offset)
            compressed = stream.read(rodata_compressed_size)
            decompressed = lz4.block.decompress(
                compressed,
                uncompressed_size=self._header.rodata_decompressed_size
            )
            result[self._header.rodata_memory_offset:
                   self._header.rodata_memory_offset + len(decompressed)] = decompressed
        else:
            stream.seek(self._header.rodata_file_offset)
            raw = stream.read(self._header.rodata_decompressed_size)
            result[self._header.rodata_memory_offset:
                   self._header.rodata_memory_offset + len(raw)] = raw

        # Decompress data segment
        if data_compressed:
            stream.seek(self._header.data_file_offset)
            compressed = stream.read(data_compressed_size)
            decompressed = lz4.block.decompress(
                compressed,
                uncompressed_size=self._header.data_decompressed_size
            )
            result[self._header.data_memory_offset:
                   self._header.data_memory_offset + len(decompressed)] = decompressed
        else:
            stream.seek(self._header.data_file_offset)
            raw = stream.read(self._header.data_decompressed_size)
            result[self._header.data_memory_offset:
                   self._header.data_memory_offset + len(raw)] = raw

        return bytes(result)

    def _load(self) -> None:
        """Load NSO structures."""
        if not self._header:
            return

        # Calculate segment boundaries (in decompressed image)
        self._text_start = self._header.text_memory_offset
        self._text_end = self._text_start + self._header.text_decompressed_size

        self._rodata_start = self._header.rodata_memory_offset
        self._rodata_end = self._rodata_start + self._header.rodata_decompressed_size

        self._data_start = self._header.data_memory_offset
        self._data_end = self._data_start + self._header.data_decompressed_size

        self._bss_end = self._data_end + self._header.bss_size

    def map_vatr(self, addr: int) -> int:
        """Map virtual address to raw file offset.

        For decompressed NSO, virtual address == file offset.
        """
        return addr

    def map_rtva(self, addr: int) -> int:
        """Map raw file offset to virtual address.

        For decompressed NSO, file offset == virtual address.
        """
        return addr

    def search(self) -> bool:
        """Search for registration using pattern matching."""
        return False

    def plus_search(self, method_count: int, type_definitions_count: int, image_count: int) -> bool:
        """Search using modern algorithm."""
        section_helper = self.get_section_helper(method_count, type_definitions_count, image_count)
        code_registration = section_helper.find_code_registration()
        metadata_registration = section_helper.find_metadata_registration()
        return self.auto_plus_init(code_registration, metadata_registration)

    def symbol_search(self) -> bool:
        """Search using symbol table. NSO doesn't have exposed symbols."""
        return False

    def get_section_helper(self, method_count: int, type_definitions_count: int, image_count: int) -> SectionHelper:
        """Get section helper for searching."""
        exec_list = []
        data_list = []
        bss_list = []

        # Text section (executable)
        exec_list.append(SearchSection(
            offset=self._text_start,
            offset_end=self._text_end,
            address=self._text_start,
            address_end=self._text_end
        ))

        # Rodata section (data)
        data_list.append(SearchSection(
            offset=self._rodata_start,
            offset_end=self._rodata_end,
            address=self._rodata_start,
            address_end=self._rodata_end
        ))

        # Data section (data)
        data_list.append(SearchSection(
            offset=self._data_start,
            offset_end=self._data_end,
            address=self._data_start,
            address_end=self._data_end
        ))

        # BSS section
        if self._header and self._header.bss_size > 0:
            bss_list.append(SearchSection(
                offset=self._data_end,
                offset_end=self._bss_end,
                address=self._data_end,
                address_end=self._bss_end
            ))

        helper = SectionHelper(self, method_count, type_definitions_count,
                               self._metadata_usages_count, image_count)
        helper.set_exec_sections(exec_list)
        helper.set_data_sections(data_list)
        helper.set_bss_sections(bss_list if bss_list else data_list)

        return helper

    def check_dump(self) -> bool:
        """Check if this is a memory dump."""
        return False

    def get_rva(self, pointer: int) -> int:
        """Get RVA."""
        return pointer
