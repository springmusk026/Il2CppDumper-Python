"""
WebAssembly (WASM) format parser for IL2CPP WebGL builds.

WebAssembly is used for Unity WebGL builds. The IL2CPP binary is compiled
to WebAssembly and runs in web browsers.
"""

from typing import List, Optional
from io import BytesIO

from ..il2cpp.base import Il2Cpp
from ..search.section_helper import SectionHelper, SearchSection
from .wasm_structures import (
    WasmSection, WasmDataSegment,
    WASM_MAGIC, WASM_VERSION, WasmSectionId
)


class WebAssembly(Il2Cpp):
    """
    WebAssembly format parser for IL2CPP WebGL binaries.
    """

    def __init__(self, data: bytes):
        super().__init__(data)
        self.is_32bit = True  # WASM is 32-bit memory model
        self._sections: List[WasmSection] = []
        self._data_segments: List[WasmDataSegment] = []
        self._code_section: Optional[WasmSection] = None
        self._data_section: Optional[WasmSection] = None
        self._load()

    def _load(self) -> None:
        """Load WebAssembly structures."""
        self.position = 0

        # Read magic
        magic = self.read_uint32()
        if magic != WASM_MAGIC:
            raise ValueError(f"Invalid WebAssembly magic: 0x{magic:08X}")

        # Read version
        version = self.read_uint32()
        if version != WASM_VERSION:
            raise ValueError(f"Unsupported WebAssembly version: {version}")

        # Parse sections
        while self.position < len(self._data):
            section = self._read_section()
            if section is None:
                break
            self._sections.append(section)

            if section.id == WasmSectionId.CODE:
                self._code_section = section
            elif section.id == WasmSectionId.DATA:
                self._data_section = section
                self._parse_data_section(section)

    def _read_leb128_unsigned(self) -> int:
        """Read unsigned LEB128 encoded integer."""
        result = 0
        shift = 0
        while True:
            byte = self.read_byte()
            result |= (byte & 0x7F) << shift
            if (byte & 0x80) == 0:
                break
            shift += 7
        return result

    def _read_leb128_signed(self) -> int:
        """Read signed LEB128 encoded integer."""
        result = 0
        shift = 0
        size = 64  # Maximum number of bits
        byte = 0
        while True:
            byte = self.read_byte()
            result |= (byte & 0x7F) << shift
            shift += 7
            if (byte & 0x80) == 0:
                break

        if shift < size and (byte & 0x40) != 0:
            result |= (~0 << shift)

        return result

    def _read_section(self) -> Optional[WasmSection]:
        """Read a WebAssembly section."""
        if self.position >= len(self._data):
            return None

        section = WasmSection()
        section.id = self.read_byte()
        section.size = self._read_leb128_unsigned()
        section.offset = self.position

        # For custom sections, read the name
        if section.id == WasmSectionId.CUSTOM:
            name_len = self._read_leb128_unsigned()
            name_bytes = self.read_bytes(name_len)
            section.name = name_bytes.decode('utf-8', errors='replace')
            # Skip the rest of the custom section
            remaining = section.size - (self.position - section.offset)
            self.position += remaining
        else:
            # Skip section content
            self.position = section.offset + section.size

        return section

    def _parse_data_section(self, section: WasmSection) -> None:
        """Parse the data section to find data segments."""
        saved_pos = self.position
        self.position = section.offset

        num_segments = self._read_leb128_unsigned()

        for _ in range(num_segments):
            segment = WasmDataSegment()

            # Read segment type (flags)
            flags = self._read_leb128_unsigned()

            if flags == 0:
                # Active segment with memory index 0
                segment.memory_index = 0
                # Read init expression (i32.const followed by offset)
                opcode = self.read_byte()
                if opcode == 0x41:  # i32.const
                    segment.offset = self._read_leb128_signed()
                end = self.read_byte()  # Should be 0x0B (end)
            elif flags == 1:
                # Passive segment
                segment.memory_index = 0
                segment.offset = 0
            elif flags == 2:
                # Active segment with explicit memory index
                segment.memory_index = self._read_leb128_unsigned()
                opcode = self.read_byte()
                if opcode == 0x41:
                    segment.offset = self._read_leb128_signed()
                end = self.read_byte()

            # Read data
            segment.size = self._read_leb128_unsigned()
            segment.data_offset = self.position
            self.position += segment.size

            self._data_segments.append(segment)

        self.position = saved_pos

    def map_vatr(self, addr: int) -> int:
        """Map virtual address to raw file offset.

        For WebAssembly, addresses are linear memory offsets.
        We search data segments to find where data is stored.
        """
        for segment in self._data_segments:
            if segment.offset <= addr < segment.offset + segment.size:
                return segment.data_offset + (addr - segment.offset)

        # If not in data segments, address might be direct
        return addr

    def map_rtva(self, addr: int) -> int:
        """Map raw file offset to virtual address."""
        for segment in self._data_segments:
            if segment.data_offset <= addr < segment.data_offset + segment.size:
                return segment.offset + (addr - segment.data_offset)
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
        """Search using symbol table. WebAssembly exports might help."""
        # WASM exports could be searched here
        return False

    def get_section_helper(self, method_count: int, type_definitions_count: int, image_count: int) -> SectionHelper:
        """Get section helper for searching."""
        exec_list = []
        data_list = []

        # Code section is executable
        if self._code_section:
            exec_list.append(SearchSection(
                offset=self._code_section.offset,
                offset_end=self._code_section.offset + self._code_section.size,
                address=self._code_section.offset,
                address_end=self._code_section.offset + self._code_section.size
            ))

        # Data segments are data sections
        for segment in self._data_segments:
            data_list.append(SearchSection(
                offset=segment.data_offset,
                offset_end=segment.data_offset + segment.size,
                address=segment.offset,
                address_end=segment.offset + segment.size
            ))

        helper = SectionHelper(self, method_count, type_definitions_count,
                               self._metadata_usages_count, image_count)
        helper.set_exec_sections(exec_list)
        helper.set_data_sections(data_list)
        helper.set_bss_sections(data_list)

        return helper

    def check_dump(self) -> bool:
        """Check if this is a memory dump."""
        return False

    def get_rva(self, pointer: int) -> int:
        """Get RVA."""
        return pointer
