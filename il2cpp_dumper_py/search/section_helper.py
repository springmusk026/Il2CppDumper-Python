"""
Section helper for finding CodeRegistration and MetadataRegistration.

This module implements the pattern-based search algorithms used to locate
the IL2CPP registration structures in compiled binaries.
"""

from dataclasses import dataclass
from typing import List, Optional, Iterator, TYPE_CHECKING

if TYPE_CHECKING:
    from ..il2cpp.base import Il2Cpp

from ..utils.pattern_search import search_pattern


@dataclass
class SearchSection:
    """Represents a searchable section of the binary."""
    offset: int = 0
    offset_end: int = 0
    address: int = 0
    address_end: int = 0


class SectionHelper:
    """
    Helper class for finding IL2CPP registration structures.

    This class implements various search algorithms to locate the
    CodeRegistration and MetadataRegistration structures in IL2CPP binaries.

    The main search strategies are:
    1. PlusSearch (v24.2+): Search for "mscorlib.dll" string and trace references
    2. Old search: Pattern-based search for known structure patterns
    3. Symbol search: Look for exported symbols (g_CodeRegistration, etc.)
    """

    # "mscorlib.dll\x00" in bytes
    FEATURE_BYTES = b"mscorlib.dll\x00"

    def __init__(
        self,
        il2cpp: 'Il2Cpp',
        method_count: int,
        type_definitions_count: int,
        metadata_usages_count: int,
        image_count: int
    ):
        """
        Initialize the section helper.

        Args:
            il2cpp: The IL2CPP binary parser
            method_count: Number of methods in metadata
            type_definitions_count: Number of type definitions
            metadata_usages_count: Number of metadata usages
            image_count: Number of images/assemblies
        """
        self._il2cpp = il2cpp
        self._method_count = method_count
        self._type_definitions_count = type_definitions_count
        self._metadata_usages_count = metadata_usages_count
        self._image_count = image_count

        self._exec_sections: List[SearchSection] = []
        self._data_sections: List[SearchSection] = []
        self._bss_sections: List[SearchSection] = []

        self._pointer_in_exec = False

    @property
    def exec_sections(self) -> List[SearchSection]:
        return self._exec_sections

    @property
    def data_sections(self) -> List[SearchSection]:
        return self._data_sections

    @property
    def bss_sections(self) -> List[SearchSection]:
        return self._bss_sections

    def set_exec_sections(self, sections: List[SearchSection]) -> None:
        """Set executable sections."""
        self._exec_sections = sections

    def set_data_sections(self, sections: List[SearchSection]) -> None:
        """Set data sections."""
        self._data_sections = sections

    def set_bss_sections(self, sections: List[SearchSection]) -> None:
        """Set BSS sections."""
        self._bss_sections = sections

    def find_code_registration(self) -> int:
        """
        Find the CodeRegistration structure address.

        Returns:
            Address of CodeRegistration, or 0 if not found
        """
        if self._il2cpp.version >= 24.2:
            # Try exec first for ELF, data first for others
            from ..formats.elf import ElfBase
            if isinstance(self._il2cpp, ElfBase):
                result = self._find_code_registration_exec()
                if result == 0:
                    result = self._find_code_registration_data()
                else:
                    self._pointer_in_exec = True
            else:
                result = self._find_code_registration_data()
                if result == 0:
                    result = self._find_code_registration_exec()
                    self._pointer_in_exec = True
            return result

        return self._find_code_registration_old()

    def find_metadata_registration(self) -> int:
        """
        Find the MetadataRegistration structure address.

        Returns:
            Address of MetadataRegistration, or 0 if not found
        """
        if self._il2cpp.version < 19:
            return 0

        if self._il2cpp.version >= 27:
            return self._find_metadata_registration_v21()

        return self._find_metadata_registration_old()

    def _find_code_registration_old(self) -> int:
        """Find CodeRegistration using old algorithm (pre-24.2)."""
        for section in self._data_sections:
            self._il2cpp.position = section.offset
            while self._il2cpp.position < section.offset_end:
                addr = self._il2cpp.position
                if self._il2cpp.read_int_ptr() == self._method_count:
                    try:
                        pointer = self._il2cpp.map_vatr(self._il2cpp.read_uint_ptr())
                        if self._check_pointer_range_data_ra(pointer):
                            pointers = self._il2cpp.read_ptr_array(pointer, self._method_count)
                            if self._check_pointer_range_exec_va(pointers):
                                return addr - section.offset + section.address
                    except:
                        pass
                self._il2cpp.position = addr + self._il2cpp.pointer_size

        return 0

    def _find_metadata_registration_old(self) -> int:
        """Find MetadataRegistration using old algorithm."""
        for section in self._data_sections:
            self._il2cpp.position = section.offset
            end = min(section.offset_end, self._il2cpp.length) - self._il2cpp.pointer_size

            while self._il2cpp.position < end:
                addr = self._il2cpp.position
                if self._il2cpp.read_int_ptr() == self._type_definitions_count:
                    try:
                        self._il2cpp.position += self._il2cpp.pointer_size * 2
                        pointer = self._il2cpp.map_vatr(self._il2cpp.read_uint_ptr())
                        if self._check_pointer_range_data_ra(pointer):
                            pointers = self._il2cpp.read_ptr_array(
                                pointer, self._metadata_usages_count
                            )
                            if self._check_pointer_range_bss_va(pointers):
                                return (
                                    addr -
                                    self._il2cpp.pointer_size * 12 -
                                    section.offset +
                                    section.address
                                )
                    except:
                        pass
                self._il2cpp.position = addr + self._il2cpp.pointer_size

        return 0

    def _find_metadata_registration_v21(self) -> int:
        """Find MetadataRegistration for v21+ (looks for two type counts with a pointer between)."""
        import struct

        # Get raw data for fast search
        raw_data = self._il2cpp._stream.getvalue()
        ptr_size = self._il2cpp.pointer_size
        type_count = self._type_definitions_count

        # Pack the type count we're looking for
        if ptr_size == 8:
            count_bytes = struct.pack('<Q', type_count)
        else:
            count_bytes = struct.pack('<I', type_count)

        # Pattern: [type_count][pointer][type_count]
        # We search for first occurrence of count, then check at offset +2*ptr_size for second count
        for section in self._data_sections:
            section_data = raw_data[section.offset:section.offset_end]
            start = 0

            while True:
                idx = section_data.find(count_bytes, start)
                if idx == -1:
                    break

                # Check alignment
                if idx % ptr_size == 0:
                    # Check if value at idx + 2*ptr_size is also type_count
                    second_idx = idx + 2 * ptr_size
                    if second_idx + ptr_size <= len(section_data):
                        if ptr_size == 8:
                            second_val = struct.unpack_from('<Q', section_data, second_idx)[0]
                        else:
                            second_val = struct.unpack_from('<I', section_data, second_idx)[0]

                        if second_val == type_count:
                            try:
                                # Found the pattern! Now verify the types pointer
                                # The next value after second count is the typeDefinitionsSizes pointer
                                ptr_offset = section.offset + idx + 3 * ptr_size
                                if ptr_size == 8:
                                    pointer_va = struct.unpack_from('<Q', raw_data, ptr_offset)[0]
                                else:
                                    pointer_va = struct.unpack_from('<I', raw_data, ptr_offset)[0]

                                # Map pointer VA to file offset
                                pointer_offset = None
                                for sec in self._data_sections:
                                    if sec.address <= pointer_va < sec.address_end:
                                        pointer_offset = pointer_va - sec.address + sec.offset
                                        break

                                if pointer_offset is not None:
                                    # Read first few pointers to verify
                                    sample_size = min(10, type_count)
                                    valid = True
                                    for i in range(sample_size):
                                        sample_offset = pointer_offset + i * ptr_size
                                        if sample_offset + ptr_size > len(raw_data):
                                            valid = False
                                            break
                                        if ptr_size == 8:
                                            ptr_val = struct.unpack_from('<Q', raw_data, sample_offset)[0]
                                        else:
                                            ptr_val = struct.unpack_from('<I', raw_data, sample_offset)[0]

                                        # Check if pointer is in valid range
                                        in_range = False
                                        if self._pointer_in_exec:
                                            for sec in self._exec_sections:
                                                if sec.address <= ptr_val <= sec.address_end:
                                                    in_range = True
                                                    break
                                        else:
                                            for sec in self._data_sections:
                                                if sec.address <= ptr_val <= sec.address_end:
                                                    in_range = True
                                                    break

                                        if not in_range:
                                            valid = False
                                            break

                                    if valid:
                                        # Calculate MetadataRegistration address
                                        # idx points to fieldOffsetsCount (field 10)
                                        # MetadataRegistration is at field 0
                                        # Offset from field 10 to field 0 = -10 * ptr_size
                                        addr = section.offset + idx
                                        result = addr - ptr_size * 10 - section.offset + section.address
                                        return result
                            except Exception:
                                pass

                start = idx + 1

        return 0

    def _find_code_registration_data(self) -> int:
        """Find CodeRegistration in data sections."""
        return self._find_code_registration_2019(self._data_sections)

    def _find_code_registration_exec(self) -> int:
        """Find CodeRegistration in exec sections."""
        return self._find_code_registration_2019(self._exec_sections)

    def _find_code_registration_2019(self, sections: List[SearchSection]) -> int:
        """
        Find CodeRegistration using 2019+ algorithm.

        This searches for "mscorlib.dll" string and traces pointer references
        back to find the CodeRegistration structure.
        """
        import struct

        # Get raw data for fast search
        raw_data = self._il2cpp._stream.getvalue()
        ptr_size = self._il2cpp.pointer_size

        # Helper to convert file offset to VA
        def offset_to_va(offset):
            for section in self._data_sections:
                if section.offset <= offset < section.offset_end:
                    return offset - section.offset + section.address
            return None

        # Helper to find all pointer refs to an address
        def find_refs_fast(addr):
            if ptr_size == 8:
                addr_bytes = struct.pack('<Q', addr)
            else:
                addr_bytes = struct.pack('<I', addr)

            refs = []
            start = 0
            while True:
                idx = raw_data.find(addr_bytes, start)
                if idx == -1:
                    break
                if idx % ptr_size == 0:
                    va = offset_to_va(idx)
                    if va is not None:
                        refs.append((idx, va))
                start = idx + 1
            return refs

        for section in sections:
            self._il2cpp.position = section.offset
            buff = self._il2cpp.read_bytes(section.offset_end - section.offset)

            # Search for "mscorlib.dll"
            for index in self._search_bytes(buff, self.FEATURE_BYTES):
                dll_va = index + section.address

                # Find references to this string
                refs1 = find_refs_fast(dll_va)

                for _, ref_va in refs1:
                    # Find references to the reference (this is the array entry)
                    refs2 = find_refs_fast(ref_va)

                    for ref_offset2, ref_va2 in refs2:
                        # Version-specific logic
                        if self._il2cpp.version >= 27:
                            # Optimization: Calculate the base address of the codeGenModules array
                            # ref_va2 is codeGenModules[i], so codeGenModules = ref_va2 - i * ptr_size
                            # We need to find which i gives us a codeGenModules pointer that exists
                            # in the binary with image_count just before it

                            # Instead of trying all i values, calculate candidate codeGenModules addresses
                            # and search for them with the image_count pattern

                            # Search for pattern: [image_count][codeGenModules_ptr]
                            # where codeGenModules_ptr points somewhere in the range
                            # (ref_va2 - (image_count-1)*ptr_size) to ref_va2

                            min_target = ref_va2 - (self._image_count - 1) * ptr_size
                            max_target = ref_va2

                            # Search for image_count in raw data
                            if ptr_size == 8:
                                count_bytes = struct.pack('<Q', self._image_count)
                            else:
                                count_bytes = struct.pack('<I', self._image_count)

                            start_search = 0
                            while True:
                                idx = raw_data.find(count_bytes, start_search)
                                if idx == -1:
                                    break
                                if idx % ptr_size == 0:
                                    # Check if the next value is a valid codeGenModules pointer
                                    next_offset = idx + ptr_size
                                    if next_offset + ptr_size <= len(raw_data):
                                        if ptr_size == 8:
                                            ptr_val = struct.unpack_from('<Q', raw_data, next_offset)[0]
                                        else:
                                            ptr_val = struct.unpack_from('<I', raw_data, next_offset)[0]

                                        if min_target <= ptr_val <= max_target:
                                            # This could be it! Calculate i
                                            i = (ref_va2 - ptr_val) // ptr_size
                                            if 0 <= i < self._image_count and ptr_val == ref_va2 - i * ptr_size:
                                                ref_va3 = offset_to_va(next_offset)
                                                if ref_va3 is not None:
                                                    # v29.1+ has 2 extra fields (unresolvedInstanceCallPointers, unresolvedStaticCallPointers)
                                                    if self._il2cpp.version >= 29.1:
                                                        return ref_va3 - ptr_size * 16
                                                    elif self._il2cpp.version >= 29:
                                                        return ref_va3 - ptr_size * 14
                                                    return ref_va3 - ptr_size * 13

                                start_search = idx + 1
                        else:
                            for i in range(self._image_count):
                                target = ref_va2 - i * ptr_size
                                refs3 = find_refs_fast(target)
                                for _, ref_va3 in refs3:
                                    return ref_va3 - ptr_size * 13

        return 0

    def _find_reference(self, addr: int) -> Iterator[int]:
        """Find all references to an address in data sections."""
        import struct

        # Pack the address we're looking for
        if self._il2cpp.pointer_size == 8:
            addr_bytes = struct.pack('<Q', addr)
        else:
            addr_bytes = struct.pack('<I', addr)

        # Get raw data for fast search
        raw_data = self._il2cpp._stream.getvalue()

        for section in self._data_sections:
            # Search in section data using bytes.find() for speed
            section_data = raw_data[section.offset:section.offset_end]
            start = 0

            while True:
                idx = section_data.find(addr_bytes, start)
                if idx == -1:
                    break
                # Only yield if aligned to pointer size
                if idx % self._il2cpp.pointer_size == 0:
                    yield idx + section.address
                start = idx + 1

    def _search_bytes(self, data: bytes, pattern: bytes) -> Iterator[int]:
        """Search for a byte pattern in data."""
        start = 0
        while True:
            index = data.find(pattern, start)
            if index == -1:
                break
            yield index
            start = index + 1

    def _check_pointer_range_data_ra(self, pointer: int) -> bool:
        """Check if pointer is in data sections (raw address)."""
        return any(
            section.offset <= pointer <= section.offset_end
            for section in self._data_sections
        )

    def _check_pointer_range_exec_va(self, pointers: List[int]) -> bool:
        """Check if all pointers are in exec sections (virtual address)."""
        return all(
            any(
                section.address <= ptr <= section.address_end
                for section in self._exec_sections
            )
            for ptr in pointers
        )

    def _check_pointer_range_data_va(self, pointers: List[int]) -> bool:
        """Check if all pointers are in data sections (virtual address)."""
        return all(
            any(
                section.address <= ptr <= section.address_end
                for section in self._data_sections
            )
            for ptr in pointers
        )

    def _check_pointer_range_bss_va(self, pointers: List[int]) -> bool:
        """Check if all pointers are in BSS sections (virtual address)."""
        return all(
            any(
                section.address <= ptr <= section.address_end
                for section in self._bss_sections
            )
            for ptr in pointers
        )
