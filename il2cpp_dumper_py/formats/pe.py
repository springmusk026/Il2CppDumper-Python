"""
PE (Portable Executable) format parser for Windows IL2CPP binaries.

Parses GameAssembly.dll and other Windows IL2CPP binaries.
"""

from typing import List, Optional, Dict

from ..il2cpp.base import Il2Cpp
from ..search.section_helper import SectionHelper, SearchSection
from .pe_structures import (
    ImageDosHeader,
    ImageFileHeader,
    ImageOptionalHeader32,
    ImageOptionalHeader64,
    ImageDataDirectory,
    SectionHeader,
    ImageExportDirectory,
    IMAGE_DOS_SIGNATURE,
    IMAGE_NT_SIGNATURE,
    IMAGE_FILE_MACHINE_AMD64,
    IMAGE_FILE_MACHINE_ARM64,
    IMAGE_SCN_CNT_CODE,
    IMAGE_SCN_MEM_EXECUTE,
    IMAGE_SCN_CNT_INITIALIZED_DATA,
    IMAGE_DIRECTORY_ENTRY_EXPORT,
)


class PE(Il2Cpp):
    """
    PE format parser for Windows IL2CPP binaries.

    Supports both PE32 (32-bit) and PE32+ (64-bit) formats.
    """

    def __init__(self, data: bytes):
        super().__init__(data)
        self._load()

    def _load(self) -> None:
        """Load PE structures."""
        # Read DOS header
        self._dos_header = self._read_dos_header()
        if self._dos_header.e_magic != IMAGE_DOS_SIGNATURE:
            raise ValueError("Invalid DOS signature")

        # Read NT headers
        self.position = self._dos_header.e_lfanew
        nt_signature = self.read_uint32()
        if nt_signature != IMAGE_NT_SIGNATURE:
            raise ValueError("Invalid NT signature")

        # Read file header
        self._file_header = self._read_file_header()

        # Determine if 32-bit or 64-bit
        optional_magic = self.read_uint16()
        self.position -= 2  # Go back to read full optional header

        if optional_magic == 0x20B:  # PE32+
            self.is_32bit = False
            self._optional_header = self._read_optional_header64()
        else:  # PE32
            self.is_32bit = True
            self._optional_header = self._read_optional_header32()

        self.image_base = self._optional_header.ImageBase

        # Read section headers
        self._sections = self._read_sections()

        # Build section name lookup
        self._section_by_name: Dict[str, SectionHeader] = {
            s.Name: s for s in self._sections
        }

    def _read_dos_header(self) -> ImageDosHeader:
        """Read DOS header."""
        self.position = 0
        header = ImageDosHeader()
        header.e_magic = self.read_uint16()
        header.e_cblp = self.read_uint16()
        header.e_cp = self.read_uint16()
        header.e_crlc = self.read_uint16()
        header.e_cparhdr = self.read_uint16()
        header.e_minalloc = self.read_uint16()
        header.e_maxalloc = self.read_uint16()
        header.e_ss = self.read_uint16()
        header.e_sp = self.read_uint16()
        header.e_csum = self.read_uint16()
        header.e_ip = self.read_uint16()
        header.e_cs = self.read_uint16()
        header.e_lfarlc = self.read_uint16()
        header.e_ovno = self.read_uint16()
        header.e_res = self.read_bytes(8)
        header.e_oemid = self.read_uint16()
        header.e_oeminfo = self.read_uint16()
        header.e_res2 = self.read_bytes(20)
        header.e_lfanew = self.read_uint32()
        return header

    def _read_file_header(self) -> ImageFileHeader:
        """Read COFF file header."""
        header = ImageFileHeader()
        header.Machine = self.read_uint16()
        header.NumberOfSections = self.read_uint16()
        header.TimeDateStamp = self.read_uint32()
        header.PointerToSymbolTable = self.read_uint32()
        header.NumberOfSymbols = self.read_uint32()
        header.SizeOfOptionalHeader = self.read_uint16()
        header.Characteristics = self.read_uint16()
        return header

    def _read_optional_header32(self) -> ImageOptionalHeader32:
        """Read 32-bit optional header."""
        header = ImageOptionalHeader32()
        header.Magic = self.read_uint16()
        header.MajorLinkerVersion = self.read_byte()
        header.MinorLinkerVersion = self.read_byte()
        header.SizeOfCode = self.read_uint32()
        header.SizeOfInitializedData = self.read_uint32()
        header.SizeOfUninitializedData = self.read_uint32()
        header.AddressOfEntryPoint = self.read_uint32()
        header.BaseOfCode = self.read_uint32()
        header.BaseOfData = self.read_uint32()
        header.ImageBase = self.read_uint32()
        header.SectionAlignment = self.read_uint32()
        header.FileAlignment = self.read_uint32()
        header.MajorOperatingSystemVersion = self.read_uint16()
        header.MinorOperatingSystemVersion = self.read_uint16()
        header.MajorImageVersion = self.read_uint16()
        header.MinorImageVersion = self.read_uint16()
        header.MajorSubsystemVersion = self.read_uint16()
        header.MinorSubsystemVersion = self.read_uint16()
        header.Win32VersionValue = self.read_uint32()
        header.SizeOfImage = self.read_uint32()
        header.SizeOfHeaders = self.read_uint32()
        header.CheckSum = self.read_uint32()
        header.Subsystem = self.read_uint16()
        header.DllCharacteristics = self.read_uint16()
        header.SizeOfStackReserve = self.read_uint32()
        header.SizeOfStackCommit = self.read_uint32()
        header.SizeOfHeapReserve = self.read_uint32()
        header.SizeOfHeapCommit = self.read_uint32()
        header.LoaderFlags = self.read_uint32()
        header.NumberOfRvaAndSizes = self.read_uint32()

        # Read data directories
        header.DataDirectory = []
        for _ in range(min(header.NumberOfRvaAndSizes, 16)):
            dd = ImageDataDirectory()
            dd.VirtualAddress = self.read_uint32()
            dd.Size = self.read_uint32()
            header.DataDirectory.append(dd)

        return header

    def _read_optional_header64(self) -> ImageOptionalHeader64:
        """Read 64-bit optional header (PE32+)."""
        header = ImageOptionalHeader64()
        header.Magic = self.read_uint16()
        header.MajorLinkerVersion = self.read_byte()
        header.MinorLinkerVersion = self.read_byte()
        header.SizeOfCode = self.read_uint32()
        header.SizeOfInitializedData = self.read_uint32()
        header.SizeOfUninitializedData = self.read_uint32()
        header.AddressOfEntryPoint = self.read_uint32()
        header.BaseOfCode = self.read_uint32()
        # Note: No BaseOfData in PE32+
        header.ImageBase = self.read_uint64()
        header.SectionAlignment = self.read_uint32()
        header.FileAlignment = self.read_uint32()
        header.MajorOperatingSystemVersion = self.read_uint16()
        header.MinorOperatingSystemVersion = self.read_uint16()
        header.MajorImageVersion = self.read_uint16()
        header.MinorImageVersion = self.read_uint16()
        header.MajorSubsystemVersion = self.read_uint16()
        header.MinorSubsystemVersion = self.read_uint16()
        header.Win32VersionValue = self.read_uint32()
        header.SizeOfImage = self.read_uint32()
        header.SizeOfHeaders = self.read_uint32()
        header.CheckSum = self.read_uint32()
        header.Subsystem = self.read_uint16()
        header.DllCharacteristics = self.read_uint16()
        header.SizeOfStackReserve = self.read_uint64()
        header.SizeOfStackCommit = self.read_uint64()
        header.SizeOfHeapReserve = self.read_uint64()
        header.SizeOfHeapCommit = self.read_uint64()
        header.LoaderFlags = self.read_uint32()
        header.NumberOfRvaAndSizes = self.read_uint32()

        # Read data directories
        header.DataDirectory = []
        for _ in range(min(header.NumberOfRvaAndSizes, 16)):
            dd = ImageDataDirectory()
            dd.VirtualAddress = self.read_uint32()
            dd.Size = self.read_uint32()
            header.DataDirectory.append(dd)

        return header

    def _read_sections(self) -> List[SectionHeader]:
        """Read section headers."""
        sections = []
        for _ in range(self._file_header.NumberOfSections):
            section = SectionHeader()
            name_bytes = self.read_bytes(8)
            section.Name = name_bytes.rstrip(b'\x00').decode('ascii', errors='replace')
            section.VirtualSize = self.read_uint32()
            section.VirtualAddress = self.read_uint32()
            section.SizeOfRawData = self.read_uint32()
            section.PointerToRawData = self.read_uint32()
            section.PointerToRelocations = self.read_uint32()
            section.PointerToLinenumbers = self.read_uint32()
            section.NumberOfRelocations = self.read_uint16()
            section.NumberOfLinenumbers = self.read_uint16()
            section.Characteristics = self.read_uint32()
            sections.append(section)
        return sections

    def map_vatr(self, addr: int) -> int:
        """Map virtual address to raw file offset."""
        # Handle addresses that include image base
        if addr >= self.image_base:
            addr -= self.image_base

        for section in self._sections:
            section_start = section.VirtualAddress
            section_end = section_start + section.VirtualSize
            if section_start <= addr < section_end:
                return addr - section.VirtualAddress + section.PointerToRawData

        raise ValueError(f"Address 0x{addr:x} not in any section")

    def map_rtva(self, addr: int) -> int:
        """Map raw file offset to virtual address."""
        for section in self._sections:
            section_start = section.PointerToRawData
            section_end = section_start + section.SizeOfRawData
            if section_start <= addr < section_end:
                return addr - section.PointerToRawData + section.VirtualAddress + self.image_base

        return 0

    def search(self) -> bool:
        """Search for registration using pattern matching."""
        # PE files typically use symbol/export search instead
        return False

    def plus_search(self, method_count: int, type_definitions_count: int, image_count: int) -> bool:
        """Search using modern algorithm."""
        section_helper = self.get_section_helper(method_count, type_definitions_count, image_count)
        code_registration = section_helper.find_code_registration()
        metadata_registration = section_helper.find_metadata_registration()
        return self.auto_plus_init(code_registration, metadata_registration)

    def symbol_search(self) -> bool:
        """Search using export table."""
        code_registration = 0
        metadata_registration = 0

        # Get export directory
        if len(self._optional_header.DataDirectory) <= IMAGE_DIRECTORY_ENTRY_EXPORT:
            return False

        export_dir = self._optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
        if export_dir.VirtualAddress == 0:
            return False

        try:
            self.position = self.map_vatr(export_dir.VirtualAddress)
            export = ImageExportDirectory()
            export.Characteristics = self.read_uint32()
            export.TimeDateStamp = self.read_uint32()
            export.MajorVersion = self.read_uint16()
            export.MinorVersion = self.read_uint16()
            export.Name = self.read_uint32()
            export.Base = self.read_uint32()
            export.NumberOfFunctions = self.read_uint32()
            export.NumberOfNames = self.read_uint32()
            export.AddressOfFunctions = self.read_uint32()
            export.AddressOfNames = self.read_uint32()
            export.AddressOfNameOrdinals = self.read_uint32()

            # Read export names
            names_offset = self.map_vatr(export.AddressOfNames)
            ordinals_offset = self.map_vatr(export.AddressOfNameOrdinals)
            functions_offset = self.map_vatr(export.AddressOfFunctions)

            for i in range(export.NumberOfNames):
                # Read name RVA
                self.position = names_offset + i * 4
                name_rva = self.read_uint32()
                name = self.read_string_to_null(self.map_vatr(name_rva))

                # Read ordinal
                self.position = ordinals_offset + i * 2
                ordinal = self.read_uint16()

                # Read function RVA
                self.position = functions_offset + ordinal * 4
                func_rva = self.read_uint32()

                if name == "g_CodeRegistration":
                    code_registration = func_rva + self.image_base
                elif name == "g_MetadataRegistration":
                    metadata_registration = func_rva + self.image_base

            if code_registration > 0 and metadata_registration > 0:
                print("Detected Symbol!")
                print(f"CodeRegistration : {code_registration:x}")
                print(f"MetadataRegistration : {metadata_registration:x}")
                self.init(code_registration, metadata_registration)
                return True

        except Exception as e:
            print(f"Export search error: {e}")

        return False

    def get_section_helper(self, method_count: int, type_definitions_count: int, image_count: int) -> SectionHelper:
        """Get section helper for searching."""
        data_list = []
        exec_list = []

        for section in self._sections:
            if section.VirtualSize == 0:
                continue

            search_section = SearchSection(
                offset=section.PointerToRawData,
                offset_end=section.PointerToRawData + section.SizeOfRawData,
                address=section.VirtualAddress + self.image_base,
                address_end=section.VirtualAddress + section.VirtualSize + self.image_base
            )

            # Check if executable
            if (section.Characteristics & IMAGE_SCN_CNT_CODE) != 0 or \
               (section.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0:
                exec_list.append(search_section)
            else:
                data_list.append(search_section)

        helper = SectionHelper(self, method_count, type_definitions_count,
                               self._metadata_usages_count, image_count)
        helper.set_exec_sections(exec_list)
        helper.set_data_sections(data_list)
        helper.set_bss_sections(data_list)

        return helper

    def check_dump(self) -> bool:
        """Check if this is a memory dump."""
        # Check if sections are properly aligned
        for section in self._sections:
            if section.PointerToRawData != section.VirtualAddress:
                return False
        return True

    def get_rva(self, pointer: int) -> int:
        """Get RVA from virtual address."""
        return pointer - self.image_base
