"""
Mach-O format parser for macOS/iOS IL2CPP binaries.

Supports both 32-bit and 64-bit Mach-O formats, as well as
FAT (Universal) binaries containing multiple architectures.
"""

from typing import List, Optional, Dict, Tuple
from io import BytesIO

from ..il2cpp.base import Il2Cpp
from ..search.section_helper import SectionHelper, SearchSection
from .macho_structures import (
    MachHeader, MachHeader64,
    SegmentCommand, SegmentCommand64,
    MachoSection, MachoSection64Bit,
    SymtabCommand, Nlist, Nlist64,
    EncryptionInfoCommand, EncryptionInfoCommand64,
    FatHeader, FatArch,
    MH_MAGIC, MH_MAGIC_64, FAT_MAGIC, FAT_CIGAM,
    LC_SEGMENT, LC_SEGMENT_64, LC_SYMTAB, LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64,
    S_ATTR_PURE_INSTRUCTIONS, S_ATTR_SOME_INSTRUCTIONS,
)


class MachoFat:
    """
    FAT (Universal) Mach-O parser.

    This handles universal binaries containing multiple architectures.
    """

    def __init__(self, data: bytes):
        self._data = data
        self._stream = BytesIO(data)
        self.fats: List[Tuple[int, FatArch]] = []  # (magic, FatArch)
        self._load()

    def _load(self) -> None:
        """Load FAT header and architecture entries."""
        self._stream.seek(0)
        magic = int.from_bytes(self._stream.read(4), 'big')

        if magic not in (FAT_MAGIC, FAT_CIGAM):
            raise ValueError("Not a FAT Mach-O file")

        nfat_arch = int.from_bytes(self._stream.read(4), 'big')

        for _ in range(nfat_arch):
            arch = FatArch()
            arch.cputype = int.from_bytes(self._stream.read(4), 'big')
            arch.cpusubtype = int.from_bytes(self._stream.read(4), 'big')
            arch.offset = int.from_bytes(self._stream.read(4), 'big')
            arch.size = int.from_bytes(self._stream.read(4), 'big')
            arch.align = int.from_bytes(self._stream.read(4), 'big')

            # Peek at the magic to determine 32/64 bit
            self._stream.seek(arch.offset)
            slice_magic = int.from_bytes(self._stream.read(4), 'little')
            self.fats.append((slice_magic, arch))

    def get_macho(self, index: int) -> bytes:
        """Get a specific architecture slice."""
        if index < 0 or index >= len(self.fats):
            raise IndexError("Invalid architecture index")

        _, arch = self.fats[index]
        return self._data[arch.offset:arch.offset + arch.size]


class Macho(Il2Cpp):
    """
    32-bit Mach-O parser for iOS/macOS IL2CPP binaries.
    """

    def __init__(self, data: bytes):
        super().__init__(data)
        self.is_32bit = True
        self._sections: List[MachoSection] = []
        self._symbols: List[Nlist] = []
        self._string_table: bytes = b''
        self._load()

    def _load(self) -> None:
        """Load Mach-O structures."""
        self.position = 0
        self._header = self._read_header()

        if self._header.magic != MH_MAGIC:
            raise ValueError("Invalid Mach-O magic")

        # Read load commands
        self._segments: List[SegmentCommand] = []
        self._symtab: Optional[SymtabCommand] = None
        self._encryption_info: Optional[EncryptionInfoCommand] = None

        for _ in range(self._header.ncmds):
            cmd_pos = self.position
            cmd = self.read_uint32()
            cmdsize = self.read_uint32()

            if cmd == LC_SEGMENT:
                self.position = cmd_pos
                segment = self._read_segment_command()
                self._segments.append(segment)

                # Read sections
                for _ in range(segment.nsects):
                    section = self._read_section()
                    self._sections.append(section)

            elif cmd == LC_SYMTAB:
                self.position = cmd_pos
                self._symtab = self._read_symtab_command()

            elif cmd == LC_ENCRYPTION_INFO:
                self.position = cmd_pos
                self._encryption_info = self._read_encryption_info()

            self.position = cmd_pos + cmdsize

        # Load symbols
        if self._symtab:
            self._load_symbols()

        # Check for encryption
        if self._encryption_info and self._encryption_info.cryptid != 0:
            print("WARNING: Binary is encrypted")

    def _read_header(self) -> MachHeader:
        """Read Mach-O header."""
        header = MachHeader()
        header.magic = self.read_uint32()
        header.cputype = self.read_int32()
        header.cpusubtype = self.read_int32()
        header.filetype = self.read_uint32()
        header.ncmds = self.read_uint32()
        header.sizeofcmds = self.read_uint32()
        header.flags = self.read_uint32()
        return header

    def _read_segment_command(self) -> SegmentCommand:
        """Read segment load command."""
        segment = SegmentCommand()
        segment.cmd = self.read_uint32()
        segment.cmdsize = self.read_uint32()
        segment.segname = self.read_bytes(16).rstrip(b'\x00').decode('ascii', errors='replace')
        segment.vmaddr = self.read_uint32()
        segment.vmsize = self.read_uint32()
        segment.fileoff = self.read_uint32()
        segment.filesize = self.read_uint32()
        segment.maxprot = self.read_int32()
        segment.initprot = self.read_int32()
        segment.nsects = self.read_uint32()
        segment.flags = self.read_uint32()
        return segment

    def _read_section(self) -> MachoSection:
        """Read section."""
        section = MachoSection()
        section.sectname = self.read_bytes(16).rstrip(b'\x00').decode('ascii', errors='replace')
        section.segname = self.read_bytes(16).rstrip(b'\x00').decode('ascii', errors='replace')
        section.addr = self.read_uint32()
        section.size = self.read_uint32()
        section.offset = self.read_uint32()
        section.align = self.read_uint32()
        section.reloff = self.read_uint32()
        section.nreloc = self.read_uint32()
        section.flags = self.read_uint32()
        section.reserved1 = self.read_uint32()
        section.reserved2 = self.read_uint32()
        return section

    def _read_symtab_command(self) -> SymtabCommand:
        """Read symbol table command."""
        symtab = SymtabCommand()
        symtab.cmd = self.read_uint32()
        symtab.cmdsize = self.read_uint32()
        symtab.symoff = self.read_uint32()
        symtab.nsyms = self.read_uint32()
        symtab.stroff = self.read_uint32()
        symtab.strsize = self.read_uint32()
        return symtab

    def _read_encryption_info(self) -> EncryptionInfoCommand:
        """Read encryption info command."""
        enc = EncryptionInfoCommand()
        enc.cmd = self.read_uint32()
        enc.cmdsize = self.read_uint32()
        enc.cryptoff = self.read_uint32()
        enc.cryptsize = self.read_uint32()
        enc.cryptid = self.read_uint32()
        return enc

    def _load_symbols(self) -> None:
        """Load symbol table."""
        if not self._symtab:
            return

        # Read string table
        self.position = self._symtab.stroff
        self._string_table = self.read_bytes(self._symtab.strsize)

        # Read symbols
        self.position = self._symtab.symoff
        for _ in range(self._symtab.nsyms):
            sym = Nlist()
            sym.n_strx = self.read_uint32()
            sym.n_type = self.read_byte()
            sym.n_sect = self.read_byte()
            sym.n_desc = self.read_int16()
            sym.n_value = self.read_uint32()
            self._symbols.append(sym)

    def _get_symbol_name(self, sym: Nlist) -> str:
        """Get symbol name from string table."""
        if sym.n_strx >= len(self._string_table):
            return ""
        end = self._string_table.find(b'\x00', sym.n_strx)
        if end == -1:
            end = len(self._string_table)
        return self._string_table[sym.n_strx:end].decode('ascii', errors='replace')

    def map_vatr(self, addr: int) -> int:
        """Map virtual address to raw file offset."""
        for segment in self._segments:
            if segment.vmaddr <= addr < segment.vmaddr + segment.vmsize:
                return addr - segment.vmaddr + segment.fileoff
        raise ValueError(f"Address 0x{addr:x} not in any segment")

    def map_rtva(self, addr: int) -> int:
        """Map raw file offset to virtual address."""
        for segment in self._segments:
            if segment.fileoff <= addr < segment.fileoff + segment.filesize:
                return addr - segment.fileoff + segment.vmaddr
        return 0

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
        """Search using symbol table."""
        code_registration = 0
        metadata_registration = 0

        for sym in self._symbols:
            name = self._get_symbol_name(sym)
            if name == "_g_CodeRegistration":
                code_registration = sym.n_value
            elif name == "_g_MetadataRegistration":
                metadata_registration = sym.n_value

        if code_registration > 0 and metadata_registration > 0:
            print("Detected Symbol!")
            print(f"CodeRegistration : {code_registration:x}")
            print(f"MetadataRegistration : {metadata_registration:x}")
            self.init(code_registration, metadata_registration)
            return True

        return False

    def get_section_helper(self, method_count: int, type_definitions_count: int, image_count: int) -> SectionHelper:
        """Get section helper for searching."""
        data_list = []
        exec_list = []

        for section in self._sections:
            search_section = SearchSection(
                offset=section.offset,
                offset_end=section.offset + section.size,
                address=section.addr,
                address_end=section.addr + section.size
            )

            if (section.flags & S_ATTR_PURE_INSTRUCTIONS) != 0 or \
               (section.flags & S_ATTR_SOME_INSTRUCTIONS) != 0:
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
        return False

    def get_rva(self, pointer: int) -> int:
        """Get RVA."""
        return pointer


class Macho64(Il2Cpp):
    """
    64-bit Mach-O parser for iOS/macOS IL2CPP binaries.
    """

    def __init__(self, data: bytes):
        super().__init__(data)
        self.is_32bit = False
        self._sections: List[MachoSection64Bit] = []
        self._symbols: List[Nlist64] = []
        self._string_table: bytes = b''
        self._load()

    def _load(self) -> None:
        """Load Mach-O structures."""
        self.position = 0
        self._header = self._read_header()

        if self._header.magic != MH_MAGIC_64:
            raise ValueError("Invalid Mach-O 64-bit magic")

        # Read load commands
        self._segments: List[SegmentCommand64] = []
        self._symtab: Optional[SymtabCommand] = None
        self._encryption_info: Optional[EncryptionInfoCommand64] = None

        for _ in range(self._header.ncmds):
            cmd_pos = self.position
            cmd = self.read_uint32()
            cmdsize = self.read_uint32()

            if cmd == LC_SEGMENT_64:
                self.position = cmd_pos
                segment = self._read_segment_command()
                self._segments.append(segment)

                # Read sections
                for _ in range(segment.nsects):
                    section = self._read_section()
                    self._sections.append(section)

            elif cmd == LC_SYMTAB:
                self.position = cmd_pos
                self._symtab = self._read_symtab_command()

            elif cmd == LC_ENCRYPTION_INFO_64:
                self.position = cmd_pos
                self._encryption_info = self._read_encryption_info()

            self.position = cmd_pos + cmdsize

        # Load symbols
        if self._symtab:
            self._load_symbols()

        # Check for encryption
        if self._encryption_info and self._encryption_info.cryptid != 0:
            print("WARNING: Binary is encrypted")

    def _read_header(self) -> MachHeader64:
        """Read Mach-O 64-bit header."""
        header = MachHeader64()
        header.magic = self.read_uint32()
        header.cputype = self.read_int32()
        header.cpusubtype = self.read_int32()
        header.filetype = self.read_uint32()
        header.ncmds = self.read_uint32()
        header.sizeofcmds = self.read_uint32()
        header.flags = self.read_uint32()
        header.reserved = self.read_uint32()
        return header

    def _read_segment_command(self) -> SegmentCommand64:
        """Read segment load command."""
        segment = SegmentCommand64()
        segment.cmd = self.read_uint32()
        segment.cmdsize = self.read_uint32()
        segment.segname = self.read_bytes(16).rstrip(b'\x00').decode('ascii', errors='replace')
        segment.vmaddr = self.read_uint64()
        segment.vmsize = self.read_uint64()
        segment.fileoff = self.read_uint64()
        segment.filesize = self.read_uint64()
        segment.maxprot = self.read_int32()
        segment.initprot = self.read_int32()
        segment.nsects = self.read_uint32()
        segment.flags = self.read_uint32()
        return segment

    def _read_section(self) -> MachoSection64Bit:
        """Read section."""
        section = MachoSection64Bit()
        section.sectname = self.read_bytes(16).rstrip(b'\x00').decode('ascii', errors='replace')
        section.segname = self.read_bytes(16).rstrip(b'\x00').decode('ascii', errors='replace')
        section.addr = self.read_uint64()
        section.size = self.read_uint64()
        section.offset = self.read_uint32()
        section.align = self.read_uint32()
        section.reloff = self.read_uint32()
        section.nreloc = self.read_uint32()
        section.flags = self.read_uint32()
        section.reserved1 = self.read_uint32()
        section.reserved2 = self.read_uint32()
        section.reserved3 = self.read_uint32()
        return section

    def _read_symtab_command(self) -> SymtabCommand:
        """Read symbol table command."""
        symtab = SymtabCommand()
        symtab.cmd = self.read_uint32()
        symtab.cmdsize = self.read_uint32()
        symtab.symoff = self.read_uint32()
        symtab.nsyms = self.read_uint32()
        symtab.stroff = self.read_uint32()
        symtab.strsize = self.read_uint32()
        return symtab

    def _read_encryption_info(self) -> EncryptionInfoCommand64:
        """Read encryption info command."""
        enc = EncryptionInfoCommand64()
        enc.cmd = self.read_uint32()
        enc.cmdsize = self.read_uint32()
        enc.cryptoff = self.read_uint32()
        enc.cryptsize = self.read_uint32()
        enc.cryptid = self.read_uint32()
        enc.pad = self.read_uint32()
        return enc

    def _load_symbols(self) -> None:
        """Load symbol table."""
        if not self._symtab:
            return

        # Read string table
        self.position = self._symtab.stroff
        self._string_table = self.read_bytes(self._symtab.strsize)

        # Read symbols
        self.position = self._symtab.symoff
        for _ in range(self._symtab.nsyms):
            sym = Nlist64()
            sym.n_strx = self.read_uint32()
            sym.n_type = self.read_byte()
            sym.n_sect = self.read_byte()
            sym.n_desc = self.read_uint16()
            sym.n_value = self.read_uint64()
            self._symbols.append(sym)

    def _get_symbol_name(self, sym: Nlist64) -> str:
        """Get symbol name from string table."""
        if sym.n_strx >= len(self._string_table):
            return ""
        end = self._string_table.find(b'\x00', sym.n_strx)
        if end == -1:
            end = len(self._string_table)
        return self._string_table[sym.n_strx:end].decode('ascii', errors='replace')

    def map_vatr(self, addr: int) -> int:
        """Map virtual address to raw file offset."""
        for segment in self._segments:
            if segment.vmaddr <= addr < segment.vmaddr + segment.vmsize:
                return addr - segment.vmaddr + segment.fileoff
        raise ValueError(f"Address 0x{addr:x} not in any segment")

    def map_rtva(self, addr: int) -> int:
        """Map raw file offset to virtual address."""
        for segment in self._segments:
            if segment.fileoff <= addr < segment.fileoff + segment.filesize:
                return addr - segment.fileoff + segment.vmaddr
        return 0

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
        """Search using symbol table."""
        code_registration = 0
        metadata_registration = 0

        for sym in self._symbols:
            name = self._get_symbol_name(sym)
            if name == "_g_CodeRegistration":
                code_registration = sym.n_value
            elif name == "_g_MetadataRegistration":
                metadata_registration = sym.n_value

        if code_registration > 0 and metadata_registration > 0:
            print("Detected Symbol!")
            print(f"CodeRegistration : {code_registration:x}")
            print(f"MetadataRegistration : {metadata_registration:x}")
            self.init(code_registration, metadata_registration)
            return True

        return False

    def get_section_helper(self, method_count: int, type_definitions_count: int, image_count: int) -> SectionHelper:
        """Get section helper for searching."""
        data_list = []
        exec_list = []

        for section in self._sections:
            search_section = SearchSection(
                offset=section.offset,
                offset_end=section.offset + section.size,
                address=section.addr,
                address_end=section.addr + section.size
            )

            if (section.flags & S_ATTR_PURE_INSTRUCTIONS) != 0 or \
               (section.flags & S_ATTR_SOME_INSTRUCTIONS) != 0:
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
        return False

    def get_rva(self, pointer: int) -> int:
        """Get RVA."""
        return pointer
