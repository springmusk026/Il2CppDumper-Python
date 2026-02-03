"""
ELF format parser for IL2CPP binaries.

Supports both ELF32 (32-bit) and ELF64 (64-bit) formats,
commonly used for Android (libil2cpp.so) and Linux binaries.
"""

from typing import List, Optional, Dict, Any
from abc import abstractmethod

from ..il2cpp.base import Il2Cpp
from ..search.section_helper import SectionHelper, SearchSection
from .elf_structures import (
    Elf32_Ehdr, Elf64_Ehdr,
    Elf32_Phdr, Elf64_Phdr,
    Elf32_Shdr, Elf64_Shdr,
    Elf32_Dyn, Elf64_Dyn,
    Elf32_Sym, Elf64_Sym,
    Elf32_Rel, Elf64_Rel,
    PT_LOAD, PT_DYNAMIC,
    PF_X, PF_W, PF_R,
    DT_PLTGOT, DT_HASH, DT_GNU_HASH, DT_STRTAB, DT_SYMTAB,
    DT_INIT, DT_REL, DT_RELSZ, DT_RELA, DT_RELASZ,
    EM_ARM, EM_AARCH64, EM_X86_64,
    R_386_32, R_ARM_ABS32,
    R_AARCH64_ABS64, R_AARCH64_RELATIVE,
    R_X86_64_64, R_X86_64_RELATIVE,
    SHT_LOUSER,
)
from ..utils.pattern_search import search_pattern


class ElfBase(Il2Cpp):
    """Base class for ELF format parsing."""

    def __init__(self, data: bytes):
        super().__init__(data)
        self._dynamic_section = []
        self._symbol_table = []
        self._section_table = []

    @abstractmethod
    def _load(self) -> None:
        """Load ELF structures."""
        pass

    def reload(self) -> None:
        """Reload after setting image base for memory dumps."""
        self._load()

    @abstractmethod
    def _check_section(self) -> bool:
        """Check if sections are valid."""
        pass


class Elf(ElfBase):
    """
    ELF32 format parser.

    Used for 32-bit Android and Linux IL2CPP binaries.
    """

    # ARM feature bytes pattern for searching
    ARM_FEATURE_BYTES = "? 10 ? E7 ? 00 ? E0 ? 20 ? E0"

    def __init__(self, data: bytes):
        super().__init__(data)
        self.is_32bit = True
        self._load()

    def _load(self) -> None:
        """Load ELF32 structures."""
        # Read ELF header
        self._elf_header = self._read_elf32_header()

        # Read program headers
        self._program_segments = self._read_elf32_phdrs()

        if self.is_dumped:
            self._fix_program_segments()

        # Find PT_DYNAMIC segment
        self._pt_dynamic = None
        for seg in self._program_segments:
            if seg.p_type == PT_DYNAMIC:
                self._pt_dynamic = seg
                break

        if self._pt_dynamic is None:
            raise ValueError("No PT_DYNAMIC segment found")

        # Read dynamic section
        self._dynamic_section = self._read_elf32_dynamic()

        if self.is_dumped:
            self._fix_dynamic_section()

        # Read symbols
        self._read_symbols()

        if not self.is_dumped:
            self._process_relocations()
            if self._check_protection():
                print("ERROR: This file may be protected.")

    def _read_elf32_header(self) -> Elf32_Ehdr:
        """Read ELF32 header."""
        self.position = 0
        header = Elf32_Ehdr()
        header.e_ident = self.read_bytes(16)
        header.e_type = self.read_uint16()
        header.e_machine = self.read_uint16()
        header.e_version = self.read_uint32()
        header.e_entry = self.read_uint32()
        header.e_phoff = self.read_uint32()
        header.e_shoff = self.read_uint32()
        header.e_flags = self.read_uint32()
        header.e_ehsize = self.read_uint16()
        header.e_phentsize = self.read_uint16()
        header.e_phnum = self.read_uint16()
        header.e_shentsize = self.read_uint16()
        header.e_shnum = self.read_uint16()
        header.e_shstrndx = self.read_uint16()
        return header

    def _read_elf32_phdrs(self) -> List[Elf32_Phdr]:
        """Read ELF32 program headers."""
        self.position = self._elf_header.e_phoff
        segments = []
        for _ in range(self._elf_header.e_phnum):
            phdr = Elf32_Phdr()
            phdr.p_type = self.read_uint32()
            phdr.p_offset = self.read_uint32()
            phdr.p_vaddr = self.read_uint32()
            phdr.p_paddr = self.read_uint32()
            phdr.p_filesz = self.read_uint32()
            phdr.p_memsz = self.read_uint32()
            phdr.p_flags = self.read_uint32()
            phdr.p_align = self.read_uint32()
            segments.append(phdr)
        return segments

    def _read_elf32_dynamic(self) -> List[Elf32_Dyn]:
        """Read ELF32 dynamic section."""
        self.position = self._pt_dynamic.p_offset
        count = self._pt_dynamic.p_filesz // 8
        entries = []
        for _ in range(count):
            dyn = Elf32_Dyn()
            dyn.d_tag = self.read_int32()
            dyn.d_un = self.read_uint32()
            entries.append(dyn)
            if dyn.d_tag == 0:  # DT_NULL
                break
        return entries

    def _read_symbols(self) -> None:
        """Read symbol table."""
        try:
            # Find symbol count via hash table
            symbol_count = 0
            hash_entry = self._find_dynamic_entry(DT_HASH)
            if hash_entry:
                addr = self.map_vatr(hash_entry.d_un)
                self.position = addr
                nbucket = self.read_uint32()
                nchain = self.read_uint32()
                symbol_count = nchain
            else:
                # Try GNU hash
                hash_entry = self._find_dynamic_entry(DT_GNU_HASH)
                if hash_entry:
                    addr = self.map_vatr(hash_entry.d_un)
                    self.position = addr
                    nbuckets = self.read_uint32()
                    symoffset = self.read_uint32()
                    bloom_size = self.read_uint32()
                    bloom_shift = self.read_uint32()
                    buckets_address = addr + 16 + (4 * bloom_size)
                    self.position = buckets_address
                    buckets = [self.read_uint32() for _ in range(nbuckets)]
                    last_symbol = max(buckets) if buckets else 0
                    if last_symbol < symoffset:
                        symbol_count = symoffset
                    else:
                        chains_base = buckets_address + 4 * nbuckets
                        self.position = chains_base + (last_symbol - symoffset) * 4
                        while True:
                            chain_entry = self.read_uint32()
                            last_symbol += 1
                            if (chain_entry & 1) != 0:
                                break
                        symbol_count = last_symbol

            # Read symbols
            symtab_entry = self._find_dynamic_entry(DT_SYMTAB)
            if symtab_entry and symbol_count > 0:
                dynsym_offset = self.map_vatr(symtab_entry.d_un)
                self.position = dynsym_offset
                self._symbol_table = []
                for _ in range(symbol_count):
                    sym = Elf32_Sym()
                    sym.st_name = self.read_uint32()
                    sym.st_value = self.read_uint32()
                    sym.st_size = self.read_uint32()
                    sym.st_info = self.read_byte()
                    sym.st_other = self.read_byte()
                    sym.st_shndx = self.read_uint16()
                    self._symbol_table.append(sym)
        except Exception:
            pass

    def _find_dynamic_entry(self, tag: int) -> Optional[Elf32_Dyn]:
        """Find a dynamic entry by tag."""
        for entry in self._dynamic_section:
            if entry.d_tag == tag:
                return entry
        return None

    def _process_relocations(self) -> None:
        """Process relocations."""
        print("Applying relocations...")
        try:
            rel_entry = self._find_dynamic_entry(DT_REL)
            relsz_entry = self._find_dynamic_entry(DT_RELSZ)
            if not rel_entry or not relsz_entry:
                return

            rel_offset = self.map_vatr(rel_entry.d_un)
            rel_size = relsz_entry.d_un
            count = rel_size // 8

            self.position = rel_offset
            is_x86 = self._elf_header.e_machine == 0x3

            for _ in range(count):
                r_offset = self.read_uint32()
                r_info = self.read_uint32()
                rel_type = r_info & 0xFF
                sym = r_info >> 8

                if (rel_type == R_386_32 and is_x86) or (rel_type == R_ARM_ABS32 and not is_x86):
                    if sym < len(self._symbol_table):
                        symbol = self._symbol_table[sym]
                        self.position = self.map_vatr(r_offset)
                        self.write_uint32(symbol.st_value)
        except Exception:
            pass

    def _check_protection(self) -> bool:
        """Check for protection (packers, obfuscators)."""
        try:
            # Check for .init_proc
            if self._find_dynamic_entry(DT_INIT):
                print("WARNING: find .init_proc")
                return True

            # Check for JNI_OnLoad
            strtab_entry = self._find_dynamic_entry(DT_STRTAB)
            if strtab_entry:
                dynstr_offset = self.map_vatr(strtab_entry.d_un)
                for symbol in self._symbol_table:
                    name = self.read_string_to_null(dynstr_offset + symbol.st_name)
                    if name == "JNI_OnLoad":
                        print("WARNING: find JNI_OnLoad")
                        return True

            # Check for SHT_LOUSER sections
            if self._section_table:
                for section in self._section_table:
                    if section.sh_type == SHT_LOUSER:
                        print("WARNING: find SHT_LOUSER section")
                        return True
        except Exception:
            pass
        return False

    def _check_section(self) -> bool:
        """Check if sections are valid."""
        try:
            names = []
            self.position = self._elf_header.e_shoff
            self._section_table = []
            for _ in range(self._elf_header.e_shnum):
                shdr = Elf32_Shdr()
                shdr.sh_name = self.read_uint32()
                shdr.sh_type = self.read_uint32()
                shdr.sh_flags = self.read_uint32()
                shdr.sh_addr = self.read_uint32()
                shdr.sh_offset = self.read_uint32()
                shdr.sh_size = self.read_uint32()
                shdr.sh_link = self.read_uint32()
                shdr.sh_info = self.read_uint32()
                shdr.sh_addralign = self.read_uint32()
                shdr.sh_entsize = self.read_uint32()
                self._section_table.append(shdr)

            if self._elf_header.e_shstrndx < len(self._section_table):
                shstrndx = self._section_table[self._elf_header.e_shstrndx].sh_offset
                for section in self._section_table:
                    names.append(self.read_string_to_null(shstrndx + section.sh_name))

            return ".text" in names
        except Exception:
            return False

    def _fix_program_segments(self) -> None:
        """Fix program segments for memory dumps."""
        for i, phdr in enumerate(self._program_segments):
            self.position = self._elf_header.e_phoff + i * 32 + 4
            phdr.p_offset = phdr.p_vaddr
            self.write_uint32(phdr.p_offset)
            phdr.p_vaddr += self.image_base
            self.write_uint32(phdr.p_vaddr)
            self.position += 4
            phdr.p_filesz = phdr.p_memsz
            self.write_uint32(phdr.p_filesz)

    def _fix_dynamic_section(self) -> None:
        """Fix dynamic section for memory dumps."""
        for i, dyn in enumerate(self._dynamic_section):
            self.position = self._pt_dynamic.p_offset + i * 8 + 4
            if dyn.d_tag in [DT_PLTGOT, DT_HASH, DT_STRTAB, DT_SYMTAB,
                             7, DT_INIT, 13, DT_REL, 23, 25, 26]:  # Various DT_* tags
                dyn.d_un += self.image_base
                self.write_uint32(dyn.d_un)

    def map_vatr(self, addr: int) -> int:
        """Map virtual address to raw file offset."""
        for phdr in self._program_segments:
            if phdr.p_vaddr <= addr <= phdr.p_vaddr + phdr.p_memsz:
                return addr - phdr.p_vaddr + phdr.p_offset
        raise ValueError(f"Address 0x{addr:x} not in any segment")

    def map_rtva(self, addr: int) -> int:
        """Map raw file offset to virtual address."""
        for phdr in self._program_segments:
            if phdr.p_offset <= addr <= phdr.p_offset + phdr.p_filesz:
                return addr - phdr.p_offset + phdr.p_vaddr
        return 0

    def search(self) -> bool:
        """Search for registration using pattern matching."""
        pltgot = self._find_dynamic_entry(DT_PLTGOT)
        if not pltgot:
            return False

        global_offset_table = pltgot.d_un

        # Find executable segments
        execs = [seg for seg in self._program_segments
                 if seg.p_type == PT_LOAD and (seg.p_flags & PF_X)]

        feature_bytes = self.ARM_FEATURE_BYTES if self._elf_header.e_machine == EM_ARM else self.ARM_FEATURE_BYTES

        results = []
        for exec_seg in execs:
            self.position = exec_seg.p_offset
            buff = self.read_bytes(exec_seg.p_filesz)
            matches = search_pattern(buff, feature_bytes)
            for match in matches:
                # Check if it's an LDR instruction
                if len(buff) > match + 2:
                    bin_str = format(buff[match + 2], '08b')
                    if bin_str[3] == '1':  # LDR
                        results.append(match)

        if len(results) == 1:
            result = results[0]
            code_registration = 0
            metadata_registration = 0

            if self.version < 24:
                if self._elf_header.e_machine == EM_ARM:
                    self.position = result + 0x14
                    code_registration = self.read_uint32() + global_offset_table
                    self.position = result + 0x18
                    ptr = self.read_uint32() + global_offset_table
                    self.position = self.map_vatr(ptr)
                    metadata_registration = self.read_uint32()
            elif self.version >= 24:
                if self._elf_header.e_machine == EM_ARM:
                    self.position = result + 0x14
                    code_registration = self.read_uint32() + result + 0xC + self.image_base
                    self.position = result + 0x10
                    ptr = self.read_uint32() + result + 0x8
                    self.position = self.map_vatr(ptr + self.image_base)
                    metadata_registration = self.read_uint32()

            if code_registration and metadata_registration:
                print(f"CodeRegistration : {code_registration:x}")
                print(f"MetadataRegistration : {metadata_registration:x}")
                self.init(code_registration, metadata_registration)
                return True

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

        strtab_entry = self._find_dynamic_entry(DT_STRTAB)
        if not strtab_entry:
            return False

        dynstr_offset = self.map_vatr(strtab_entry.d_un)

        for symbol in self._symbol_table:
            name = self.read_string_to_null(dynstr_offset + symbol.st_name)
            if name == "g_CodeRegistration":
                code_registration = symbol.st_value
            elif name == "g_MetadataRegistration":
                metadata_registration = symbol.st_value

        if code_registration > 0 and metadata_registration > 0:
            print("Detected Symbol!")
            print(f"CodeRegistration : {code_registration:x}")
            print(f"MetadataRegistration : {metadata_registration:x}")
            self.init(code_registration, metadata_registration)
            return True

        print("ERROR: No symbol is detected")
        return False

    def get_section_helper(self, method_count: int, type_definitions_count: int, image_count: int) -> 'SectionHelper':
        """Get section helper for searching."""
        from .elf_structures import PT_LOAD

        data_list = []
        exec_list = []

        for phdr in self._program_segments:
            # Only process PT_LOAD segments with non-zero memory size
            if phdr.p_type == PT_LOAD and phdr.p_memsz != 0:
                section = SearchSection(
                    offset=phdr.p_offset,
                    offset_end=phdr.p_offset + phdr.p_filesz,
                    address=phdr.p_vaddr,
                    address_end=phdr.p_vaddr + phdr.p_memsz
                )

                if phdr.p_flags in [1, 3, 5, 7]:  # Executable (PF_X set)
                    exec_list.append(section)
                elif phdr.p_flags in [2, 4, 6]:  # Data (no PF_X)
                    data_list.append(section)

        helper = SectionHelper(self, method_count, type_definitions_count,
                               self._metadata_usages_count, image_count)
        helper.set_exec_sections(exec_list)
        helper.set_data_sections(data_list)
        helper.set_bss_sections(data_list)

        return helper

    def check_dump(self) -> bool:
        """Check if this is a memory dump."""
        return not self._check_section()

    def get_rva(self, pointer: int) -> int:
        """Get RVA."""
        if self.is_dumped:
            return pointer - self.image_base
        return pointer


class Elf64(ElfBase):
    """
    ELF64 format parser.

    Used for 64-bit Android and Linux IL2CPP binaries.
    """

    def __init__(self, data: bytes):
        super().__init__(data)
        self.is_32bit = False
        self._load()

    def _load(self) -> None:
        """Load ELF64 structures."""
        # Read ELF header
        self._elf_header = self._read_elf64_header()

        # Read program headers
        self._program_segments = self._read_elf64_phdrs()

        if self.is_dumped:
            self._fix_program_segments()

        # Find PT_DYNAMIC segment
        self._pt_dynamic = None
        for seg in self._program_segments:
            if seg.p_type == PT_DYNAMIC:
                self._pt_dynamic = seg
                break

        if self._pt_dynamic is None:
            raise ValueError("No PT_DYNAMIC segment found")

        # Read dynamic section
        self._dynamic_section = self._read_elf64_dynamic()

        if self.is_dumped:
            self._fix_dynamic_section()

        # Read symbols
        self._read_symbols()

        if not self.is_dumped:
            self._process_relocations()
            if self._check_protection():
                print("ERROR: This file may be protected.")

    def _read_elf64_header(self) -> Elf64_Ehdr:
        """Read ELF64 header."""
        self.position = 0
        header = Elf64_Ehdr()
        header.e_ident = self.read_bytes(16)
        header.e_type = self.read_uint16()
        header.e_machine = self.read_uint16()
        header.e_version = self.read_uint32()
        header.e_entry = self.read_uint64()
        header.e_phoff = self.read_uint64()
        header.e_shoff = self.read_uint64()
        header.e_flags = self.read_uint32()
        header.e_ehsize = self.read_uint16()
        header.e_phentsize = self.read_uint16()
        header.e_phnum = self.read_uint16()
        header.e_shentsize = self.read_uint16()
        header.e_shnum = self.read_uint16()
        header.e_shstrndx = self.read_uint16()
        return header

    def _read_elf64_phdrs(self) -> List[Elf64_Phdr]:
        """Read ELF64 program headers."""
        self.position = self._elf_header.e_phoff
        segments = []
        for _ in range(self._elf_header.e_phnum):
            phdr = Elf64_Phdr()
            phdr.p_type = self.read_uint32()
            phdr.p_flags = self.read_uint32()
            phdr.p_offset = self.read_uint64()
            phdr.p_vaddr = self.read_uint64()
            phdr.p_paddr = self.read_uint64()
            phdr.p_filesz = self.read_uint64()
            phdr.p_memsz = self.read_uint64()
            phdr.p_align = self.read_uint64()
            segments.append(phdr)
        return segments

    def _read_elf64_dynamic(self) -> List[Elf64_Dyn]:
        """Read ELF64 dynamic section."""
        self.position = self._pt_dynamic.p_offset
        count = self._pt_dynamic.p_filesz // 16
        entries = []
        for _ in range(count):
            dyn = Elf64_Dyn()
            dyn.d_tag = self.read_int64()
            dyn.d_un = self.read_uint64()
            entries.append(dyn)
            if dyn.d_tag == 0:  # DT_NULL
                break
        return entries

    def _read_symbols(self) -> None:
        """Read symbol table."""
        try:
            # Find symbol count via hash table
            symbol_count = 0
            hash_entry = self._find_dynamic_entry(DT_HASH)
            if hash_entry:
                addr = self.map_vatr(hash_entry.d_un)
                self.position = addr
                nbucket = self.read_uint32()
                nchain = self.read_uint32()
                symbol_count = nchain
            else:
                # Try GNU hash
                hash_entry = self._find_dynamic_entry(DT_GNU_HASH)
                if hash_entry:
                    addr = self.map_vatr(hash_entry.d_un)
                    self.position = addr
                    nbuckets = self.read_uint32()
                    symoffset = self.read_uint32()
                    bloom_size = self.read_uint32()
                    bloom_shift = self.read_uint32()
                    buckets_address = addr + 16 + (8 * bloom_size)  # 8 bytes for 64-bit
                    self.position = buckets_address
                    buckets = [self.read_uint32() for _ in range(nbuckets)]
                    last_symbol = max(buckets) if buckets else 0
                    if last_symbol < symoffset:
                        symbol_count = symoffset
                    else:
                        chains_base = buckets_address + 4 * nbuckets
                        self.position = chains_base + (last_symbol - symoffset) * 4
                        while True:
                            chain_entry = self.read_uint32()
                            last_symbol += 1
                            if (chain_entry & 1) != 0:
                                break
                        symbol_count = last_symbol

            # Read symbols
            symtab_entry = self._find_dynamic_entry(DT_SYMTAB)
            if symtab_entry and symbol_count > 0:
                dynsym_offset = self.map_vatr(symtab_entry.d_un)
                self.position = dynsym_offset
                self._symbol_table = []
                for _ in range(symbol_count):
                    sym = Elf64_Sym()
                    sym.st_name = self.read_uint32()
                    sym.st_info = self.read_byte()
                    sym.st_other = self.read_byte()
                    sym.st_shndx = self.read_uint16()
                    sym.st_value = self.read_uint64()
                    sym.st_size = self.read_uint64()
                    self._symbol_table.append(sym)
        except Exception:
            pass

    def _find_dynamic_entry(self, tag: int) -> Optional[Elf64_Dyn]:
        """Find a dynamic entry by tag."""
        for entry in self._dynamic_section:
            if entry.d_tag == tag:
                return entry
        return None

    def _process_relocations(self) -> None:
        """Process relocations for ELF64."""
        print("Applying relocations...")
        try:
            rela_entry = self._find_dynamic_entry(DT_RELA)
            relasz_entry = self._find_dynamic_entry(DT_RELASZ)
            if not rela_entry or not relasz_entry:
                return

            rela_offset = self.map_vatr(rela_entry.d_un)
            rela_size = relasz_entry.d_un
            count = rela_size // 24  # sizeof(Elf64_Rela) = 24

            is_aarch64 = self._elf_header.e_machine == EM_AARCH64
            is_x86_64 = self._elf_header.e_machine == EM_X86_64

            # Read all relocation data at once for speed
            self.position = rela_offset
            rela_data = self.read_bytes(rela_size)

            # Get raw buffer for direct writes (much faster than stream seeks)
            raw_buffer = self._stream.getvalue()
            if isinstance(raw_buffer, bytes):
                raw_buffer = bytearray(raw_buffer)
                # Replace stream with mutable version
                from io import BytesIO
                self._stream = BytesIO(raw_buffer)

            # Build segment mapping for fast VA->file offset lookup
            from .elf_structures import PT_LOAD
            seg_map = []
            for phdr in self._program_segments:
                if phdr.p_type == PT_LOAD:
                    seg_map.append((phdr.p_vaddr, phdr.p_vaddr + phdr.p_memsz, phdr.p_offset))

            def fast_map_va(va):
                for va_start, va_end, file_offset in seg_map:
                    if va_start <= va < va_end:
                        return va - va_start + file_offset
                return None

            import struct
            for i in range(count):
                offset = i * 24
                r_offset, r_info, r_addend = struct.unpack_from('<QQq', rela_data, offset)

                rel_type = r_info & 0xFFFFFFFF
                sym = r_info >> 32

                value = None

                if is_aarch64:
                    if rel_type == R_AARCH64_ABS64:
                        if sym < len(self._symbol_table):
                            value = self._symbol_table[sym].st_value + r_addend
                    elif rel_type == R_AARCH64_RELATIVE:
                        value = r_addend
                elif is_x86_64:
                    if rel_type == R_X86_64_64:
                        if sym < len(self._symbol_table):
                            value = self._symbol_table[sym].st_value + r_addend
                    elif rel_type == R_X86_64_RELATIVE:
                        value = r_addend

                if value is not None:
                    write_pos = fast_map_va(r_offset)
                    if write_pos is not None and write_pos + 8 <= len(raw_buffer):
                        struct.pack_into('<Q', raw_buffer, write_pos, value)

            # CRITICAL: Replace stream with the modified buffer
            # BytesIO copies the data, so we need to create a new stream with modified data
            from io import BytesIO
            self._stream = BytesIO(bytes(raw_buffer))
        except Exception:
            pass  # Silently ignore relocation errors

    def _check_protection(self) -> bool:
        """Check for protection."""
        try:
            if self._find_dynamic_entry(DT_INIT):
                print("WARNING: find .init_proc")
                return True

            strtab_entry = self._find_dynamic_entry(DT_STRTAB)
            if strtab_entry:
                dynstr_offset = self.map_vatr(strtab_entry.d_un)
                for symbol in self._symbol_table:
                    name = self.read_string_to_null(dynstr_offset + symbol.st_name)
                    if name == "JNI_OnLoad":
                        print("WARNING: find JNI_OnLoad")
                        return True
        except Exception:
            pass
        return False

    def _check_section(self) -> bool:
        """Check if sections are valid."""
        # Similar to Elf32
        return True

    def _fix_program_segments(self) -> None:
        """Fix program segments for memory dumps."""
        for phdr in self._program_segments:
            phdr.p_offset = phdr.p_vaddr
            phdr.p_vaddr += self.image_base
            phdr.p_filesz = phdr.p_memsz

    def _fix_dynamic_section(self) -> None:
        """Fix dynamic section for memory dumps."""
        for dyn in self._dynamic_section:
            if dyn.d_tag in [DT_PLTGOT, DT_HASH, DT_STRTAB, DT_SYMTAB,
                             7, DT_INIT, 13, DT_REL, 23, 25, 26]:
                dyn.d_un += self.image_base

    def map_vatr(self, addr: int) -> int:
        """Map virtual address to raw file offset."""
        for phdr in self._program_segments:
            if phdr.p_vaddr <= addr <= phdr.p_vaddr + phdr.p_memsz:
                return addr - phdr.p_vaddr + phdr.p_offset
        raise ValueError(f"Address 0x{addr:x} not in any segment")

    def map_rtva(self, addr: int) -> int:
        """Map raw file offset to virtual address."""
        for phdr in self._program_segments:
            if phdr.p_offset <= addr <= phdr.p_offset + phdr.p_filesz:
                return addr - phdr.p_offset + phdr.p_vaddr
        return 0

    def search(self) -> bool:
        """Search for registration using pattern matching."""
        return False  # TODO: Implement ARM64 pattern search

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

        strtab_entry = self._find_dynamic_entry(DT_STRTAB)
        if not strtab_entry:
            return False

        dynstr_offset = self.map_vatr(strtab_entry.d_un)

        for symbol in self._symbol_table:
            name = self.read_string_to_null(dynstr_offset + symbol.st_name)
            if name == "g_CodeRegistration":
                code_registration = symbol.st_value
            elif name == "g_MetadataRegistration":
                metadata_registration = symbol.st_value

        if code_registration > 0 and metadata_registration > 0:
            print("Detected Symbol!")
            print(f"CodeRegistration : {code_registration:x}")
            print(f"MetadataRegistration : {metadata_registration:x}")
            self.init(code_registration, metadata_registration)
            return True

        print("ERROR: No symbol is detected")
        return False

    def get_section_helper(self, method_count: int, type_definitions_count: int, image_count: int) -> 'SectionHelper':
        """Get section helper for searching."""
        from .elf_structures import PT_LOAD

        data_list = []
        exec_list = []

        for phdr in self._program_segments:
            # Only process PT_LOAD segments with non-zero memory size
            if phdr.p_type == PT_LOAD and phdr.p_memsz != 0:
                section = SearchSection(
                    offset=phdr.p_offset,
                    offset_end=phdr.p_offset + phdr.p_filesz,
                    address=phdr.p_vaddr,
                    address_end=phdr.p_vaddr + phdr.p_memsz
                )

                if phdr.p_flags in [1, 3, 5, 7]:  # Executable (PF_X set)
                    exec_list.append(section)
                elif phdr.p_flags in [2, 4, 6]:  # Data (no PF_X)
                    data_list.append(section)

        helper = SectionHelper(self, method_count, type_definitions_count,
                               self._metadata_usages_count, image_count)
        helper.set_exec_sections(exec_list)
        helper.set_data_sections(data_list)
        helper.set_bss_sections(data_list)

        return helper

    def check_dump(self) -> bool:
        """Check if this is a memory dump."""
        return not self._check_section()

    def get_rva(self, pointer: int) -> int:
        """Get RVA."""
        if self.is_dumped:
            return pointer - self.image_base
        return pointer
