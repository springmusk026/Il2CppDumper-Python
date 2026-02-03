"""
Mach-O format structure definitions for macOS/iOS binaries.
"""

from dataclasses import dataclass
from typing import List


# Mach-O Magic numbers
MH_MAGIC = 0xFEEDFACE     # 32-bit
MH_CIGAM = 0xCEFAEDFE     # 32-bit byte-swapped
MH_MAGIC_64 = 0xFEEDFACF  # 64-bit
MH_CIGAM_64 = 0xCFFAEDFE  # 64-bit byte-swapped
FAT_MAGIC = 0xCAFEBABE    # Universal binary
FAT_CIGAM = 0xBEBAFECA    # Universal binary byte-swapped

# CPU types
CPU_TYPE_X86 = 0x00000007
CPU_TYPE_X86_64 = 0x01000007
CPU_TYPE_ARM = 0x0000000C
CPU_TYPE_ARM64 = 0x0100000C

# Load command types
LC_SEGMENT = 0x1
LC_SYMTAB = 0x2
LC_SYMSEG = 0x3
LC_THREAD = 0x4
LC_UNIXTHREAD = 0x5
LC_LOADFVMLIB = 0x6
LC_IDFVMLIB = 0x7
LC_IDENT = 0x8
LC_FVMFILE = 0x9
LC_PREPAGE = 0xA
LC_DYSYMTAB = 0xB
LC_LOAD_DYLIB = 0xC
LC_ID_DYLIB = 0xD
LC_LOAD_DYLINKER = 0xE
LC_ID_DYLINKER = 0xF
LC_PREBOUND_DYLIB = 0x10
LC_ROUTINES = 0x11
LC_SUB_FRAMEWORK = 0x12
LC_SUB_UMBRELLA = 0x13
LC_SUB_CLIENT = 0x14
LC_SUB_LIBRARY = 0x15
LC_TWOLEVEL_HINTS = 0x16
LC_PREBIND_CKSUM = 0x17
LC_SEGMENT_64 = 0x19
LC_ROUTINES_64 = 0x1A
LC_UUID = 0x1B
LC_ENCRYPTION_INFO = 0x21
LC_ENCRYPTION_INFO_64 = 0x2C
LC_DYLD_INFO = 0x22
LC_DYLD_INFO_ONLY = 0x80000022
LC_FUNCTION_STARTS = 0x26
LC_MAIN = 0x80000028

# Section types
S_REGULAR = 0x0
S_ZEROFILL = 0x1
S_CSTRING_LITERALS = 0x2
S_4BYTE_LITERALS = 0x3
S_8BYTE_LITERALS = 0x4
S_LITERAL_POINTERS = 0x5
S_NON_LAZY_SYMBOL_POINTERS = 0x6
S_LAZY_SYMBOL_POINTERS = 0x7
S_SYMBOL_STUBS = 0x8
S_MOD_INIT_FUNC_POINTERS = 0x9
S_MOD_TERM_FUNC_POINTERS = 0xA
S_COALESCED = 0xB
S_GB_ZEROFILL = 0xC
S_INTERPOSING = 0xD
S_16BYTE_LITERALS = 0xE

# Section attributes
S_ATTR_PURE_INSTRUCTIONS = 0x80000000
S_ATTR_NO_TOC = 0x40000000
S_ATTR_STRIP_STATIC_SYMS = 0x20000000
S_ATTR_NO_DEAD_STRIP = 0x10000000
S_ATTR_LIVE_SUPPORT = 0x08000000
S_ATTR_SELF_MODIFYING_CODE = 0x04000000
S_ATTR_DEBUG = 0x02000000
S_ATTR_SOME_INSTRUCTIONS = 0x00000400
S_ATTR_EXT_RELOC = 0x00000200
S_ATTR_LOC_RELOC = 0x00000100


@dataclass
class FatHeader:
    """Universal binary header."""
    magic: int = 0
    nfat_arch: int = 0


@dataclass
class FatArch:
    """Universal binary architecture entry."""
    cputype: int = 0
    cpusubtype: int = 0
    offset: int = 0
    size: int = 0
    align: int = 0


@dataclass
class MachHeader:
    """32-bit Mach-O header."""
    magic: int = 0
    cputype: int = 0
    cpusubtype: int = 0
    filetype: int = 0
    ncmds: int = 0
    sizeofcmds: int = 0
    flags: int = 0


@dataclass
class MachHeader64:
    """64-bit Mach-O header."""
    magic: int = 0
    cputype: int = 0
    cpusubtype: int = 0
    filetype: int = 0
    ncmds: int = 0
    sizeofcmds: int = 0
    flags: int = 0
    reserved: int = 0


@dataclass
class LoadCommand:
    """Load command header."""
    cmd: int = 0
    cmdsize: int = 0


@dataclass
class SegmentCommand:
    """32-bit segment load command."""
    cmd: int = 0
    cmdsize: int = 0
    segname: str = ""  # 16 bytes
    vmaddr: int = 0
    vmsize: int = 0
    fileoff: int = 0
    filesize: int = 0
    maxprot: int = 0
    initprot: int = 0
    nsects: int = 0
    flags: int = 0


@dataclass
class SegmentCommand64:
    """64-bit segment load command."""
    cmd: int = 0
    cmdsize: int = 0
    segname: str = ""  # 16 bytes
    vmaddr: int = 0
    vmsize: int = 0
    fileoff: int = 0
    filesize: int = 0
    maxprot: int = 0
    initprot: int = 0
    nsects: int = 0
    flags: int = 0


@dataclass
class MachoSection:
    """32-bit section."""
    sectname: str = ""  # 16 bytes
    segname: str = ""   # 16 bytes
    addr: int = 0
    size: int = 0
    offset: int = 0
    align: int = 0
    reloff: int = 0
    nreloc: int = 0
    flags: int = 0
    reserved1: int = 0
    reserved2: int = 0


@dataclass
class MachoSection64Bit:
    """64-bit section."""
    sectname: str = ""  # 16 bytes
    segname: str = ""   # 16 bytes
    addr: int = 0
    size: int = 0
    offset: int = 0
    align: int = 0
    reloff: int = 0
    nreloc: int = 0
    flags: int = 0
    reserved1: int = 0
    reserved2: int = 0
    reserved3: int = 0


@dataclass
class SymtabCommand:
    """Symbol table load command."""
    cmd: int = 0
    cmdsize: int = 0
    symoff: int = 0
    nsyms: int = 0
    stroff: int = 0
    strsize: int = 0


@dataclass
class DysymtabCommand:
    """Dynamic symbol table load command."""
    cmd: int = 0
    cmdsize: int = 0
    ilocalsym: int = 0
    nlocalsym: int = 0
    iextdefsym: int = 0
    nextdefsym: int = 0
    iundefsym: int = 0
    nundefsym: int = 0
    tocoff: int = 0
    ntoc: int = 0
    modtaboff: int = 0
    nmodtab: int = 0
    extrefsymoff: int = 0
    nextrefsyms: int = 0
    indirectsymoff: int = 0
    nindirectsyms: int = 0
    extreloff: int = 0
    nextrel: int = 0
    locreloff: int = 0
    nlocrel: int = 0


@dataclass
class Nlist:
    """32-bit symbol table entry."""
    n_strx: int = 0   # index into string table
    n_type: int = 0   # type flag
    n_sect: int = 0   # section number
    n_desc: int = 0   # description
    n_value: int = 0  # value


@dataclass
class Nlist64:
    """64-bit symbol table entry."""
    n_strx: int = 0
    n_type: int = 0
    n_sect: int = 0
    n_desc: int = 0
    n_value: int = 0


@dataclass
class EncryptionInfoCommand:
    """Encryption info load command."""
    cmd: int = 0
    cmdsize: int = 0
    cryptoff: int = 0
    cryptsize: int = 0
    cryptid: int = 0


@dataclass
class EncryptionInfoCommand64:
    """64-bit encryption info load command."""
    cmd: int = 0
    cmdsize: int = 0
    cryptoff: int = 0
    cryptsize: int = 0
    cryptid: int = 0
    pad: int = 0
