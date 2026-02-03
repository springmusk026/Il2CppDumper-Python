"""
PE (Portable Executable) format structures for Windows binaries.
"""

from dataclasses import dataclass
from typing import List


# PE Constants
IMAGE_DOS_SIGNATURE = 0x5A4D  # MZ
IMAGE_NT_SIGNATURE = 0x00004550  # PE\0\0

# Machine types
IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_FILE_MACHINE_ARM = 0x01C0
IMAGE_FILE_MACHINE_ARM64 = 0xAA64

# Section characteristics
IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000

# Data directory indices
IMAGE_DIRECTORY_ENTRY_EXPORT = 0
IMAGE_DIRECTORY_ENTRY_IMPORT = 1
IMAGE_DIRECTORY_ENTRY_RESOURCE = 2
IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3
IMAGE_DIRECTORY_ENTRY_SECURITY = 4
IMAGE_DIRECTORY_ENTRY_BASERELOC = 5
IMAGE_DIRECTORY_ENTRY_DEBUG = 6
IMAGE_DIRECTORY_ENTRY_ARCHITECTURE = 7
IMAGE_DIRECTORY_ENTRY_GLOBALPTR = 8
IMAGE_DIRECTORY_ENTRY_TLS = 9
IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10
IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT = 11
IMAGE_DIRECTORY_ENTRY_IAT = 12
IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = 13
IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14


@dataclass
class ImageDosHeader:
    """DOS header (MZ header)."""
    e_magic: int = 0      # Magic number (MZ)
    e_cblp: int = 0       # Bytes on last page of file
    e_cp: int = 0         # Pages in file
    e_crlc: int = 0       # Relocations
    e_cparhdr: int = 0    # Size of header in paragraphs
    e_minalloc: int = 0   # Minimum extra paragraphs needed
    e_maxalloc: int = 0   # Maximum extra paragraphs needed
    e_ss: int = 0         # Initial (relative) SS value
    e_sp: int = 0         # Initial SP value
    e_csum: int = 0       # Checksum
    e_ip: int = 0         # Initial IP value
    e_cs: int = 0         # Initial (relative) CS value
    e_lfarlc: int = 0     # File address of relocation table
    e_ovno: int = 0       # Overlay number
    e_res: bytes = b''    # Reserved words (8 bytes)
    e_oemid: int = 0      # OEM identifier
    e_oeminfo: int = 0    # OEM information
    e_res2: bytes = b''   # Reserved words (20 bytes)
    e_lfanew: int = 0     # File address of new exe header


@dataclass
class ImageFileHeader:
    """COFF file header."""
    Machine: int = 0
    NumberOfSections: int = 0
    TimeDateStamp: int = 0
    PointerToSymbolTable: int = 0
    NumberOfSymbols: int = 0
    SizeOfOptionalHeader: int = 0
    Characteristics: int = 0


@dataclass
class ImageDataDirectory:
    """Data directory entry."""
    VirtualAddress: int = 0
    Size: int = 0


@dataclass
class ImageOptionalHeader32:
    """Optional header for 32-bit PE."""
    Magic: int = 0
    MajorLinkerVersion: int = 0
    MinorLinkerVersion: int = 0
    SizeOfCode: int = 0
    SizeOfInitializedData: int = 0
    SizeOfUninitializedData: int = 0
    AddressOfEntryPoint: int = 0
    BaseOfCode: int = 0
    BaseOfData: int = 0
    ImageBase: int = 0
    SectionAlignment: int = 0
    FileAlignment: int = 0
    MajorOperatingSystemVersion: int = 0
    MinorOperatingSystemVersion: int = 0
    MajorImageVersion: int = 0
    MinorImageVersion: int = 0
    MajorSubsystemVersion: int = 0
    MinorSubsystemVersion: int = 0
    Win32VersionValue: int = 0
    SizeOfImage: int = 0
    SizeOfHeaders: int = 0
    CheckSum: int = 0
    Subsystem: int = 0
    DllCharacteristics: int = 0
    SizeOfStackReserve: int = 0
    SizeOfStackCommit: int = 0
    SizeOfHeapReserve: int = 0
    SizeOfHeapCommit: int = 0
    LoaderFlags: int = 0
    NumberOfRvaAndSizes: int = 0
    DataDirectory: List[ImageDataDirectory] = None


@dataclass
class ImageOptionalHeader64:
    """Optional header for 64-bit PE (PE32+)."""
    Magic: int = 0
    MajorLinkerVersion: int = 0
    MinorLinkerVersion: int = 0
    SizeOfCode: int = 0
    SizeOfInitializedData: int = 0
    SizeOfUninitializedData: int = 0
    AddressOfEntryPoint: int = 0
    BaseOfCode: int = 0
    # Note: No BaseOfData in PE32+
    ImageBase: int = 0
    SectionAlignment: int = 0
    FileAlignment: int = 0
    MajorOperatingSystemVersion: int = 0
    MinorOperatingSystemVersion: int = 0
    MajorImageVersion: int = 0
    MinorImageVersion: int = 0
    MajorSubsystemVersion: int = 0
    MinorSubsystemVersion: int = 0
    Win32VersionValue: int = 0
    SizeOfImage: int = 0
    SizeOfHeaders: int = 0
    CheckSum: int = 0
    Subsystem: int = 0
    DllCharacteristics: int = 0
    SizeOfStackReserve: int = 0
    SizeOfStackCommit: int = 0
    SizeOfHeapReserve: int = 0
    SizeOfHeapCommit: int = 0
    LoaderFlags: int = 0
    NumberOfRvaAndSizes: int = 0
    DataDirectory: List[ImageDataDirectory] = None


@dataclass
class SectionHeader:
    """Section header."""
    Name: str = ""
    VirtualSize: int = 0
    VirtualAddress: int = 0
    SizeOfRawData: int = 0
    PointerToRawData: int = 0
    PointerToRelocations: int = 0
    PointerToLinenumbers: int = 0
    NumberOfRelocations: int = 0
    NumberOfLinenumbers: int = 0
    Characteristics: int = 0


@dataclass
class ImageExportDirectory:
    """Export directory."""
    Characteristics: int = 0
    TimeDateStamp: int = 0
    MajorVersion: int = 0
    MinorVersion: int = 0
    Name: int = 0
    Base: int = 0
    NumberOfFunctions: int = 0
    NumberOfNames: int = 0
    AddressOfFunctions: int = 0
    AddressOfNames: int = 0
    AddressOfNameOrdinals: int = 0
