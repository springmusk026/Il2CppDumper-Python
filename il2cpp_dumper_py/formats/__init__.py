"""
Executable format parsers.

Supports:
- ELF (Linux, Android) - 32-bit and 64-bit
- PE (Windows) - 32-bit and 64-bit
- Mach-O (macOS, iOS) - 32-bit, 64-bit, and FAT/Universal binaries
- NSO (Nintendo Switch)
- WebAssembly (WebGL)
"""

from .elf import Elf, Elf64
from .pe import PE
from .macho import Macho, Macho64, MachoFat
from .nso import NSO
from .wasm import WebAssembly
from .elf_structures import *
from .pe_structures import *
from .macho_structures import *
from .nso_structures import *
from .wasm_structures import *

__all__ = ['Elf', 'Elf64', 'PE', 'Macho', 'Macho64', 'MachoFat', 'NSO', 'WebAssembly']
