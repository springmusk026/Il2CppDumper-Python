#!/usr/bin/env python3
"""
IL2CPP Dumper - Python Port

Command-line interface for extracting metadata from Unity IL2CPP compiled games.

Usage:
    il2cpp_dumper <executable-file> <global-metadata> [output-directory]
    il2cpp_dumper -h | --help
    il2cpp_dumper --version

Arguments:
    executable-file    Path to the IL2CPP binary (libil2cpp.so, GameAssembly.dll, etc.)
    global-metadata    Path to global-metadata.dat
    output-directory   Output directory for dump files (default: current directory)

Options:
    -h --help          Show this help message
    --version          Show version
"""

import sys
import argparse
from pathlib import Path
from typing import Optional, Tuple

from . import __version__
from .config import Config
from .il2cpp.metadata import Metadata, NotSupportedError
from .il2cpp.base import Il2Cpp
from .formats.elf import Elf, Elf64
from .formats.pe import PE
from .formats.macho import Macho, Macho64, MachoFat
from .formats.nso import NSO
from .formats.wasm import WebAssembly
from .executor.il2cpp_executor import Il2CppExecutor
from .output.decompiler import Il2CppDecompiler
from .output.struct_generator import StructGenerator


# Magic numbers for format detection
MAGIC_METADATA = 0xFAB11BAF
MAGIC_PE = 0x905A4D
MAGIC_ELF = 0x464C457F
MAGIC_MACHO_FAT_BE = 0xCAFEBABE
MAGIC_MACHO_FAT_LE = 0xBEBAFECA
MAGIC_MACHO64 = 0xFEEDFACF
MAGIC_MACHO32 = 0xFEEDFACE
MAGIC_NSO = 0x304F534E
MAGIC_WASM = 0x6D736100


def detect_files(args: list) -> Tuple[Optional[str], Optional[str], str]:
    """
    Detect which file is the IL2CPP binary and which is the metadata.

    Args:
        args: List of file paths

    Returns:
        Tuple of (il2cpp_path, metadata_path, output_dir)
    """
    il2cpp_path = None
    metadata_path = None
    output_dir = "."

    for arg in args:
        path = Path(arg)

        if path.is_file():
            # Read first 4 bytes to detect file type
            with open(path, 'rb') as f:
                magic = int.from_bytes(f.read(4), 'little')

            if magic == MAGIC_METADATA:
                metadata_path = str(path)
            else:
                il2cpp_path = str(path)
        elif path.is_dir():
            output_dir = str(path)

    return il2cpp_path, metadata_path, output_dir


def create_il2cpp_parser(data: bytes) -> Il2Cpp:
    """
    Create the appropriate IL2CPP parser based on file format.

    Args:
        data: Binary data

    Returns:
        IL2CPP parser instance

    Raises:
        ValueError: If format is not supported
    """
    magic = int.from_bytes(data[:4], 'little')

    if magic == MAGIC_ELF:
        # Check if 32-bit or 64-bit
        if data[4] == 2:  # ELF64
            print("Detected ELF64 format")
            return Elf64(data)
        else:
            print("Detected ELF32 format")
            return Elf(data)

    elif magic == MAGIC_PE:
        # PE format (Windows)
        print("Detected PE format")
        return PE(data)

    elif magic in (MAGIC_MACHO_FAT_BE, MAGIC_MACHO_FAT_LE):
        # FAT Mach-O (iOS/macOS universal binary)
        print("Detected FAT Mach-O (Universal binary) format")
        fat = MachoFat(data)
        print(f"Found {len(fat.fats)} architectures:")
        for i, (slice_magic, arch) in enumerate(fat.fats):
            arch_name = "64-bit" if slice_magic == MAGIC_MACHO64 else "32-bit"
            print(f"  {i}: {arch_name} (cputype: 0x{arch.cputype:x})")

        # Prefer 64-bit architecture
        chosen_idx = 0
        for i, (slice_magic, _) in enumerate(fat.fats):
            if slice_magic == MAGIC_MACHO64:
                chosen_idx = i
                break

        print(f"Using architecture {chosen_idx}")
        slice_data = fat.get_macho(chosen_idx)
        slice_magic, _ = fat.fats[chosen_idx]

        if slice_magic == MAGIC_MACHO64:
            return Macho64(slice_data)
        else:
            return Macho(slice_data)

    elif magic == MAGIC_MACHO64:
        # 64-bit Mach-O
        print("Detected Mach-O 64-bit format")
        return Macho64(data)

    elif magic == MAGIC_MACHO32:
        # 32-bit Mach-O
        print("Detected Mach-O 32-bit format")
        return Macho(data)

    elif magic == MAGIC_NSO:
        # Nintendo Switch NSO
        print("Detected NSO (Nintendo Switch) format")
        return NSO(data)

    elif magic == MAGIC_WASM:
        # WebAssembly
        print("Detected WebAssembly (WASM) format")
        return WebAssembly(data)

    else:
        raise ValueError(f"Unsupported IL2CPP binary format (magic: 0x{magic:08X})")


def init(il2cpp_path: str, metadata_path: str, config: Config) -> Tuple[Metadata, Il2Cpp]:
    """
    Initialize metadata and IL2CPP binary.

    Args:
        il2cpp_path: Path to IL2CPP binary
        metadata_path: Path to metadata file
        config: Configuration

    Returns:
        Tuple of (Metadata, Il2Cpp)
    """
    print("Initializing metadata...")
    metadata_bytes = Path(metadata_path).read_bytes()
    metadata = Metadata(metadata_bytes)
    print(f"Metadata Version: {metadata.version}")

    print("Initializing il2cpp file...")
    il2cpp_bytes = Path(il2cpp_path).read_bytes()
    il2cpp = create_il2cpp_parser(il2cpp_bytes)

    # Set version
    version = config.force_version if config.force_il2cpp_version else metadata.version
    il2cpp.set_properties(version, metadata.metadata_usages_count)
    print(f"Il2Cpp Version: {il2cpp.version}")

    # Check for memory dump
    if config.force_dump or il2cpp.check_dump():
        from .formats.elf import ElfBase
        if isinstance(il2cpp, ElfBase):
            print("Detected this may be a dump file.")
            print("Input il2cpp dump address or input 0 to force continue:")
            try:
                dump_addr_str = input()
                dump_addr = int(dump_addr_str, 16)
                if dump_addr != 0:
                    il2cpp.image_base = dump_addr
                    il2cpp.is_dumped = True
                    if not config.no_redirected_pointer:
                        il2cpp.reload()
            except ValueError:
                pass
        else:
            il2cpp.is_dumped = True

    # Search for registration structures
    print("Searching...")
    method_count = sum(1 for m in metadata.method_defs if m.method_index >= 0)

    found = il2cpp.plus_search(method_count, len(metadata.type_defs), len(metadata.image_defs))

    if not found:
        found = il2cpp.search()

    if not found:
        found = il2cpp.symbol_search()

    if not found:
        print("ERROR: Can't use auto mode to process file, try manual mode.")
        print("Input CodeRegistration: ", end="")
        code_reg_str = input()
        print("Input MetadataRegistration: ", end="")
        meta_reg_str = input()
        try:
            code_registration = int(code_reg_str, 16)
            metadata_registration = int(meta_reg_str, 16)
            il2cpp.init(code_registration, metadata_registration)
        except ValueError:
            raise ValueError("Invalid address input")

    # Handle v27+ dumped files
    if il2cpp.version >= 27 and il2cpp.is_dumped:
        type_def = metadata.type_defs[0]
        il2cpp_type = il2cpp.types[type_def.byval_type_index]
        metadata.image_base = il2cpp_type.type_handle - metadata.header.type_definitions_offset

    return metadata, il2cpp


def dump(metadata: Metadata, il2cpp: Il2Cpp, output_dir: str, config: Config) -> None:
    """
    Perform the dump operation.

    Args:
        metadata: Parsed metadata
        il2cpp: Parsed IL2CPP binary
        output_dir: Output directory
        config: Configuration
    """
    print("Dumping...")
    executor = Il2CppExecutor(metadata, il2cpp)
    decompiler = Il2CppDecompiler(executor)
    decompiler.decompile(config, output_dir)
    print("Done!")

    if config.generate_struct:
        print("Generate struct...")
        struct_generator = StructGenerator(executor)
        struct_generator.write_script(output_dir)
        print("Done!")

    if config.generate_dummy_dll:
        print("Generate dummy dll... (not yet implemented in Python port)")
        # TODO: This requires a .NET assembly generator
        print("Skipped (requires .NET)")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="IL2CPP Dumper - Extract metadata from Unity IL2CPP games",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('files', nargs='*', help='IL2CPP binary, metadata file, and/or output directory')
    parser.add_argument('--version', action='version', version=f'il2cpp_dumper {__version__}')
    parser.add_argument('--config', type=str, help='Path to config.json')

    args = parser.parse_args()

    if len(args.files) < 2:
        parser.print_help()
        print("\nERROR: Both IL2CPP binary and global-metadata.dat are required")
        sys.exit(1)

    # Load config
    config_path = Path(args.config) if args.config else None
    config = Config.load(config_path)

    # Detect files
    il2cpp_path, metadata_path, output_dir = detect_files(args.files)

    if il2cpp_path is None:
        print("ERROR: IL2CPP binary not found")
        sys.exit(1)

    if metadata_path is None:
        print("ERROR: Metadata file not found or encrypted")
        sys.exit(1)

    # Ensure output directory exists
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    try:
        metadata, il2cpp = init(il2cpp_path, metadata_path, config)
        dump(metadata, il2cpp, output_dir, config)
    except NotSupportedError as e:
        print(f"ERROR: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    if config.require_any_key:
        try:
            input("Press Enter to exit...")
        except EOFError:
            pass  # Non-interactive mode


if __name__ == "__main__":
    main()
