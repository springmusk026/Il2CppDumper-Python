"""
Abstract base class for IL2CPP binary parsing.

This module defines the interface that all executable format parsers must implement.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Tuple, Type, TypeVar, Any
from io import BytesIO

from ..io.binary_stream import BinaryStream
from .structures import (
    Il2CppCodeRegistration,
    Il2CppMetadataRegistration,
    Il2CppType,
    Il2CppGenericInst,
    Il2CppMethodSpec,
    Il2CppGenericMethodFunctionsDefinitions,
    Il2CppCodeGenModule,
    Il2CppRGCTXDefinition,
    Il2CppTokenRangePair,
)

T = TypeVar('T')


class Il2Cpp(BinaryStream, ABC):
    """
    Abstract base class for IL2CPP binary parsing.

    This class defines the interface for parsing IL2CPP compiled binaries
    across different executable formats (ELF, PE, Mach-O, etc.).

    Subclasses must implement:
    - map_vatr(): Map virtual address to raw file offset
    - map_rtva(): Map raw file offset to virtual address
    - search(): Pattern-based registration search
    - plus_search(): Modern registration search
    - symbol_search(): Symbol table based search
    - get_section_helper(): Get section helper for searching
    - check_dump(): Check if file is a memory dump

    Attributes:
        method_pointers: Array of method code pointers
        generic_method_pointers: Array of generic method pointers
        invoker_pointers: Array of invoker function pointers
        types: Array of IL2CPP types
        method_specs: Array of method specifications
        is_dumped: Whether the binary is a memory dump
    """

    def __init__(self, data: bytes):
        """Initialize the IL2CPP parser."""
        super().__init__(data)

        # Registration structures
        self._code_registration: Optional[Il2CppCodeRegistration] = None
        self._metadata_registration: Optional[Il2CppMetadataRegistration] = None

        # Method and type data
        self.method_pointers: List[int] = []
        self.generic_method_pointers: List[int] = []
        self.invoker_pointers: List[int] = []
        self.custom_attribute_generators: List[int] = []
        self.reverse_pinvoke_wrappers: List[int] = []
        self.unresolved_virtual_call_pointers: List[int] = []

        # Type data
        self.types: List[Il2CppType] = []
        self._type_dic: Dict[int, Il2CppType] = {}
        self.metadata_usages: List[int] = []

        # Field offsets
        self._field_offsets: List[int] = []
        self._field_offsets_are_pointers: bool = False

        # Generic data
        self.generic_inst_pointers: List[int] = []
        self.generic_insts: List[Il2CppGenericInst] = []
        self._generic_method_table: List[Il2CppGenericMethodFunctionsDefinitions] = []
        self.method_specs: List[Il2CppMethodSpec] = []
        self.method_definition_method_specs: Dict[int, List[Il2CppMethodSpec]] = {}
        self.method_spec_generic_method_pointers: Dict[int, int] = {}

        # Code gen modules (v24.2+)
        self.code_gen_modules: Dict[str, Il2CppCodeGenModule] = {}
        self.code_gen_module_method_pointers: Dict[str, List[int]] = {}
        self.rgctxs_dictionary: Dict[str, Dict[int, List[Il2CppRGCTXDefinition]]] = {}

        # State flags
        self.is_dumped: bool = False
        self._metadata_usages_count: int = 0

    # ========== Abstract Methods ==========

    @abstractmethod
    def map_vatr(self, addr: int) -> int:
        """
        Map a virtual address to a raw file offset.

        Args:
            addr: Virtual address

        Returns:
            Raw file offset

        Raises:
            ValueError: If address is not in any segment
        """
        pass

    @abstractmethod
    def map_rtva(self, addr: int) -> int:
        """
        Map a raw file offset to a virtual address.

        Args:
            addr: Raw file offset

        Returns:
            Virtual address
        """
        pass

    @abstractmethod
    def search(self) -> bool:
        """
        Search for registration structures using pattern matching.

        Returns:
            True if registration structures were found
        """
        pass

    @abstractmethod
    def plus_search(self, method_count: int, type_definitions_count: int, image_count: int) -> bool:
        """
        Search for registration structures using modern algorithm.

        Args:
            method_count: Number of methods
            type_definitions_count: Number of type definitions
            image_count: Number of images

        Returns:
            True if registration structures were found
        """
        pass

    @abstractmethod
    def symbol_search(self) -> bool:
        """
        Search for registration structures using symbol table.

        Returns:
            True if registration structures were found
        """
        pass

    @abstractmethod
    def get_section_helper(self, method_count: int, type_definitions_count: int, image_count: int):
        """
        Get a section helper for searching.

        Args:
            method_count: Number of methods
            type_definitions_count: Number of type definitions
            image_count: Number of images

        Returns:
            A SectionHelper instance
        """
        pass

    @abstractmethod
    def check_dump(self) -> bool:
        """
        Check if this binary appears to be a memory dump.

        Returns:
            True if this appears to be a memory dump
        """
        pass

    # ========== Initialization ==========

    def set_properties(self, version: float, metadata_usages_count: int) -> None:
        """
        Set version and metadata usage count.

        Args:
            version: IL2CPP version
            metadata_usages_count: Number of metadata usages
        """
        self.version = version
        self._metadata_usages_count = metadata_usages_count

    def init(self, code_registration: int, metadata_registration: int) -> None:
        """
        Initialize with registration structure addresses.

        Args:
            code_registration: Address of Il2CppCodeRegistration
            metadata_registration: Address of Il2CppMetadataRegistration
        """
        # Read registration structures
        self._code_registration = self.map_vatr_class(Il2CppCodeRegistration, code_registration)

        # Version detection based on structure values
        self._detect_version_from_registration(code_registration)

        self._metadata_registration = self.map_vatr_class(Il2CppMetadataRegistration, metadata_registration)

        # Read pointer arrays
        self._load_pointers()

        # Read types
        self._load_types()

        # Read generic data
        self._load_generics()

        # Load code gen modules (v24.2+)
        if self.version >= 24.2:
            self._load_code_gen_modules()

    def _detect_version_from_registration(self, code_registration: int) -> None:
        """Detect version based on registration structure values."""
        cr = self._code_registration
        limit = 0x50000

        if self.version == 27 and cr.invoker_pointers_count > limit:
            self.version = 27.1
            print(f"Change il2cpp version to: {self.version}")
            self._code_registration = self.map_vatr_class(Il2CppCodeRegistration, code_registration)

        if self.version == 24.4 and cr.invoker_pointers_count > limit:
            self.version = 24.5
            print(f"Change il2cpp version to: {self.version}")
            self._code_registration = self.map_vatr_class(Il2CppCodeRegistration, code_registration)

        if self.version == 24.2 and cr.code_gen_modules == 0:
            self.version = 24.3
            print(f"Change il2cpp version to: {self.version}")
            self._code_registration = self.map_vatr_class(Il2CppCodeRegistration, code_registration)

    def _load_pointers(self) -> None:
        """Load method and invoker pointers."""
        cr = self._code_registration
        mr = self._metadata_registration

        # Generic method pointers
        if cr.generic_method_pointers_count > 0:
            self.generic_method_pointers = self.map_vatr_array(
                cr.generic_method_pointers, cr.generic_method_pointers_count
            )

        # Invoker pointers
        if cr.invoker_pointers_count > 0:
            self.invoker_pointers = self.map_vatr_array(
                cr.invoker_pointers, cr.invoker_pointers_count
            )

        # Custom attribute generators (v < 27)
        if self.version < 27 and cr.custom_attribute_count > 0:
            self.custom_attribute_generators = self.map_vatr_array(
                cr.custom_attribute_generators, cr.custom_attribute_count
            )

        # Metadata usages (v17-26)
        if 16 < self.version < 27 and self._metadata_usages_count > 0:
            self.metadata_usages = self.map_vatr_array(
                mr.metadata_usages, self._metadata_usages_count
            )

        # Reverse P/Invoke wrappers (v22+)
        if self.version >= 22 and cr.reverse_pinvoke_wrapper_count > 0:
            self.reverse_pinvoke_wrappers = self.map_vatr_array(
                cr.reverse_pinvoke_wrappers, cr.reverse_pinvoke_wrapper_count
            )

        # Unresolved virtual calls (v22+)
        if self.version >= 22 and cr.unresolved_virtual_call_count > 0:
            self.unresolved_virtual_call_pointers = self.map_vatr_array(
                cr.unresolved_virtual_call_pointers, cr.unresolved_virtual_call_count
            )

    def _load_types(self) -> None:
        """Load IL2CPP types."""
        mr = self._metadata_registration

        # Read type pointers
        type_pointers = self.map_vatr_array(mr.types, mr.types_count)

        # Read all types at once using batch reading
        # Il2CppType is 12 bytes: ulong (8) + uint (4)
        self.types = []
        type_data_list = []

        # Batch read raw data for all types
        for ptr in type_pointers:
            offset = self.map_vatr(ptr)
            self.position = offset
            data = self.read_bytes(12)
            type_data_list.append((ptr, data))

        # Parse all types
        import struct
        for ptr, data in type_data_list:
            datapoint, bits = struct.unpack('<QI', data)
            il2cpp_type = Il2CppType()
            il2cpp_type.datapoint = datapoint
            il2cpp_type.bits = bits
            il2cpp_type.init(self.version)
            self.types.append(il2cpp_type)
            self._type_dic[ptr] = il2cpp_type

        # Field offsets
        self._field_offsets_are_pointers = self.version > 21
        if self.version == 21:
            # Heuristic check
            test = self.map_vatr_array(mr.field_offsets, min(6, mr.field_offsets_count))
            self._field_offsets_are_pointers = (
                test[0] == 0 and test[1] == 0 and test[2] == 0 and
                test[3] == 0 and test[4] == 0 and test[5] > 0
            )

        if self._field_offsets_are_pointers:
            self._field_offsets = self.map_vatr_array(mr.field_offsets, mr.field_offsets_count)
        else:
            self._field_offsets = list(self.map_vatr_uint32_array(mr.field_offsets, mr.field_offsets_count))

    def _load_generics(self) -> None:
        """Load generic type and method data."""
        import struct as st
        mr = self._metadata_registration

        # Generic instances - batch read
        self.generic_inst_pointers = self.map_vatr_array(mr.generic_insts, mr.generic_insts_count)

        # Il2CppGenericInst is 16 bytes (2 pointers)
        self.generic_insts = []
        for ptr in self.generic_inst_pointers:
            offset = self.map_vatr(ptr)
            self.position = offset
            data = self.read_bytes(16)
            type_argc, type_argv = st.unpack('<QQ', data)
            gi = Il2CppGenericInst()
            gi.type_argc = type_argc
            gi.type_argv = type_argv
            self.generic_insts.append(gi)

        # Generic method table - use fast batch reading
        self.position = self.map_vatr(mr.generic_method_table)
        self._generic_method_table = self.read_class_array_fast(
            Il2CppGenericMethodFunctionsDefinitions,
            count=mr.generic_method_table_count
        )

        # Method specs - batch read (12 bytes each: 3 x int32)
        self.position = self.map_vatr(mr.method_specs)
        if mr.method_specs_count > 0:
            data = self.read_bytes(mr.method_specs_count * 12)
            self.method_specs = []
            for i in range(mr.method_specs_count):
                offset = i * 12
                values = st.unpack('<iii', data[offset:offset + 12])
                ms = Il2CppMethodSpec()
                ms.method_definition_index = values[0]
                ms.class_index_index = values[1]
                ms.method_index_index = values[2]
                self.method_specs.append(ms)
        else:
            self.method_specs = []

        # Build method spec lookup
        for table in self._generic_method_table:
            method_spec = self.method_specs[table.generic_method_index]
            method_def_index = method_spec.method_definition_index

            if method_def_index not in self.method_definition_method_specs:
                self.method_definition_method_specs[method_def_index] = []

            self.method_definition_method_specs[method_def_index].append(method_spec)

            # Map to generic method pointer
            if table.indices and len(self.generic_method_pointers) > table.indices.method_index:
                self.method_spec_generic_method_pointers[id(method_spec)] = \
                    self.generic_method_pointers[table.indices.method_index]

    def _load_code_gen_modules(self) -> None:
        """Load code generation modules (v24.2+)."""
        cr = self._code_registration

        module_pointers = self.map_vatr_array(cr.code_gen_modules, cr.code_gen_modules_count)

        for ptr in module_pointers:
            module = self.map_vatr_class(Il2CppCodeGenModule, ptr)
            module_name = self.read_string_to_null(self.map_vatr(module.module_name))

            self.code_gen_modules[module_name] = module

            # Method pointers
            try:
                method_ptrs = self.map_vatr_array(module.method_pointers, module.method_pointer_count)
            except:
                method_ptrs = [0] * module.method_pointer_count

            self.code_gen_module_method_pointers[module_name] = method_ptrs

            # RGCTX data
            rgctx_def_dic: Dict[int, List[Il2CppRGCTXDefinition]] = {}
            self.rgctxs_dictionary[module_name] = rgctx_def_dic

            if module.rgctxs_count > 0:
                self.position = self.map_vatr(module.rgctxs)
                rgctxs = self.read_class_array_fast(Il2CppRGCTXDefinition, count=module.rgctxs_count)

                self.position = self.map_vatr(module.rgctx_ranges)
                rgctx_ranges = self.read_class_array_fast(Il2CppTokenRangePair, count=module.rgctx_ranges_count)

                for rgctx_range in rgctx_ranges:
                    if rgctx_range.range:
                        start = rgctx_range.range.start
                        length = rgctx_range.range.length
                        rgctx_def_dic[rgctx_range.token] = rgctxs[start:start + length]

    # ========== Helper Methods ==========

    def map_vatr_class(self, cls: Type[T], addr: int) -> T:
        """Read a class at a virtual address."""
        return self.read_class(cls, self.map_vatr(addr))

    def map_vatr_array(self, addr: int, count: int) -> List[int]:
        """Read an array of pointers at a virtual address."""
        return self.read_ptr_array(self.map_vatr(addr), count)

    def map_vatr_uint32_array(self, addr: int, count: int) -> List[int]:
        """Read an array of uint32 at a virtual address."""
        return self.read_uint32_array(self.map_vatr(addr), count)

    def get_il2cpp_type(self, pointer: int) -> Optional[Il2CppType]:
        """Get an IL2CPP type by its pointer."""
        return self._type_dic.get(pointer)

    def get_field_offset_from_index(
        self,
        type_index: int,
        field_index_in_type: int,
        field_index: int,
        is_value_type: bool,
        is_static: bool
    ) -> int:
        """
        Get field offset from indices.

        Args:
            type_index: Index of the type
            field_index_in_type: Field index within the type
            field_index: Global field index
            is_value_type: Whether the type is a value type
            is_static: Whether the field is static

        Returns:
            Field offset, or -1 if not found
        """
        try:
            offset = -1

            if self._field_offsets_are_pointers:
                ptr = self._field_offsets[type_index]
                if ptr > 0:
                    self.position = self.map_vatr(ptr) + 4 * field_index_in_type
                    offset = self.read_int32()
            else:
                offset = self._field_offsets[field_index]

            if offset > 0 and is_value_type and not is_static:
                # Adjust for value type header
                offset -= 8 if self.is_32bit else 16

            return offset
        except:
            return -1

    def get_method_pointer(self, image_name: str, method_def) -> int:
        """
        Get method pointer from method definition.

        Args:
            image_name: Name of the image/assembly
            method_def: Method definition

        Returns:
            Method pointer address, or 0 if not found
        """
        if self.version >= 24.2:
            method_token = method_def.token
            ptrs = self.code_gen_module_method_pointers.get(image_name, [])
            method_pointer_index = method_token & 0x00FFFFFF
            if method_pointer_index > 0 and method_pointer_index <= len(ptrs):
                return ptrs[method_pointer_index - 1]
        else:
            method_index = method_def.method_index
            if method_index >= 0 and method_index < len(self.method_pointers):
                return self.method_pointers[method_index]

        return 0

    def get_rva(self, pointer: int) -> int:
        """
        Get relative virtual address.

        Args:
            pointer: Virtual address

        Returns:
            RVA (for dumped files, subtracts image base)
        """
        return pointer

    def auto_plus_init(self, code_registration: int, metadata_registration: int) -> bool:
        """
        Auto-initialize with version detection.

        Args:
            code_registration: Code registration address
            metadata_registration: Metadata registration address

        Returns:
            True if initialization succeeded
        """
        if code_registration != 0:
            limit = 0x50000

            if self.version >= 24.2:
                self._code_registration = self.map_vatr_class(Il2CppCodeRegistration, code_registration)
                cr = self._code_registration

                # Version detection logic
                if self.version == 31 and cr.generic_method_pointers_count > limit:
                    code_registration -= self.pointer_size * 2
                elif self.version == 29 and cr.generic_method_pointers_count > limit:
                    self.version = 29.1
                    code_registration -= self.pointer_size * 2
                    print(f"Change il2cpp version to: {self.version}")
                elif self.version == 27 and cr.reverse_pinvoke_wrapper_count > limit:
                    self.version = 27.1
                    code_registration -= self.pointer_size
                    print(f"Change il2cpp version to: {self.version}")
                elif self.version == 24.4:
                    code_registration -= self.pointer_size * 2
                    if cr.reverse_pinvoke_wrapper_count > limit:
                        self.version = 24.5
                        code_registration -= self.pointer_size
                        print(f"Change il2cpp version to: {self.version}")
                elif self.version == 24.2 and cr.interop_data_count == 0:
                    self.version = 24.3
                    code_registration -= self.pointer_size * 2
                    print(f"Change il2cpp version to: {self.version}")

        print(f"CodeRegistration : {code_registration:x}")
        print(f"MetadataRegistration : {metadata_registration:x}")

        if code_registration != 0 and metadata_registration != 0:
            self.init(code_registration, metadata_registration)
            return True

        return False
