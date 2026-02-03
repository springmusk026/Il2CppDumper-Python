"""
IL2CPP data structure definitions.

These dataclasses represent the binary structures found in IL2CPP compiled binaries
and metadata files. Fields marked with version_field() are only present in certain
IL2CPP versions.
"""

from dataclasses import dataclass, field
from typing import List, Optional
from ..io.version_aware import version_field


def array_field(length: int, default_factory=None):
    """Create a field for fixed-size arrays."""
    if default_factory is None:
        default_factory = lambda: b'\x00' * length
    return field(
        default_factory=default_factory,
        metadata={'array_length': length}
    )


def ushort_field(default: int = 0):
    """Create a field that should be read as unsigned short (2 bytes)."""
    return field(default=default, metadata={'binary_size': 2, 'unsigned': True})


def short_field(default: int = 0):
    """Create a field that should be read as signed short (2 bytes)."""
    return field(default=default, metadata={'binary_size': 2, 'unsigned': False})


def ulong_field(default: int = 0):
    """Create a field that should be read as unsigned long (8 bytes)."""
    return field(default=default, metadata={'binary_size': 8, 'unsigned': True})


def long_field(default: int = 0):
    """Create a field that should be read as signed long (8 bytes)."""
    return field(default=default, metadata={'binary_size': 8, 'unsigned': False})


def ptr_field(default: int = 0):
    """Create a pointer field (8 bytes) for 64-bit structures."""
    return field(default=default, metadata={'binary_size': 8, 'unsigned': True})


def ptr_version_field(min_ver: float = 0, max_ver: float = 99, default: int = 0):
    """Create a pointer field (8 bytes) with version constraints."""
    return version_field(min_ver=min_ver, max_ver=max_ver, default=default, binary_size=8, unsigned=True)


# ============================================================
# Metadata Structures (from global-metadata.dat)
# ============================================================

@dataclass
class Il2CppGlobalMetadataHeader:
    """Header of the global-metadata.dat file."""
    sanity: int = 0
    version: int = 0
    string_literal_offset: int = 0
    string_literal_size: int = 0
    string_literal_data_offset: int = 0
    string_literal_data_size: int = 0
    string_offset: int = 0
    string_size: int = 0
    events_offset: int = 0
    events_size: int = 0
    properties_offset: int = 0
    properties_size: int = 0
    methods_offset: int = 0
    methods_size: int = 0
    parameter_default_values_offset: int = 0
    parameter_default_values_size: int = 0
    field_default_values_offset: int = 0
    field_default_values_size: int = 0
    field_and_parameter_default_value_data_offset: int = 0
    field_and_parameter_default_value_data_size: int = 0
    field_marshaled_sizes_offset: int = 0
    field_marshaled_sizes_size: int = 0
    parameters_offset: int = 0
    parameters_size: int = 0
    fields_offset: int = 0
    fields_size: int = 0
    generic_parameters_offset: int = 0
    generic_parameters_size: int = 0
    generic_parameter_constraints_offset: int = 0
    generic_parameter_constraints_size: int = 0
    generic_containers_offset: int = 0
    generic_containers_size: int = 0
    nested_types_offset: int = 0
    nested_types_size: int = 0
    interfaces_offset: int = 0
    interfaces_size: int = 0
    vtable_methods_offset: int = 0
    vtable_methods_size: int = 0
    interface_offsets_offset: int = 0
    interface_offsets_size: int = 0
    type_definitions_offset: int = 0
    type_definitions_size: int = 0
    # Version <= 24.1
    rgctx_entries_offset: int = version_field(max_ver=24.1, default=0)
    rgctx_entries_count: int = version_field(max_ver=24.1, default=0)
    images_offset: int = 0
    images_size: int = 0
    assemblies_offset: int = 0
    assemblies_size: int = 0
    # Version 19-24.5
    metadata_usage_lists_offset: int = version_field(min_ver=19, max_ver=24.5, default=0)
    metadata_usage_lists_count: int = version_field(min_ver=19, max_ver=24.5, default=0)
    metadata_usage_pairs_offset: int = version_field(min_ver=19, max_ver=24.5, default=0)
    metadata_usage_pairs_count: int = version_field(min_ver=19, max_ver=24.5, default=0)
    # Version 19+
    field_refs_offset: int = version_field(min_ver=19, default=0)
    field_refs_size: int = version_field(min_ver=19, default=0)
    # Version 20+
    referenced_assemblies_offset: int = version_field(min_ver=20, default=0)
    referenced_assemblies_size: int = version_field(min_ver=20, default=0)
    # Version 21-27.2
    attributes_info_offset: int = version_field(min_ver=21, max_ver=27.2, default=0)
    attributes_info_count: int = version_field(min_ver=21, max_ver=27.2, default=0)
    attribute_types_offset: int = version_field(min_ver=21, max_ver=27.2, default=0)
    attribute_types_count: int = version_field(min_ver=21, max_ver=27.2, default=0)
    # Version 29+
    attribute_data_offset: int = version_field(min_ver=29, default=0)
    attribute_data_size: int = version_field(min_ver=29, default=0)
    attribute_data_range_offset: int = version_field(min_ver=29, default=0)
    attribute_data_range_size: int = version_field(min_ver=29, default=0)
    # Version 22+
    unresolved_virtual_call_parameter_types_offset: int = version_field(min_ver=22, default=0)
    unresolved_virtual_call_parameter_types_size: int = version_field(min_ver=22, default=0)
    unresolved_virtual_call_parameter_ranges_offset: int = version_field(min_ver=22, default=0)
    unresolved_virtual_call_parameter_ranges_size: int = version_field(min_ver=22, default=0)
    # Version 23+
    windows_runtime_type_names_offset: int = version_field(min_ver=23, default=0)
    windows_runtime_type_names_size: int = version_field(min_ver=23, default=0)
    # Version 27+
    windows_runtime_strings_offset: int = version_field(min_ver=27, default=0)
    windows_runtime_strings_size: int = version_field(min_ver=27, default=0)
    # Version 24+
    exported_type_definitions_offset: int = version_field(min_ver=24, default=0)
    exported_type_definitions_size: int = version_field(min_ver=24, default=0)


@dataclass
class Il2CppImageDefinition:
    """Assembly image definition."""
    name_index: int = 0
    assembly_index: int = 0
    type_start: int = 0
    type_count: int = 0
    # Version 24+
    exported_type_start: int = version_field(min_ver=24, default=0)
    exported_type_count: int = version_field(min_ver=24, default=0)
    entry_point_index: int = 0
    # Version 19+
    token: int = version_field(min_ver=19, default=0)
    # Version 24.1+
    custom_attribute_start: int = version_field(min_ver=24.1, default=0)
    custom_attribute_count: int = version_field(min_ver=24.1, default=0)


@dataclass
class Il2CppAssemblyNameDefinition:
    """Assembly name information."""
    name_index: int = 0
    culture_index: int = 0
    # Version <= 24.3
    hash_value_index: int = version_field(max_ver=24.3, default=0)
    public_key_index: int = 0
    hash_alg: int = 0
    hash_len: int = 0
    flags: int = 0
    major: int = 0
    minor: int = 0
    build: int = 0
    revision: int = 0
    public_key_token: bytes = array_field(8, lambda: b'\x00' * 8)


@dataclass
class Il2CppAssemblyDefinition:
    """Assembly definition."""
    image_index: int = 0
    # Version 24.1+
    token: int = version_field(min_ver=24.1, default=0)
    # Version <= 24
    custom_attribute_index: int = version_field(max_ver=24, default=0)
    # Version 20+
    referenced_assembly_start: int = version_field(min_ver=20, default=0)
    referenced_assembly_count: int = version_field(min_ver=20, default=0)
    aname: Optional['Il2CppAssemblyNameDefinition'] = None


@dataclass
class Il2CppTypeDefinition:
    """Type (class/struct/enum/interface) definition."""
    name_index: int = 0
    namespace_index: int = 0
    # Version <= 24
    custom_attribute_index: int = version_field(max_ver=24, default=0)
    byval_type_index: int = 0
    # Version <= 24.5
    byref_type_index: int = version_field(max_ver=24.5, default=0)
    declaring_type_index: int = 0
    parent_index: int = 0
    element_type_index: int = 0
    # Version <= 24.1
    rgctx_start_index: int = version_field(max_ver=24.1, default=0)
    rgctx_count: int = version_field(max_ver=24.1, default=0)
    generic_container_index: int = 0
    # Version <= 22
    delegate_wrapper_from_managed_to_native_index: int = version_field(max_ver=22, default=0)
    marshaling_functions_index: int = version_field(max_ver=22, default=0)
    # Version 21-22
    ccw_function_index: int = version_field(min_ver=21, max_ver=22, default=0)
    guid_index: int = version_field(min_ver=21, max_ver=22, default=0)
    flags: int = 0
    field_start: int = 0
    method_start: int = 0
    event_start: int = 0
    property_start: int = 0
    nested_types_start: int = 0
    interfaces_start: int = 0
    vtable_start: int = 0
    interface_offsets_start: int = 0
    method_count: int = ushort_field(0)
    property_count: int = ushort_field(0)
    field_count: int = ushort_field(0)
    event_count: int = ushort_field(0)
    nested_type_count: int = ushort_field(0)
    vtable_count: int = ushort_field(0)
    interfaces_count: int = ushort_field(0)
    interface_offsets_count: int = ushort_field(0)
    bitfield: int = 0
    # Version 19+
    token: int = version_field(min_ver=19, default=0)

    @property
    def is_value_type(self) -> bool:
        """Check if this is a value type."""
        return (self.bitfield & 0x1) == 1

    @property
    def is_enum(self) -> bool:
        """Check if this is an enum."""
        return ((self.bitfield >> 1) & 0x1) == 1


@dataclass
class Il2CppMethodDefinition:
    """Method definition."""
    name_index: int = 0  # uint
    declaring_type: int = 0  # int
    return_type: int = 0  # int
    # Version 31+
    return_parameter_token: int = version_field(min_ver=31, default=0)
    parameter_start: int = 0  # int
    # Version <= 24
    custom_attribute_index: int = version_field(max_ver=24, default=0)
    generic_container_index: int = 0  # int
    # Version <= 24.1
    method_index: int = version_field(max_ver=24.1, default=0)
    invoker_index: int = version_field(max_ver=24.1, default=0)
    delegate_wrapper_index: int = version_field(max_ver=24.1, default=0)
    rgctx_start_index: int = version_field(max_ver=24.1, default=0)
    rgctx_count: int = version_field(max_ver=24.1, default=0)
    token: int = 0  # uint
    token2: int = 0  # uint
    flags: int = ushort_field(0)
    iflags: int = ushort_field(0)
    slot: int = ushort_field(0)
    parameter_count: int = ushort_field(0)


@dataclass
class Il2CppParameterDefinition:
    """Parameter definition."""
    name_index: int = 0
    token: int = 0
    # Version <= 24
    custom_attribute_index: int = version_field(max_ver=24, default=0)
    type_index: int = 0


@dataclass
class Il2CppFieldDefinition:
    """Field definition."""
    name_index: int = 0
    type_index: int = 0
    # Version <= 24
    custom_attribute_index: int = version_field(max_ver=24, default=0)
    # Version 19+
    token: int = version_field(min_ver=19, default=0)


@dataclass
class Il2CppFieldDefaultValue:
    """Field default value."""
    field_index: int = 0
    type_index: int = 0
    data_index: int = 0


@dataclass
class Il2CppParameterDefaultValue:
    """Parameter default value."""
    parameter_index: int = 0
    type_index: int = 0
    data_index: int = 0


@dataclass
class Il2CppPropertyDefinition:
    """Property definition."""
    name_index: int = 0
    get: int = 0
    set: int = 0
    attrs: int = 0
    # Version <= 24
    custom_attribute_index: int = version_field(max_ver=24, default=0)
    # Version 19+
    token: int = version_field(min_ver=19, default=0)


@dataclass
class Il2CppEventDefinition:
    """Event definition."""
    name_index: int = 0
    type_index: int = 0
    add: int = 0
    remove: int = 0
    raise_: int = 0  # 'raise' is a Python keyword
    # Version <= 24
    custom_attribute_index: int = version_field(max_ver=24, default=0)
    # Version 19+
    token: int = version_field(min_ver=19, default=0)


@dataclass
class Il2CppGenericContainer:
    """Generic container (type or method with generic parameters)."""
    owner_index: int = 0
    type_argc: int = 0
    is_method: int = 0
    generic_parameter_start: int = 0


@dataclass
class Il2CppGenericParameter:
    """Generic parameter."""
    owner_index: int = 0  # int
    name_index: int = 0  # uint
    constraints_start: int = short_field(0)  # short
    constraints_count: int = short_field(0)  # short
    num: int = ushort_field(0)  # ushort
    flags: int = ushort_field(0)  # ushort


@dataclass
class Il2CppCustomAttributeTypeRange:
    """Custom attribute type range."""
    # Version 24.1+
    token: int = version_field(min_ver=24.1, default=0)
    start: int = 0
    count: int = 0


@dataclass
class Il2CppCustomAttributeDataRange:
    """Custom attribute data range (v29+)."""
    token: int = 0
    start_offset: int = 0


@dataclass
class Il2CppMetadataUsageList:
    """Metadata usage list."""
    start: int = 0
    count: int = 0


@dataclass
class Il2CppMetadataUsagePair:
    """Metadata usage pair."""
    destination_index: int = 0
    encoded_source_index: int = 0


@dataclass
class Il2CppStringLiteral:
    """String literal."""
    length: int = 0
    data_index: int = 0


@dataclass
class Il2CppFieldRef:
    """Field reference."""
    type_index: int = 0
    field_index: int = 0


@dataclass
class Il2CppRGCTXDefinitionData:
    """RGCTX definition data."""
    rgctx_data_dummy: int = 0

    @property
    def method_index(self) -> int:
        return self.rgctx_data_dummy

    @property
    def type_index(self) -> int:
        return self.rgctx_data_dummy


@dataclass
class Il2CppRGCTXDefinition:
    """RGCTX definition."""
    # Version <= 27.1
    type_pre29: int = version_field(max_ver=27.1, default=0)
    # Version 29+
    type_post29: int = version_field(min_ver=29, default=0)
    # Version <= 27.1
    data: Optional['Il2CppRGCTXDefinitionData'] = version_field(max_ver=27.1, default=None)
    # Version 27.2+
    _data: int = version_field(min_ver=27.2, default=0)

    @property
    def type(self) -> int:
        if self.type_post29 == 0:
            return self.type_pre29
        return self.type_post29


# ============================================================
# Runtime Structures (from IL2CPP binary)
# ============================================================

@dataclass
class Il2CppCodeRegistration:
    """Code registration structure. All fields are pointer-sized (8 bytes on 64-bit)."""
    # Version <= 24.1
    method_pointers_count: int = ptr_version_field(max_ver=24.1, default=0)
    method_pointers: int = ptr_version_field(max_ver=24.1, default=0)
    # Version <= 21
    delegate_wrappers_from_native_to_managed_count: int = ptr_version_field(max_ver=21, default=0)
    delegate_wrappers_from_native_to_managed: int = ptr_version_field(max_ver=21, default=0)
    # Version 22+
    reverse_pinvoke_wrapper_count: int = ptr_version_field(min_ver=22, default=0)
    reverse_pinvoke_wrappers: int = ptr_version_field(min_ver=22, default=0)
    # Version <= 22
    delegate_wrappers_from_managed_to_native_count: int = ptr_version_field(max_ver=22, default=0)
    delegate_wrappers_from_managed_to_native: int = ptr_version_field(max_ver=22, default=0)
    marshaling_functions_count: int = ptr_version_field(max_ver=22, default=0)
    marshaling_functions: int = ptr_version_field(max_ver=22, default=0)
    # Version 21-22
    ccw_marshaling_functions_count: int = ptr_version_field(min_ver=21, max_ver=22, default=0)
    ccw_marshaling_functions: int = ptr_version_field(min_ver=21, max_ver=22, default=0)
    # All versions
    generic_method_pointers_count: int = ptr_field(0)
    generic_method_pointers: int = ptr_field(0)
    # Version 24.5 and 27.1+
    generic_adjustor_thunks: int = ptr_version_field(min_ver=24.5, default=0)
    invoker_pointers_count: int = ptr_field(0)
    invoker_pointers: int = ptr_field(0)
    # Version <= 24.5
    custom_attribute_count: int = ptr_version_field(max_ver=24.5, default=0)
    custom_attribute_generators: int = ptr_version_field(max_ver=24.5, default=0)
    # Version 21-22
    guid_count: int = ptr_version_field(min_ver=21, max_ver=22, default=0)
    guids: int = ptr_version_field(min_ver=21, max_ver=22, default=0)
    # Version 22+
    unresolved_virtual_call_count: int = ptr_version_field(min_ver=22, default=0)
    unresolved_virtual_call_pointers: int = ptr_version_field(min_ver=22, default=0)
    # Version 29.1+
    unresolved_instance_call_pointers: int = ptr_version_field(min_ver=29.1, default=0)
    unresolved_static_call_pointers: int = ptr_version_field(min_ver=29.1, default=0)
    # Version 23+
    interop_data_count: int = ptr_version_field(min_ver=23, default=0)
    interop_data: int = ptr_version_field(min_ver=23, default=0)
    # Version 24.3+
    windows_runtime_factory_count: int = ptr_version_field(min_ver=24.3, default=0)
    windows_runtime_factory_table: int = ptr_version_field(min_ver=24.3, default=0)
    # Version 24.2+
    code_gen_modules_count: int = ptr_version_field(min_ver=24.2, default=0)
    code_gen_modules: int = ptr_version_field(min_ver=24.2, default=0)


@dataclass
class Il2CppMetadataRegistration:
    """Metadata registration structure. All fields are pointer-sized (8 bytes on 64-bit)."""
    generic_classes_count: int = ptr_field(0)
    generic_classes: int = ptr_field(0)
    generic_insts_count: int = ptr_field(0)
    generic_insts: int = ptr_field(0)
    generic_method_table_count: int = ptr_field(0)
    generic_method_table: int = ptr_field(0)
    types_count: int = ptr_field(0)
    types: int = ptr_field(0)
    method_specs_count: int = ptr_field(0)
    method_specs: int = ptr_field(0)
    # Version <= 16
    method_references_count: int = ptr_version_field(max_ver=16, default=0)
    method_references: int = ptr_version_field(max_ver=16, default=0)
    field_offsets_count: int = ptr_field(0)
    field_offsets: int = ptr_field(0)
    type_definitions_sizes_count: int = ptr_field(0)
    type_definitions_sizes: int = ptr_field(0)
    # Version 19+
    metadata_usages_count: int = ptr_version_field(min_ver=19, default=0)
    metadata_usages: int = ptr_version_field(min_ver=19, default=0)


@dataclass
class Il2CppType:
    """IL2CPP type representation."""
    datapoint: int = ulong_field(0)  # ulong (8 bytes)
    bits: int = 0  # uint (4 bytes)

    # Parsed values (set after reading)
    _attrs: int = 0
    _type: int = 0
    _num_mods: int = 0
    _byref: int = 0
    _pinned: int = 0
    _valuetype: int = 0

    def init(self, version: float) -> None:
        """Initialize parsed values from bits."""
        self._attrs = self.bits & 0xFFFF
        self._type = (self.bits >> 16) & 0xFF

        if version >= 27.2:
            self._num_mods = (self.bits >> 24) & 0x1F
            self._byref = (self.bits >> 29) & 1
            self._pinned = (self.bits >> 30) & 1
            self._valuetype = self.bits >> 31
        else:
            self._num_mods = (self.bits >> 24) & 0x3F
            self._byref = (self.bits >> 30) & 1
            self._pinned = self.bits >> 31

    @property
    def attrs(self) -> int:
        return self._attrs

    @property
    def type(self) -> int:
        return self._type

    @property
    def byref(self) -> int:
        return self._byref

    @property
    def pinned(self) -> int:
        return self._pinned

    # Data union accessors
    @property
    def klass_index(self) -> int:
        """For VALUETYPE and CLASS."""
        return self.datapoint

    @property
    def type_handle(self) -> int:
        """For VALUETYPE and CLASS at runtime."""
        return self.datapoint

    @property
    def type_ptr(self) -> int:
        """For PTR and SZARRAY."""
        return self.datapoint

    @property
    def array(self) -> int:
        """For ARRAY."""
        return self.datapoint

    @property
    def generic_parameter_index(self) -> int:
        """For VAR and MVAR."""
        return self.datapoint

    @property
    def generic_parameter_handle(self) -> int:
        """For VAR and MVAR at runtime."""
        return self.datapoint

    @property
    def generic_class(self) -> int:
        """For GENERICINST."""
        return self.datapoint


@dataclass
class Il2CppGenericClass:
    """Generic class instance. All fields are pointer-sized (8 bytes on 64-bit)."""
    # Version <= 24.5
    type_definition_index: int = ptr_version_field(max_ver=24.5, default=0)
    # Version 27+
    type: int = ptr_version_field(min_ver=27, default=0)
    context: Optional['Il2CppGenericContext'] = None
    cached_class: int = ptr_field(0)


@dataclass
class Il2CppGenericContext:
    """Generic context. All fields are pointer-sized (8 bytes on 64-bit)."""
    class_inst: int = ptr_field(0)
    method_inst: int = ptr_field(0)


@dataclass
class Il2CppGenericInst:
    """Generic instantiation. All fields are pointer-sized (8 bytes on 64-bit)."""
    type_argc: int = ptr_field(0)
    type_argv: int = ptr_field(0)


@dataclass
class Il2CppArrayType:
    """Array type."""
    etype: int = 0
    rank: int = 0  # byte
    numsizes: int = 0  # byte
    numlobounds: int = 0  # byte
    sizes: int = 0
    lobounds: int = 0


@dataclass
class Il2CppGenericMethodFunctionsDefinitions:
    """Generic method function definitions."""
    generic_method_index: int = 0
    indices: Optional['Il2CppGenericMethodIndices'] = None


@dataclass
class Il2CppGenericMethodIndices:
    """Generic method indices."""
    method_index: int = 0
    invoker_index: int = 0
    # Version 24.5 and 27.1+
    adjustor_thunk: int = version_field(min_ver=24.5, default=0)


@dataclass
class Il2CppMethodSpec:
    """Method specification."""
    method_definition_index: int = 0
    class_index_index: int = 0
    method_index_index: int = 0


@dataclass
class Il2CppCodeGenModule:
    """Code generation module. All fields are pointer-sized (8 bytes on 64-bit)."""
    module_name: int = ptr_field(0)
    method_pointer_count: int = long_field(0)
    method_pointers: int = ptr_field(0)
    # Version 24.5 and 27.1+
    adjustor_thunk_count: int = ptr_version_field(min_ver=24.5, default=0)
    adjustor_thunks: int = ptr_version_field(min_ver=24.5, default=0)
    invoker_indices: int = ptr_field(0)
    reverse_pinvoke_wrapper_count: int = ptr_field(0)
    reverse_pinvoke_wrapper_indices: int = ptr_field(0)
    rgctx_ranges_count: int = long_field(0)
    rgctx_ranges: int = ptr_field(0)
    rgctxs_count: int = long_field(0)
    rgctxs: int = ptr_field(0)
    debugger_metadata: int = ptr_field(0)
    # Version 27-27.2
    custom_attribute_cache_generator: int = ptr_version_field(min_ver=27, max_ver=27.2, default=0)
    # Version 27+
    module_initializer: int = ptr_version_field(min_ver=27, default=0)
    static_constructor_type_indices: int = ptr_version_field(min_ver=27, default=0)
    metadata_registration: int = ptr_version_field(min_ver=27, default=0)
    code_registration: int = ptr_version_field(min_ver=27, default=0)


@dataclass
class Il2CppRange:
    """Range structure."""
    start: int = 0
    length: int = 0


@dataclass
class Il2CppTokenRangePair:
    """Token range pair."""
    token: int = 0
    range: Optional['Il2CppRange'] = None
