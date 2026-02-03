"""
IL2CPP Executor for type name resolution and metadata handling.

This module provides the core logic for resolving IL2CPP types to their
string representations, handling generics, and managing metadata lookups.
"""

from typing import Dict, List, Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from ..il2cpp.metadata import Metadata
    from ..il2cpp.base import Il2Cpp

from ..il2cpp.structures import (
    Il2CppType,
    Il2CppTypeDefinition,
    Il2CppMethodDefinition,
    Il2CppGenericInst,
    Il2CppGenericClass,
    Il2CppGenericContainer,
    Il2CppGenericParameter,
    Il2CppGenericContext,
    Il2CppMethodSpec,
    Il2CppImageDefinition,
    Il2CppRGCTXDefinition,
)
from ..il2cpp.enums import Il2CppTypeEnum, TYPE_NAMES


class Il2CppExecutor:
    """
    Executor for IL2CPP type resolution and metadata handling.

    This class provides methods for:
    - Resolving IL2CPP types to string names
    - Handling generic types and methods
    - Getting default values for fields and parameters
    - Managing custom attributes

    Attributes:
        metadata: The parsed metadata file
        il2cpp: The parsed IL2CPP binary
        custom_attribute_generators: Array of custom attribute generator pointers
    """

    def __init__(self, metadata: 'Metadata', il2cpp: 'Il2Cpp'):
        """
        Initialize the executor.

        Args:
            metadata: Parsed metadata
            il2cpp: Parsed IL2CPP binary
        """
        self.metadata = metadata
        self.il2cpp = il2cpp
        self.custom_attribute_generators: List[int] = []

        # Caches for performance
        self._type_name_cache: Dict[int, str] = {}  # id(il2cpp_type) -> type_name
        self._generic_class_cache: Dict[int, Il2CppGenericClass] = {}  # address -> Il2CppGenericClass
        self._generic_inst_cache: Dict[int, Il2CppGenericInst] = {}  # address -> Il2CppGenericInst
        self._generic_inst_params_cache: Dict[int, str] = {}  # (type_argv, type_argc) -> params string
        self._generic_container_params_cache: Dict[int, str] = {}  # generic_parameter_start -> params string
        self._method_spec_name_cache: Dict[int, tuple] = {}  # id(method_spec) -> (type_name, method_name)
        self._type_def_name_cache: Dict[tuple, str] = {}  # (type_def_index, add_namespace, generic_parameter) -> name

        # Build custom attribute generators for v27-28
        if 27 <= il2cpp.version < 29:
            total_count = sum(img.custom_attribute_count for img in metadata.image_defs)
            self.custom_attribute_generators = [0] * total_count

            for image_def in metadata.image_defs:
                image_name = metadata.get_string_from_index(image_def.name_index)
                if image_name in il2cpp.code_gen_modules:
                    code_gen_module = il2cpp.code_gen_modules[image_name]
                    if image_def.custom_attribute_count > 0:
                        pointers = il2cpp.read_ptr_array(
                            il2cpp.map_vatr(code_gen_module.custom_attribute_cache_generator),
                            image_def.custom_attribute_count
                        )
                        for i, ptr in enumerate(pointers):
                            self.custom_attribute_generators[
                                image_def.custom_attribute_start + i
                            ] = ptr

        elif il2cpp.version < 27:
            self.custom_attribute_generators = il2cpp.custom_attribute_generators

    def get_type_name(
        self,
        il2cpp_type: Il2CppType,
        add_namespace: bool = True,
        is_nested: bool = False
    ) -> str:
        """
        Get the string name of an IL2CPP type.

        Args:
            il2cpp_type: The IL2CPP type
            add_namespace: Whether to include the namespace
            is_nested: Whether this is a nested type (internal use)

        Returns:
            The type name as a string
        """
        # Check cache first (use datapoint + bits as key since il2cpp_type may be recreated)
        cache_key = (il2cpp_type.datapoint, il2cpp_type.bits, add_namespace, is_nested)
        if cache_key in self._type_name_cache:
            return self._type_name_cache[cache_key]

        result = self._get_type_name_impl(il2cpp_type, add_namespace, is_nested)
        self._type_name_cache[cache_key] = result
        return result

    def _get_type_name_impl(
        self,
        il2cpp_type: Il2CppType,
        add_namespace: bool = True,
        is_nested: bool = False
    ) -> str:
        """Internal implementation of get_type_name."""
        type_enum = Il2CppTypeEnum(il2cpp_type.type)

        # Handle arrays
        if type_enum == Il2CppTypeEnum.IL2CPP_TYPE_ARRAY:
            array_type = self.il2cpp.map_vatr_class(
                type(self.il2cpp).__module__ + '.Il2CppArrayType',
                il2cpp_type.array
            )
            # Fallback for simple handling
            element_type = self.il2cpp.get_il2cpp_type(il2cpp_type.array)
            if element_type:
                element_name = self.get_type_name(element_type, add_namespace, False)
                return f"{element_name}[,]"  # Multi-dimensional array
            return "object[]"

        # Handle single-dimension arrays
        if type_enum == Il2CppTypeEnum.IL2CPP_TYPE_SZARRAY:
            element_type = self.il2cpp.get_il2cpp_type(il2cpp_type.type_ptr)
            if element_type:
                element_name = self.get_type_name(element_type, add_namespace, False)
                return f"{element_name}[]"
            return "object[]"

        # Handle pointers
        if type_enum == Il2CppTypeEnum.IL2CPP_TYPE_PTR:
            ori_type = self.il2cpp.get_il2cpp_type(il2cpp_type.type_ptr)
            if ori_type:
                return f"{self.get_type_name(ori_type, add_namespace, False)}*"
            return "void*"

        # Handle generic parameters
        if type_enum in (Il2CppTypeEnum.IL2CPP_TYPE_VAR, Il2CppTypeEnum.IL2CPP_TYPE_MVAR):
            param = self._get_generic_parameter_from_type(il2cpp_type)
            if param:
                return self.metadata.get_string_from_index(param.name_index)
            return "T"

        # Handle classes, value types, and generic instances
        if type_enum in (
            Il2CppTypeEnum.IL2CPP_TYPE_CLASS,
            Il2CppTypeEnum.IL2CPP_TYPE_VALUETYPE,
            Il2CppTypeEnum.IL2CPP_TYPE_GENERICINST
        ):
            result = ""
            type_def: Optional[Il2CppTypeDefinition] = None
            generic_class: Optional[Il2CppGenericClass] = None

            if type_enum == Il2CppTypeEnum.IL2CPP_TYPE_GENERICINST:
                # Use cache for generic class reads
                gc_addr = il2cpp_type.generic_class
                if gc_addr in self._generic_class_cache:
                    generic_class = self._generic_class_cache[gc_addr]
                else:
                    generic_class = self.il2cpp.map_vatr_class(
                        Il2CppGenericClass, gc_addr
                    )
                    self._generic_class_cache[gc_addr] = generic_class
                type_def = self._get_generic_class_type_definition(generic_class)
            else:
                type_def = self._get_type_definition_from_type(il2cpp_type)

            if type_def is None:
                return "UnknownType"

            # Handle declaring type (nested types)
            if type_def.declaring_type_index != -1:
                declaring_type = self.il2cpp.types[type_def.declaring_type_index]
                result += self.get_type_name(declaring_type, add_namespace, True)
                result += '.'
            elif add_namespace:
                namespace = self.metadata.get_string_from_index(type_def.namespace_index)
                if namespace:
                    result += namespace + '.'

            # Get type name
            type_name = self.metadata.get_string_from_index(type_def.name_index)

            # Remove generic arity suffix (e.g., List`1 -> List)
            backtick_index = type_name.find('`')
            if backtick_index != -1:
                type_name = type_name[:backtick_index]

            result += type_name

            if is_nested:
                return result

            # Add generic parameters
            if generic_class is not None:
                # Use cache for generic inst reads
                gi_addr = generic_class.context.class_inst
                if gi_addr in self._generic_inst_cache:
                    generic_inst = self._generic_inst_cache[gi_addr]
                else:
                    generic_inst = self.il2cpp.map_vatr_class(
                        Il2CppGenericInst, gi_addr
                    )
                    self._generic_inst_cache[gi_addr] = generic_inst
                result += self._get_generic_inst_params(generic_inst)
            elif type_def.generic_container_index >= 0:
                generic_container = self.metadata.generic_containers[
                    type_def.generic_container_index
                ]
                result += self._get_generic_container_params(generic_container)

            return result

        # Handle primitive types
        if type_enum in TYPE_NAMES:
            return TYPE_NAMES[type_enum]

        return f"UnknownType({type_enum})"

    def get_type_def_name(
        self,
        type_def: Il2CppTypeDefinition,
        add_namespace: bool = True,
        generic_parameter: bool = True
    ) -> str:
        """
        Get the name of a type definition.

        Args:
            type_def: The type definition
            add_namespace: Whether to include namespace
            generic_parameter: Whether to include generic parameters

        Returns:
            The type name
        """
        # Use cache with id-based key
        cache_key = (id(type_def), add_namespace, generic_parameter)
        if cache_key in self._type_def_name_cache:
            return self._type_def_name_cache[cache_key]

        prefix = ""

        # Handle declaring type
        if type_def.declaring_type_index != -1:
            declaring_type = self.il2cpp.types[type_def.declaring_type_index]
            prefix = self.get_type_name(declaring_type, add_namespace, True) + '.'
        elif add_namespace:
            namespace = self.metadata.get_string_from_index(type_def.namespace_index)
            if namespace:
                prefix = namespace + '.'

        type_name = self.metadata.get_string_from_index(type_def.name_index)

        if type_def.generic_container_index >= 0:
            # Remove arity
            backtick_index = type_name.find('`')
            if backtick_index != -1:
                type_name = type_name[:backtick_index]

            if generic_parameter:
                generic_container = self.metadata.generic_containers[
                    type_def.generic_container_index
                ]
                type_name += self._get_generic_container_params(generic_container)

        result = prefix + type_name
        self._type_def_name_cache[cache_key] = result
        return result

    def _get_generic_inst_params(self, generic_inst: Il2CppGenericInst) -> str:
        """Get generic instantiation parameters as string."""
        # Use cache key based on type_argv address and count
        cache_key = (generic_inst.type_argv, generic_inst.type_argc)
        if cache_key in self._generic_inst_params_cache:
            return self._generic_inst_params_cache[cache_key]

        param_names = []
        pointers = self.il2cpp.map_vatr_array(
            generic_inst.type_argv, generic_inst.type_argc
        )

        for ptr in pointers:
            il2cpp_type = self.il2cpp.get_il2cpp_type(ptr)
            if il2cpp_type:
                param_names.append(self.get_type_name(il2cpp_type, False, False))
            else:
                param_names.append("?")

        result = f"<{', '.join(param_names)}>"
        self._generic_inst_params_cache[cache_key] = result
        return result

    def _get_generic_container_params(self, generic_container: Il2CppGenericContainer) -> str:
        """Get generic container parameters as string."""
        cache_key = (generic_container.generic_parameter_start, generic_container.type_argc)
        if cache_key in self._generic_container_params_cache:
            return self._generic_container_params_cache[cache_key]

        param_names = []
        for i in range(generic_container.type_argc):
            param_index = generic_container.generic_parameter_start + i
            param = self.metadata.generic_parameters[param_index]
            param_names.append(self.metadata.get_string_from_index(param.name_index))

        result = f"<{', '.join(param_names)}>"
        self._generic_container_params_cache[cache_key] = result
        return result

    def get_method_spec_name(
        self,
        method_spec: Il2CppMethodSpec,
        add_namespace: bool = False
    ) -> Tuple[str, str]:
        """
        Get type and method name for a method specification.

        Args:
            method_spec: The method specification
            add_namespace: Whether to include namespace

        Returns:
            Tuple of (type_name, method_name)
        """
        # Use cache
        cache_key = (id(method_spec), add_namespace)
        if cache_key in self._method_spec_name_cache:
            return self._method_spec_name_cache[cache_key]

        method_def = self.metadata.method_defs[method_spec.method_definition_index]
        type_def = self.metadata.type_defs[method_def.declaring_type]
        type_name = self.get_type_def_name(type_def, add_namespace, False)

        if method_spec.class_index_index != -1:
            class_inst = self.il2cpp.generic_insts[method_spec.class_index_index]
            type_name += self._get_generic_inst_params(class_inst)

        method_name = self.metadata.get_string_from_index(method_def.name_index)

        if method_spec.method_index_index != -1:
            method_inst = self.il2cpp.generic_insts[method_spec.method_index_index]
            method_name += self._get_generic_inst_params(method_inst)

        result = (type_name, method_name)
        self._method_spec_name_cache[cache_key] = result
        return result

    def get_method_spec_generic_context(
        self,
        method_spec: Il2CppMethodSpec
    ) -> Il2CppGenericContext:
        """Get the generic context for a method specification."""
        class_inst_pointer = 0
        method_inst_pointer = 0

        if method_spec.class_index_index != -1:
            class_inst_pointer = self.il2cpp.generic_inst_pointers[
                method_spec.class_index_index
            ]

        if method_spec.method_index_index != -1:
            method_inst_pointer = self.il2cpp.generic_inst_pointers[
                method_spec.method_index_index
            ]

        context = Il2CppGenericContext()
        context.class_inst = class_inst_pointer
        context.method_inst = method_inst_pointer
        return context

    def get_rgctx_definition(
        self,
        image_name: str,
        type_def: Il2CppTypeDefinition
    ) -> Optional[List[Il2CppRGCTXDefinition]]:
        """Get RGCTX definitions for a type."""
        if self.il2cpp.version >= 24.2:
            return self.il2cpp.rgctxs_dictionary.get(image_name, {}).get(
                type_def.token, None
            )
        else:
            if type_def.rgctx_count > 0:
                return self.metadata.rgctx_entries[
                    type_def.rgctx_start_index:
                    type_def.rgctx_start_index + type_def.rgctx_count
                ]
        return None

    def _get_generic_class_type_definition(
        self,
        generic_class: Il2CppGenericClass
    ) -> Optional[Il2CppTypeDefinition]:
        """Get type definition from generic class."""
        if self.il2cpp.version >= 27:
            il2cpp_type = self.il2cpp.get_il2cpp_type(generic_class.type)
            if il2cpp_type is None:
                return None
            return self._get_type_definition_from_type(il2cpp_type)

        if generic_class.type_definition_index in (4294967295, -1):
            return None

        return self.metadata.type_defs[generic_class.type_definition_index]

    def _get_type_definition_from_type(
        self,
        il2cpp_type: Il2CppType
    ) -> Optional[Il2CppTypeDefinition]:
        """Get type definition from IL2CPP type."""
        if self.il2cpp.version >= 27 and self.il2cpp.is_dumped:
            offset = (
                il2cpp_type.type_handle -
                self.metadata.image_base -
                self.metadata.header.type_definitions_offset
            )
            index = offset // self.metadata.size_of(Il2CppTypeDefinition)
            if 0 <= index < len(self.metadata.type_defs):
                return self.metadata.type_defs[index]
            return None

        klass_index = il2cpp_type.klass_index
        if 0 <= klass_index < len(self.metadata.type_defs):
            return self.metadata.type_defs[klass_index]
        return None

    def _get_generic_parameter_from_type(
        self,
        il2cpp_type: Il2CppType
    ) -> Optional[Il2CppGenericParameter]:
        """Get generic parameter from IL2CPP type."""
        if self.il2cpp.version >= 27 and self.il2cpp.is_dumped:
            offset = (
                il2cpp_type.generic_parameter_handle -
                self.metadata.image_base -
                self.metadata.header.generic_parameters_offset
            )
            index = offset // self.metadata.size_of(Il2CppGenericParameter)
            if 0 <= index < len(self.metadata.generic_parameters):
                return self.metadata.generic_parameters[index]
            return None

        param_index = il2cpp_type.generic_parameter_index
        if 0 <= param_index < len(self.metadata.generic_parameters):
            return self.metadata.generic_parameters[param_index]
        return None

    def get_section_helper(self):
        """Get a section helper from the IL2CPP binary."""
        method_count = sum(
            1 for m in self.metadata.method_defs if m.method_index >= 0
        )
        return self.il2cpp.get_section_helper(
            method_count,
            len(self.metadata.type_defs),
            len(self.metadata.image_defs)
        )

    def try_get_default_value(
        self,
        type_index: int,
        data_index: int
    ) -> Tuple[bool, any]:
        """
        Try to get a default value for a field or parameter.

        Args:
            type_index: Index of the type
            data_index: Index into default value data

        Returns:
            Tuple of (success, value)
        """
        pointer = self.metadata.get_default_value_from_index(data_index)
        default_value_type = self.il2cpp.types[type_index]
        self.metadata.position = pointer

        type_enum = Il2CppTypeEnum(default_value_type.type)

        try:
            if type_enum == Il2CppTypeEnum.IL2CPP_TYPE_BOOLEAN:
                return (True, self.metadata.read_bool())
            elif type_enum == Il2CppTypeEnum.IL2CPP_TYPE_U1:
                return (True, self.metadata.read_byte())
            elif type_enum == Il2CppTypeEnum.IL2CPP_TYPE_I1:
                return (True, self.metadata.read_sbyte())
            elif type_enum == Il2CppTypeEnum.IL2CPP_TYPE_CHAR:
                return (True, chr(self.metadata.read_uint16()))
            elif type_enum == Il2CppTypeEnum.IL2CPP_TYPE_U2:
                return (True, self.metadata.read_uint16())
            elif type_enum == Il2CppTypeEnum.IL2CPP_TYPE_I2:
                return (True, self.metadata.read_int16())
            elif type_enum == Il2CppTypeEnum.IL2CPP_TYPE_U4:
                if self.il2cpp.version >= 29:
                    return (True, self.metadata.read_compressed_uint32())
                return (True, self.metadata.read_uint32())
            elif type_enum == Il2CppTypeEnum.IL2CPP_TYPE_I4:
                if self.il2cpp.version >= 29:
                    return (True, self.metadata.read_compressed_int32())
                return (True, self.metadata.read_int32())
            elif type_enum == Il2CppTypeEnum.IL2CPP_TYPE_U8:
                return (True, self.metadata.read_uint64())
            elif type_enum == Il2CppTypeEnum.IL2CPP_TYPE_I8:
                return (True, self.metadata.read_int64())
            elif type_enum == Il2CppTypeEnum.IL2CPP_TYPE_R4:
                return (True, self.metadata.read_float())
            elif type_enum == Il2CppTypeEnum.IL2CPP_TYPE_R8:
                return (True, self.metadata.read_double())
            elif type_enum == Il2CppTypeEnum.IL2CPP_TYPE_STRING:
                if self.il2cpp.version >= 29:
                    length = self.metadata.read_compressed_int32()
                    if length == -1:
                        return (True, None)
                    return (True, self.metadata.read_bytes(length).decode('utf-8'))
                else:
                    length = self.metadata.read_int32()
                    return (True, self.metadata.read_string(length))
            else:
                return (False, pointer)
        except:
            return (False, pointer)
