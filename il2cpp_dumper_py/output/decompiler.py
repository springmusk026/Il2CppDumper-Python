"""
IL2CPP Decompiler - generates dump.cs output.

This module generates a C#-like pseudocode dump of all types, methods,
fields, and properties from an IL2CPP compiled binary.
"""

from typing import List, Dict, TextIO, Optional, TYPE_CHECKING
from pathlib import Path
from io import StringIO

if TYPE_CHECKING:
    from ..executor.il2cpp_executor import Il2CppExecutor
    from ..config import Config

from ..il2cpp.structures import (
    Il2CppTypeDefinition,
    Il2CppMethodDefinition,
    Il2CppFieldDefinition,
    Il2CppPropertyDefinition,
    Il2CppImageDefinition,
)
from ..il2cpp.enums import (
    TypeAttributes,
    FieldAttributes,
    MethodAttributes,
    ParamAttributes,
)
from ..utils.string_utils import escape_string


class Il2CppDecompiler:
    """
    Generates C#-like pseudocode dump from IL2CPP metadata.

    This creates a dump.cs file containing all types, methods, fields,
    and properties with their addresses and offsets.
    """

    # Pre-computed modifier strings based on flags (class-level cache)
    _MODIFIER_CACHE: Dict[int, str] = {}

    def __init__(self, executor: 'Il2CppExecutor'):
        """
        Initialize the decompiler.

        Args:
            executor: The IL2CPP executor for type resolution
        """
        self.executor = executor
        self.metadata = executor.metadata
        self.il2cpp = executor.il2cpp

    def decompile(self, config: 'Config', output_dir: str) -> None:
        """
        Generate the dump.cs file.

        Args:
            config: Configuration options
            output_dir: Output directory path
        """
        output_path = Path(output_dir) / "dump.cs"

        # Use StringIO buffer for better performance, then flush to file
        buffer = StringIO()

        # Write image list
        for image_index, image_def in enumerate(self.metadata.image_defs):
            image_name = self.metadata.get_string_from_index(image_def.name_index)
            buffer.write(f"// Image {image_index}: {image_name} - {image_def.type_start}\n")

        # Dump each image's types
        for image_def in self.metadata.image_defs:
            try:
                self._dump_image(buffer, image_def, config)
            except Exception as e:
                print(f"ERROR: Error dumping image: {e}")
                buffer.write("/*\n")
                buffer.write(str(e))
                buffer.write("\n*/\n}\n")

        # Write buffer to file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(buffer.getvalue())

    def _dump_image(
        self,
        writer: TextIO,
        image_def: Il2CppImageDefinition,
        config: 'Config'
    ) -> None:
        """Dump all types in an image."""
        image_name = self.metadata.get_string_from_index(image_def.name_index)
        type_end = image_def.type_start + image_def.type_count

        for type_def_index in range(image_def.type_start, type_end):
            type_def = self.metadata.type_defs[type_def_index]
            self._dump_type(writer, type_def, type_def_index, image_def, image_name, config)

    def _dump_type(
        self,
        writer: TextIO,
        type_def: Il2CppTypeDefinition,
        type_def_index: int,
        image_def: Il2CppImageDefinition,
        image_name: str,
        config: 'Config'
    ) -> None:
        """Dump a single type."""
        extends: List[str] = []

        # Get parent class
        if type_def.parent_index >= 0:
            parent = self.il2cpp.types[type_def.parent_index]
            parent_name = self.executor.get_type_name(parent, False, False)
            if not type_def.is_value_type and not type_def.is_enum and parent_name != "object":
                extends.append(parent_name)

        # Get interfaces
        if type_def.interfaces_count > 0:
            for i in range(type_def.interfaces_count):
                interface = self.il2cpp.types[
                    self.metadata.interface_indices[type_def.interfaces_start + i]
                ]
                extends.append(self.executor.get_type_name(interface, False, False))

        # Write namespace
        namespace = self.metadata.get_string_from_index(type_def.namespace_index)
        writer.write(f"\n// Namespace: {namespace}\n")

        # Write attributes
        if config.dump_attribute:
            self._write_custom_attributes(writer, image_def, type_def.custom_attribute_index, type_def.token)

            if (type_def.flags & TypeAttributes.TYPE_ATTRIBUTE_SERIALIZABLE) != 0:
                writer.write("[Serializable]\n")

        # Write visibility
        visibility = type_def.flags & TypeAttributes.TYPE_ATTRIBUTE_VISIBILITY_MASK
        visibility_str = self._get_type_visibility(visibility)
        writer.write(visibility_str)

        # Write modifiers
        if (type_def.flags & TypeAttributes.TYPE_ATTRIBUTE_ABSTRACT) != 0 and \
           (type_def.flags & TypeAttributes.TYPE_ATTRIBUTE_SEALED) != 0:
            writer.write("static ")
        elif (type_def.flags & TypeAttributes.TYPE_ATTRIBUTE_INTERFACE) == 0 and \
             (type_def.flags & TypeAttributes.TYPE_ATTRIBUTE_ABSTRACT) != 0:
            writer.write("abstract ")
        elif not type_def.is_value_type and not type_def.is_enum and \
             (type_def.flags & TypeAttributes.TYPE_ATTRIBUTE_SEALED) != 0:
            writer.write("sealed ")

        # Write type kind
        if (type_def.flags & TypeAttributes.TYPE_ATTRIBUTE_INTERFACE) != 0:
            writer.write("interface ")
        elif type_def.is_enum:
            writer.write("enum ")
        elif type_def.is_value_type:
            writer.write("struct ")
        else:
            writer.write("class ")

        # Write type name
        type_name = self.executor.get_type_def_name(type_def, False, True)
        writer.write(type_name)

        # Write extends/implements
        if extends:
            writer.write(f" : {', '.join(extends)}")

        # Write type def index
        if config.dump_type_def_index:
            writer.write(f" // TypeDefIndex: {type_def_index}\n{{")
        else:
            writer.write("\n{")

        # Dump fields
        if config.dump_field and type_def.field_count > 0:
            self._dump_fields(writer, type_def, type_def_index, image_def, config)

        # Dump properties
        if config.dump_property and type_def.property_count > 0:
            self._dump_properties(writer, type_def, image_def, config)

        # Dump methods
        if config.dump_method and type_def.method_count > 0:
            self._dump_methods(writer, type_def, image_def, image_name, config)

        writer.write("}\n")

    def _dump_fields(
        self,
        writer: TextIO,
        type_def: Il2CppTypeDefinition,
        type_def_index: int,
        image_def: Il2CppImageDefinition,
        config: 'Config'
    ) -> None:
        """Dump type fields."""
        writer.write("\n\t// Fields\n")
        field_end = type_def.field_start + type_def.field_count

        for i in range(type_def.field_start, field_end):
            field_def = self.metadata.field_defs[i]
            field_type = self.il2cpp.types[field_def.type_index]
            is_static = False
            is_const = False

            # Write attributes
            if config.dump_attribute:
                self._write_custom_attributes(
                    writer, image_def, field_def.custom_attribute_index,
                    field_def.token, "\t"
                )

            writer.write("\t")

            # Write visibility
            access = field_type.attrs & FieldAttributes.FIELD_ATTRIBUTE_FIELD_ACCESS_MASK
            writer.write(self._get_field_visibility(access))

            # Write modifiers
            if (field_type.attrs & FieldAttributes.FIELD_ATTRIBUTE_LITERAL) != 0:
                is_const = True
                writer.write("const ")
            else:
                if (field_type.attrs & FieldAttributes.FIELD_ATTRIBUTE_STATIC) != 0:
                    is_static = True
                    writer.write("static ")
                if (field_type.attrs & FieldAttributes.FIELD_ATTRIBUTE_INIT_ONLY) != 0:
                    writer.write("readonly ")

            # Write type and name
            field_type_name = self.executor.get_type_name(field_type, False, False)
            field_name = self.metadata.get_string_from_index(field_def.name_index)
            writer.write(f"{field_type_name} {field_name}")

            # Write default value
            default_value = self.metadata.get_field_default_value_from_index(i)
            if default_value and default_value.data_index != -1:
                success, value = self.executor.try_get_default_value(
                    default_value.type_index, default_value.data_index
                )
                if success:
                    writer.write(" = ")
                    if isinstance(value, str):
                        writer.write(f'"{escape_string(value)}"')
                    elif isinstance(value, bool):
                        writer.write("true" if value else "false")
                    elif value is None:
                        writer.write("null")
                    else:
                        writer.write(str(value))
                else:
                    writer.write(f" /*Metadata offset 0x{value:X}*/")

            # Write field offset
            if config.dump_field_offset and not is_const:
                offset = self.il2cpp.get_field_offset_from_index(
                    type_def_index,
                    i - type_def.field_start,
                    i,
                    type_def.is_value_type,
                    is_static
                )
                writer.write(f"; // 0x{offset:X}\n")
            else:
                writer.write(";\n")

    def _dump_properties(
        self,
        writer: TextIO,
        type_def: Il2CppTypeDefinition,
        image_def: Il2CppImageDefinition,
        config: 'Config'
    ) -> None:
        """Dump type properties."""
        writer.write("\n\t// Properties\n")
        property_end = type_def.property_start + type_def.property_count

        for i in range(type_def.property_start, property_end):
            property_def = self.metadata.property_defs[i]

            # Write attributes
            if config.dump_attribute:
                self._write_custom_attributes(
                    writer, image_def, property_def.custom_attribute_index,
                    property_def.token, "\t"
                )

            writer.write("\t")

            # Get property type from getter or setter
            if property_def.get >= 0:
                method_def = self.metadata.method_defs[type_def.method_start + property_def.get]
                writer.write(self._get_modifiers(method_def))
                property_type = self.il2cpp.types[method_def.return_type]
                property_type_name = self.executor.get_type_name(property_type, False, False)
            elif property_def.set >= 0:
                method_def = self.metadata.method_defs[type_def.method_start + property_def.set]
                writer.write(self._get_modifiers(method_def))
                param_def = self.metadata.parameter_defs[method_def.parameter_start]
                property_type = self.il2cpp.types[param_def.type_index]
                property_type_name = self.executor.get_type_name(property_type, False, False)
            else:
                property_type_name = "object"

            property_name = self.metadata.get_string_from_index(property_def.name_index)
            writer.write(f"{property_type_name} {property_name} {{ ")

            if property_def.get >= 0:
                writer.write("get; ")
            if property_def.set >= 0:
                writer.write("set; ")

            writer.write("}\n")

    def _dump_methods(
        self,
        writer: TextIO,
        type_def: Il2CppTypeDefinition,
        image_def: Il2CppImageDefinition,
        image_name: str,
        config: 'Config'
    ) -> None:
        """Dump type methods."""
        writer.write("\n\t// Methods\n")
        method_end = type_def.method_start + type_def.method_count

        for i in range(type_def.method_start, method_end):
            writer.write("\n")
            method_def = self.metadata.method_defs[i]
            is_abstract = (method_def.flags & MethodAttributes.METHOD_ATTRIBUTE_ABSTRACT) != 0

            # Write attributes
            if config.dump_attribute:
                self._write_custom_attributes(
                    writer, image_def, method_def.custom_attribute_index,
                    method_def.token, "\t"
                )

            # Write method offset
            if config.dump_method_offset:
                method_pointer = self.il2cpp.get_method_pointer(image_name, method_def)
                if not is_abstract and method_pointer > 0:
                    rva = self.il2cpp.get_rva(method_pointer)
                    offset = self.il2cpp.map_vatr(method_pointer)
                    writer.write(f"\t// RVA: 0x{rva:X} Offset: 0x{offset:X} VA: 0x{method_pointer:X}")
                else:
                    writer.write("\t// RVA: -1 Offset: -1")

                if method_def.slot != 0xFFFF:
                    writer.write(f" Slot: {method_def.slot}")
                writer.write("\n")

            writer.write("\t")
            writer.write(self._get_modifiers(method_def))

            # Return type
            return_type = self.il2cpp.types[method_def.return_type]
            method_name = self.metadata.get_string_from_index(method_def.name_index)

            # Add generic parameters
            if method_def.generic_container_index >= 0:
                generic_container = self.metadata.generic_containers[method_def.generic_container_index]
                method_name += self.executor._get_generic_container_params(generic_container)

            # ref return type
            if return_type.byref == 1:
                writer.write("ref ")

            return_type_name = self.executor.get_type_name(return_type, False, False)
            writer.write(f"{return_type_name} {method_name}(")

            # Parameters
            params = []
            for j in range(method_def.parameter_count):
                param_str = ""
                param_def = self.metadata.parameter_defs[method_def.parameter_start + j]
                param_name = self.metadata.get_string_from_index(param_def.name_index)
                param_type = self.il2cpp.types[param_def.type_index]
                param_type_name = self.executor.get_type_name(param_type, False, False)

                # ref/out/in
                if param_type.byref == 1:
                    if (param_type.attrs & ParamAttributes.PARAM_ATTRIBUTE_OUT) != 0 and \
                       (param_type.attrs & ParamAttributes.PARAM_ATTRIBUTE_IN) == 0:
                        param_str += "out "
                    elif (param_type.attrs & ParamAttributes.PARAM_ATTRIBUTE_OUT) == 0 and \
                         (param_type.attrs & ParamAttributes.PARAM_ATTRIBUTE_IN) != 0:
                        param_str += "in "
                    else:
                        param_str += "ref "
                else:
                    if (param_type.attrs & ParamAttributes.PARAM_ATTRIBUTE_IN) != 0:
                        param_str += "[In] "
                    if (param_type.attrs & ParamAttributes.PARAM_ATTRIBUTE_OUT) != 0:
                        param_str += "[Out] "

                param_str += f"{param_type_name} {param_name}"

                # Default value
                default_value = self.metadata.get_parameter_default_value_from_index(
                    method_def.parameter_start + j
                )
                if default_value and default_value.data_index != -1:
                    success, value = self.executor.try_get_default_value(
                        default_value.type_index, default_value.data_index
                    )
                    if success:
                        param_str += " = "
                        if isinstance(value, str):
                            param_str += f'"{escape_string(value)}"'
                        elif isinstance(value, bool):
                            param_str += "true" if value else "false"
                        elif value is None:
                            param_str += "null"
                        else:
                            param_str += str(value)
                    else:
                        param_str += f" /*Metadata offset 0x{value:X}*/"

                params.append(param_str)

            writer.write(", ".join(params))

            if is_abstract:
                writer.write(");\n")
            else:
                writer.write(") { }\n")

            # Write generic method instances
            if i in self.il2cpp.method_definition_method_specs:
                method_specs = self.il2cpp.method_definition_method_specs[i]
                writer.write("\t/* GenericInstMethod :\n")

                # Group by pointer
                groups: Dict[int, List] = {}
                for spec in method_specs:
                    ptr = self.il2cpp.method_spec_generic_method_pointers.get(id(spec), 0)
                    if ptr not in groups:
                        groups[ptr] = []
                    groups[ptr].append(spec)

                for ptr, specs in groups.items():
                    writer.write("\t|\n")
                    if ptr > 0:
                        rva = self.il2cpp.get_rva(ptr)
                        offset = self.il2cpp.map_vatr(ptr)
                        writer.write(f"\t|-RVA: 0x{rva:X} Offset: 0x{offset:X} VA: 0x{ptr:X}\n")
                    else:
                        writer.write("\t|-RVA: -1 Offset: -1\n")

                    for spec in specs:
                        type_name, method_name = self.executor.get_method_spec_name(spec)
                        writer.write(f"\t|-{type_name}.{method_name}\n")

                writer.write("\t*/\n")

    def _write_custom_attributes(
        self,
        writer: TextIO,
        image_def: Il2CppImageDefinition,
        custom_attribute_index: int,
        token: int,
        padding: str = ""
    ) -> None:
        """Write custom attributes for a member."""
        if self.il2cpp.version < 21:
            return

        attr_index = self.metadata.get_custom_attribute_index(
            image_def, custom_attribute_index, token
        )

        if attr_index >= 0 and self.il2cpp.version < 29:
            method_pointer = self.executor.custom_attribute_generators[attr_index]
            rva = self.il2cpp.get_rva(method_pointer)
            offset = self.il2cpp.map_vatr(method_pointer)

            attr_range = self.metadata.attribute_type_ranges[attr_index]
            for i in range(attr_range.count):
                type_index = self.metadata.attribute_types[attr_range.start + i]
                type_name = self.executor.get_type_name(
                    self.il2cpp.types[type_index], False, False
                )
                writer.write(
                    f"{padding}[{type_name}] // RVA: 0x{rva:X} Offset: 0x{offset:X} VA: 0x{method_pointer:X}\n"
                )

    def _get_modifiers(self, method_def: Il2CppMethodDefinition) -> str:
        """Get method modifiers string."""
        # Cache by flags value (much faster than id-based)
        flags = method_def.flags
        if flags in Il2CppDecompiler._MODIFIER_CACHE:
            return Il2CppDecompiler._MODIFIER_CACHE[flags]

        result = ""

        # Access - use plain int comparisons
        access = flags & 0x0007  # METHOD_ATTRIBUTE_MEMBER_ACCESS_MASK
        if access == 0x0001:  # PRIVATE
            result += "private "
        elif access == 0x0006:  # PUBLIC
            result += "public "
        elif access == 0x0004:  # FAMILY
            result += "protected "
        elif access in (0x0003, 0x0002):  # ASSEM, FAM_AND_ASSEM
            result += "internal "
        elif access == 0x0005:  # FAM_OR_ASSEM
            result += "protected internal "

        # Static
        if (flags & 0x0010) != 0:  # STATIC
            result += "static "

        # Abstract/virtual/override
        if (flags & 0x0400) != 0:  # ABSTRACT
            result += "abstract "
            if (flags & 0x0100) == 0x0000:  # REUSE_SLOT
                result += "override "
        elif (flags & 0x0020) != 0:  # FINAL
            if (flags & 0x0100) == 0x0000:  # REUSE_SLOT
                result += "sealed override "
        elif (flags & 0x0040) != 0:  # VIRTUAL
            if (flags & 0x0100) == 0x0100:  # NEW_SLOT
                result += "virtual "
            else:
                result += "override "

        # Extern
        if (flags & 0x2000) != 0:  # PINVOKE_IMPL
            result += "extern "

        Il2CppDecompiler._MODIFIER_CACHE[flags] = result
        return result

    def _get_type_visibility(self, visibility: int) -> str:
        """Get type visibility string."""
        if visibility in (TypeAttributes.TYPE_ATTRIBUTE_PUBLIC,
                          TypeAttributes.TYPE_ATTRIBUTE_NESTED_PUBLIC):
            return "public "
        elif visibility in (TypeAttributes.TYPE_ATTRIBUTE_NOT_PUBLIC,
                            TypeAttributes.TYPE_ATTRIBUTE_NESTED_FAM_AND_ASSEM,
                            TypeAttributes.TYPE_ATTRIBUTE_NESTED_ASSEMBLY):
            return "internal "
        elif visibility == TypeAttributes.TYPE_ATTRIBUTE_NESTED_PRIVATE:
            return "private "
        elif visibility == TypeAttributes.TYPE_ATTRIBUTE_NESTED_FAMILY:
            return "protected "
        elif visibility == TypeAttributes.TYPE_ATTRIBUTE_NESTED_FAM_OR_ASSEM:
            return "protected internal "
        return ""

    def _get_field_visibility(self, access: int) -> str:
        """Get field visibility string."""
        if access == FieldAttributes.FIELD_ATTRIBUTE_PRIVATE:
            return "private "
        elif access == FieldAttributes.FIELD_ATTRIBUTE_PUBLIC:
            return "public "
        elif access == FieldAttributes.FIELD_ATTRIBUTE_FAMILY:
            return "protected "
        elif access in (FieldAttributes.FIELD_ATTRIBUTE_ASSEMBLY,
                        FieldAttributes.FIELD_ATTRIBUTE_FAM_AND_ASSEM):
            return "internal "
        elif access == FieldAttributes.FIELD_ATTRIBUTE_FAM_OR_ASSEM:
            return "protected internal "
        return ""
