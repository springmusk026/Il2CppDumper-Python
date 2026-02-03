"""
Struct generator for IL2CPP headers and scripts.

Generates:
- il2cpp.h: C header file with struct definitions
- script.json: Method/type information for IDA/Ghidra
- stringliteral.json: String literal addresses
"""

from typing import List, Dict, Set, Optional, TextIO, TYPE_CHECKING
from pathlib import Path
from io import StringIO
import json

if TYPE_CHECKING:
    from ..executor.il2cpp_executor import Il2CppExecutor

from ..il2cpp.structures import (
    Il2CppTypeDefinition,
    Il2CppMethodDefinition,
    Il2CppImageDefinition,
)
from ..il2cpp.enums import Il2CppTypeEnum, TYPE_NAMES, MethodAttributes
from .script_json import ScriptJson, ScriptMethod, ScriptString, ScriptMetadata, ScriptMetadataMethod


# C type mappings for header generation
C_TYPE_MAP = {
    Il2CppTypeEnum.IL2CPP_TYPE_VOID: "void",
    Il2CppTypeEnum.IL2CPP_TYPE_BOOLEAN: "bool",
    Il2CppTypeEnum.IL2CPP_TYPE_CHAR: "uint16_t",
    Il2CppTypeEnum.IL2CPP_TYPE_I1: "int8_t",
    Il2CppTypeEnum.IL2CPP_TYPE_U1: "uint8_t",
    Il2CppTypeEnum.IL2CPP_TYPE_I2: "int16_t",
    Il2CppTypeEnum.IL2CPP_TYPE_U2: "uint16_t",
    Il2CppTypeEnum.IL2CPP_TYPE_I4: "int32_t",
    Il2CppTypeEnum.IL2CPP_TYPE_U4: "uint32_t",
    Il2CppTypeEnum.IL2CPP_TYPE_I8: "int64_t",
    Il2CppTypeEnum.IL2CPP_TYPE_U8: "uint64_t",
    Il2CppTypeEnum.IL2CPP_TYPE_R4: "float",
    Il2CppTypeEnum.IL2CPP_TYPE_R8: "double",
    Il2CppTypeEnum.IL2CPP_TYPE_STRING: "System_String_o*",
    Il2CppTypeEnum.IL2CPP_TYPE_OBJECT: "Il2CppObject*",
    Il2CppTypeEnum.IL2CPP_TYPE_I: "intptr_t",
    Il2CppTypeEnum.IL2CPP_TYPE_U: "uintptr_t",
}


class StructGenerator:
    """
    Generates struct headers and script files for IL2CPP binaries.

    Output files:
    - il2cpp.h: C header with type definitions
    - script.json: Method addresses and signatures
    - stringliteral.json: String literal addresses
    """

    def __init__(self, executor: 'Il2CppExecutor'):
        """
        Initialize the struct generator.

        Args:
            executor: The IL2CPP executor for type resolution
        """
        self.executor = executor
        self.metadata = executor.metadata
        self.il2cpp = executor.il2cpp

        # Track generated type names to avoid duplicates
        self._generated_types: Set[str] = set()
        self._type_name_map: Dict[int, str] = {}

    def write_script(self, output_dir: str) -> None:
        """
        Write all script and header files.

        Args:
            output_dir: Output directory path
        """
        output_path = Path(output_dir)

        # Generate script.json
        self._write_script_json(output_path / "script.json")

        # Generate stringliteral.json
        self._write_string_literal_json(output_path / "stringliteral.json")

        # Generate il2cpp.h
        self._write_header(output_path / "il2cpp.h")

    def _write_script_json(self, path: Path) -> None:
        """Generate script.json with method information."""
        script = ScriptJson()
        addresses_set: Set[int] = set()

        # Process each image
        for image_def in self.metadata.image_defs:
            image_name = self.metadata.get_string_from_index(image_def.name_index)
            type_end = image_def.type_start + image_def.type_count

            for type_def_index in range(image_def.type_start, type_end):
                type_def = self.metadata.type_defs[type_def_index]
                type_name = self.executor.get_type_def_name(type_def, True, False)

                # Process methods
                method_end = type_def.method_start + type_def.method_count
                for method_index in range(type_def.method_start, method_end):
                    method_def = self.metadata.method_defs[method_index]

                    # Skip abstract methods
                    if (method_def.flags & MethodAttributes.METHOD_ATTRIBUTE_ABSTRACT) != 0:
                        continue

                    method_pointer = self.il2cpp.get_method_pointer(image_name, method_def)
                    if method_pointer == 0:
                        continue

                    rva = self.il2cpp.get_rva(method_pointer)
                    addresses_set.add(rva)

                    method_name = self.metadata.get_string_from_index(method_def.name_index)
                    signature = self._get_method_signature(method_def, type_def)

                    script.ScriptMethod.append(ScriptMethod(
                        Address=rva,
                        Name=method_name,
                        Signature=signature,
                        TypeSignature=type_name
                    ))

                    # Process generic method instances
                    if method_index in self.il2cpp.method_definition_method_specs:
                        for method_spec in self.il2cpp.method_definition_method_specs[method_index]:
                            spec_ptr = self.il2cpp.method_spec_generic_method_pointers.get(id(method_spec), 0)
                            if spec_ptr == 0:
                                continue

                            spec_rva = self.il2cpp.get_rva(spec_ptr)
                            if spec_rva in addresses_set:
                                continue

                            addresses_set.add(spec_rva)
                            spec_type_name, spec_method_name = self.executor.get_method_spec_name(method_spec, True)

                            script.ScriptMethod.append(ScriptMethod(
                                Address=spec_rva,
                                Name=spec_method_name,
                                Signature=signature,
                                TypeSignature=spec_type_name
                            ))

        # Add metadata usages
        if self.il2cpp.version < 27:
            self._add_metadata_usages(script, addresses_set)

        script.Addresses = sorted(addresses_set)

        # Write to file
        with open(path, 'w', encoding='utf-8') as f:
            f.write(script.to_json())

    def _add_metadata_usages(self, script: ScriptJson, addresses_set: Set[int]) -> None:
        """Add metadata usage information to script."""
        from ..il2cpp.enums import Il2CppMetadataUsage

        if not hasattr(self.metadata, 'metadata_usage_dic'):
            return

        for usage_type, usage_dict in self.metadata.metadata_usage_dic.items():
            for dest_index, source_index in usage_dict.items():
                if dest_index >= len(self.il2cpp.metadata_usages):
                    continue

                address = self.il2cpp.metadata_usages[dest_index]
                if address == 0:
                    continue

                rva = self.il2cpp.get_rva(address)

                try:
                    if usage_type == Il2CppMetadataUsage.kIl2CppMetadataUsageTypeInfo:
                        type_def = self.metadata.type_defs[source_index]
                        name = self.executor.get_type_def_name(type_def, True, True)
                        script.ScriptMetadata.append(ScriptMetadata(Address=rva, Name=f"{name}_TypeInfo"))

                    elif usage_type == Il2CppMetadataUsage.kIl2CppMetadataUsageIl2CppType:
                        il2cpp_type = self.il2cpp.types[source_index]
                        name = self.executor.get_type_name(il2cpp_type, True, False)
                        script.ScriptMetadata.append(ScriptMetadata(Address=rva, Name=f"{name}_Type"))

                    elif usage_type == Il2CppMetadataUsage.kIl2CppMetadataUsageMethodDef:
                        method_def = self.metadata.method_defs[source_index]
                        type_def = self.metadata.type_defs[method_def.declaring_type]
                        type_name = self.executor.get_type_def_name(type_def, True, True)
                        method_name = self.metadata.get_string_from_index(method_def.name_index)
                        script.ScriptMetadataMethod.append(ScriptMetadataMethod(
                            Address=rva,
                            Name=f"{type_name}.{method_name}",
                            MethodAddress=0
                        ))

                    elif usage_type == Il2CppMetadataUsage.kIl2CppMetadataUsageStringLiteral:
                        string_literal = self.metadata.get_string_literal_from_index(source_index)
                        script.ScriptString.append(ScriptString(Address=rva, Value=string_literal))

                except Exception:
                    pass

    def _write_string_literal_json(self, path: Path) -> None:
        """Generate stringliteral.json."""
        string_literals = []

        for i, sl in enumerate(self.metadata.string_literals):
            try:
                value = self.metadata.get_string_literal_from_index(i)
                string_literals.append({
                    "index": i,
                    "value": value
                })
            except Exception:
                pass

        with open(path, 'w', encoding='utf-8') as f:
            json.dump(string_literals, f, indent=2, ensure_ascii=False)

    def _write_header(self, path: Path) -> None:
        """Generate il2cpp.h C header file."""
        # Use StringIO buffer for better performance
        f = StringIO()

        # Write header guard and includes
        f.write("// Generated by IL2CPP Dumper (Python Port)\n\n")
        f.write("#ifndef IL2CPP_H\n")
        f.write("#define IL2CPP_H\n\n")
        f.write("#include <stdint.h>\n")
        f.write("#include <stdbool.h>\n\n")

        # Write base types
        self._write_base_types(f)

        # Write forward declarations
        f.write("// Forward declarations\n")
        for type_def in self.metadata.type_defs:
            safe_name = self._get_safe_type_name(type_def)
            if safe_name and safe_name not in self._generated_types:
                f.write(f"struct {safe_name}_o;\n")
                self._generated_types.add(safe_name)
        f.write("\n")

        # Reset for actual definitions
        self._generated_types.clear()

        # Write type definitions
        f.write("// Type definitions\n")
        for type_def_index, type_def in enumerate(self.metadata.type_defs):
            self._write_type_definition(f, type_def, type_def_index)

        f.write("\n#endif // IL2CPP_H\n")

        # Write buffer to file
        with open(path, 'w', encoding='utf-8') as out:
            out.write(f.getvalue())

    def _write_base_types(self, f: TextIO) -> None:
        """Write base IL2CPP types."""
        f.write("// Base IL2CPP types\n")
        f.write("typedef struct Il2CppObject {\n")
        f.write("    void* klass;\n")
        f.write("    void* monitor;\n")
        f.write("} Il2CppObject;\n\n")

        f.write("typedef struct System_String_o {\n")
        f.write("    Il2CppObject _base;\n")
        f.write("    int32_t length;\n")
        f.write("    uint16_t chars[1];\n")
        f.write("} System_String_o;\n\n")

        f.write("typedef struct Il2CppArray {\n")
        f.write("    Il2CppObject _base;\n")
        f.write("    void* bounds;\n")
        f.write("    uintptr_t max_length;\n")
        f.write("} Il2CppArray;\n\n")

    def _write_type_definition(self, f: TextIO, type_def: Il2CppTypeDefinition, type_def_index: int) -> None:
        """Write a single type definition."""
        safe_name = self._get_safe_type_name(type_def)
        if not safe_name or safe_name in self._generated_types:
            return

        self._generated_types.add(safe_name)

        # Skip interfaces and enums for now
        if type_def.is_enum:
            self._write_enum_definition(f, type_def, safe_name)
            return

        # Write struct
        f.write(f"// TypeDefIndex: {type_def_index}\n")
        f.write(f"typedef struct {safe_name}_o {{\n")

        # Add base class if any
        if type_def.parent_index >= 0 and not type_def.is_value_type:
            parent_type = self.il2cpp.types[type_def.parent_index]
            parent_name = self.executor.get_type_name(parent_type, False, False)
            if parent_name not in ("object", "ValueType"):
                parent_safe = self._sanitize_name(parent_name)
                f.write(f"    {parent_safe}_o _base;\n")
            else:
                f.write("    Il2CppObject _base;\n")

        # Write fields
        field_end = type_def.field_start + type_def.field_count
        for i in range(type_def.field_start, field_end):
            field_def = self.metadata.field_defs[i]
            field_type = self.il2cpp.types[field_def.type_index]

            # Skip static fields
            from ..il2cpp.enums import FieldAttributes
            if (field_type.attrs & FieldAttributes.FIELD_ATTRIBUTE_STATIC) != 0:
                continue

            field_name = self.metadata.get_string_from_index(field_def.name_index)
            field_type_str = self._get_c_type_name(field_type)
            safe_field_name = self._sanitize_name(field_name)

            offset = self.il2cpp.get_field_offset_from_index(
                type_def_index, i - type_def.field_start, i,
                type_def.is_value_type, False
            )

            f.write(f"    {field_type_str} {safe_field_name}; // 0x{offset:X}\n")

        f.write(f"}} {safe_name}_o;\n\n")

    def _write_enum_definition(self, f: TextIO, type_def: Il2CppTypeDefinition, safe_name: str) -> None:
        """Write an enum definition."""
        f.write(f"typedef enum {safe_name} {{\n")

        field_end = type_def.field_start + type_def.field_count
        for i in range(type_def.field_start, field_end):
            field_def = self.metadata.field_defs[i]
            field_type = self.il2cpp.types[field_def.type_index]

            from ..il2cpp.enums import FieldAttributes
            if (field_type.attrs & FieldAttributes.FIELD_ATTRIBUTE_LITERAL) == 0:
                continue

            field_name = self.metadata.get_string_from_index(field_def.name_index)
            safe_field_name = self._sanitize_name(field_name)

            # Get default value
            default_value = self.metadata.get_field_default_value_from_index(i)
            if default_value and default_value.data_index != -1:
                success, value = self.executor.try_get_default_value(
                    default_value.type_index, default_value.data_index
                )
                if success and isinstance(value, int):
                    f.write(f"    {safe_name}_{safe_field_name} = {value},\n")
                else:
                    f.write(f"    {safe_name}_{safe_field_name},\n")
            else:
                f.write(f"    {safe_name}_{safe_field_name},\n")

        f.write(f"}} {safe_name};\n\n")

    def _get_safe_type_name(self, type_def: Il2CppTypeDefinition) -> str:
        """Get a safe C identifier for a type."""
        namespace = self.metadata.get_string_from_index(type_def.namespace_index)
        name = self.metadata.get_string_from_index(type_def.name_index)

        # Remove generic arity
        backtick = name.find('`')
        if backtick != -1:
            name = name[:backtick]

        full_name = f"{namespace}_{name}" if namespace else name
        return self._sanitize_name(full_name)

    def _sanitize_name(self, name: str) -> str:
        """Sanitize a name to be a valid C identifier."""
        # Replace invalid characters
        result = ""
        for char in name:
            if char.isalnum() or char == '_':
                result += char
            elif char in './<>[]':
                result += '_'

        # Ensure it doesn't start with a digit
        if result and result[0].isdigit():
            result = '_' + result

        return result

    def _get_c_type_name(self, il2cpp_type) -> str:
        """Get C type name for an IL2CPP type."""
        type_enum = Il2CppTypeEnum(il2cpp_type.type)

        if type_enum in C_TYPE_MAP:
            return C_TYPE_MAP[type_enum]

        if type_enum == Il2CppTypeEnum.IL2CPP_TYPE_SZARRAY:
            return "Il2CppArray*"

        if type_enum == Il2CppTypeEnum.IL2CPP_TYPE_PTR:
            return "void*"

        if type_enum in (Il2CppTypeEnum.IL2CPP_TYPE_CLASS, Il2CppTypeEnum.IL2CPP_TYPE_VALUETYPE):
            type_def = self.executor._get_type_definition_from_type(il2cpp_type)
            if type_def:
                safe_name = self._get_safe_type_name(type_def)
                if type_def.is_value_type:
                    return f"{safe_name}_o"
                else:
                    return f"{safe_name}_o*"
            return "void*"

        if type_enum == Il2CppTypeEnum.IL2CPP_TYPE_GENERICINST:
            return "void*"  # Generic instances are complex

        return "void*"

    def _get_method_signature(self, method_def: Il2CppMethodDefinition, type_def: Il2CppTypeDefinition) -> str:
        """Get method signature string."""
        return_type = self.il2cpp.types[method_def.return_type]
        return_type_name = self.executor.get_type_name(return_type, False, False)

        method_name = self.metadata.get_string_from_index(method_def.name_index)

        # Build parameter list
        params = []
        for j in range(method_def.parameter_count):
            param_def = self.metadata.parameter_defs[method_def.parameter_start + j]
            param_type = self.il2cpp.types[param_def.type_index]
            param_type_name = self.executor.get_type_name(param_type, False, False)
            param_name = self.metadata.get_string_from_index(param_def.name_index)
            params.append(f"{param_type_name} {param_name}")

        return f"{return_type_name} {method_name}({', '.join(params)})"
