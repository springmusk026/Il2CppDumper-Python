"""
Metadata parser for global-metadata.dat files.

This module parses the IL2CPP metadata file which contains all .NET type information
including class definitions, method definitions, field definitions, string literals, etc.
"""

from typing import Dict, List, Optional, Tuple, Any
from dataclasses import fields

from ..io.binary_stream import BinaryStream
from .structures import (
    Il2CppGlobalMetadataHeader,
    Il2CppImageDefinition,
    Il2CppAssemblyDefinition,
    Il2CppTypeDefinition,
    Il2CppMethodDefinition,
    Il2CppParameterDefinition,
    Il2CppFieldDefinition,
    Il2CppFieldDefaultValue,
    Il2CppParameterDefaultValue,
    Il2CppPropertyDefinition,
    Il2CppEventDefinition,
    Il2CppGenericContainer,
    Il2CppGenericParameter,
    Il2CppCustomAttributeTypeRange,
    Il2CppCustomAttributeDataRange,
    Il2CppMetadataUsageList,
    Il2CppMetadataUsagePair,
    Il2CppStringLiteral,
    Il2CppFieldRef,
    Il2CppRGCTXDefinition,
)
from .enums import Il2CppMetadataUsage


class Metadata(BinaryStream):
    """
    Parser for IL2CPP global-metadata.dat files.

    The metadata file contains all .NET type information including:
    - Type definitions (classes, structs, enums, interfaces)
    - Method definitions
    - Field definitions
    - Property and event definitions
    - String literals
    - Generic type information
    - Custom attributes

    Attributes:
        header: The metadata file header
        image_defs: Assembly image definitions
        type_defs: Type definitions
        method_defs: Method definitions
        field_defs: Field definitions
        string_literals: String literal definitions
    """

    MAGIC = 0xFAB11BAF

    def __init__(self, data: bytes):
        """
        Initialize the metadata parser.

        Args:
            data: Raw bytes of the global-metadata.dat file

        Raises:
            ValueError: If the file is not a valid metadata file
            NotSupportedError: If the metadata version is not supported
        """
        super().__init__(data)

        # Validate magic number
        sanity = self.read_uint32()
        if sanity != self.MAGIC:
            raise ValueError("Invalid metadata file: wrong magic number")

        # Read and validate version
        version = self.read_int32()
        if version < 0 or version > 1000:
            raise ValueError("Invalid metadata file: invalid version")
        if version < 16 or version > 31:
            raise NotSupportedError(f"Metadata version {version} is not supported")

        self.version = float(version)

        # Read header
        self.position = 0
        self.header = self._read_header()

        # Detect sub-versions
        self._detect_subversion()

        # Load all metadata arrays
        self._load_metadata()

        # Build lookup dictionaries
        self._build_lookups()

    def _read_header(self) -> Il2CppGlobalMetadataHeader:
        """Read the metadata header with version-aware parsing."""
        return self.read_class(Il2CppGlobalMetadataHeader)

    def _detect_subversion(self) -> None:
        """Detect sub-versions (e.g., 24.1, 24.2) based on header values."""
        if self.version == 24:
            # Check for 24.2
            if self.header.string_literal_offset == 264:
                self.version = 24.2
                self.position = 0
                self.header = self._read_header()
            else:
                # Check for 24.1 by examining image definitions
                self.image_defs = self._read_metadata_array(
                    Il2CppImageDefinition,
                    self.header.images_offset,
                    self.header.images_size
                )
                if any(img.token != 1 for img in self.image_defs):
                    self.version = 24.1

        # Re-read header with correct version
        if self.version != 24:
            self.position = 0
            self.header = self._read_header()

    def _load_metadata(self) -> None:
        """Load all metadata arrays from the file."""
        h = self.header

        # Image definitions
        self.image_defs = self._read_metadata_array(
            Il2CppImageDefinition, h.images_offset, h.images_size
        )

        # Detect more sub-versions
        if self.version == 24.2 and h.assemblies_size // 68 < len(self.image_defs):
            self.version = 24.4

        # Assembly definitions
        self.assembly_defs = self._read_metadata_array(
            Il2CppAssemblyDefinition, h.assemblies_offset, h.assemblies_size
        )

        # Type definitions
        self.type_defs = self._read_metadata_array(
            Il2CppTypeDefinition, h.type_definitions_offset, h.type_definitions_size
        )

        # Method definitions
        self.method_defs = self._read_metadata_array(
            Il2CppMethodDefinition, h.methods_offset, h.methods_size
        )

        # Parameter definitions
        self.parameter_defs = self._read_metadata_array(
            Il2CppParameterDefinition, h.parameters_offset, h.parameters_size
        )

        # Field definitions
        self.field_defs = self._read_metadata_array(
            Il2CppFieldDefinition, h.fields_offset, h.fields_size
        )

        # Default values
        field_default_values = self._read_metadata_array(
            Il2CppFieldDefaultValue, h.field_default_values_offset, h.field_default_values_size
        )
        self._field_default_values_dic = {v.field_index: v for v in field_default_values}

        param_default_values = self._read_metadata_array(
            Il2CppParameterDefaultValue, h.parameter_default_values_offset, h.parameter_default_values_size
        )
        self._param_default_values_dic = {v.parameter_index: v for v in param_default_values}

        # Property definitions
        self.property_defs = self._read_metadata_array(
            Il2CppPropertyDefinition, h.properties_offset, h.properties_size
        )

        # Interface indices
        self.interface_indices = self.read_int32_array(
            h.interfaces_offset, h.interfaces_size // 4
        )

        # Nested type indices
        self.nested_type_indices = self.read_int32_array(
            h.nested_types_offset, h.nested_types_size // 4
        )

        # Event definitions
        self.event_defs = self._read_metadata_array(
            Il2CppEventDefinition, h.events_offset, h.events_size
        )

        # Generic containers
        self.generic_containers = self._read_metadata_array(
            Il2CppGenericContainer, h.generic_containers_offset, h.generic_containers_size
        )

        # Generic parameters
        self.generic_parameters = self._read_metadata_array(
            Il2CppGenericParameter, h.generic_parameters_offset, h.generic_parameters_size
        )

        # Constraint indices
        self.constraint_indices = self.read_int32_array(
            h.generic_parameter_constraints_offset,
            h.generic_parameter_constraints_size // 4
        )

        # VTable methods
        self.vtable_methods = self.read_uint32_array(
            h.vtable_methods_offset, h.vtable_methods_size // 4
        )

        # String literals
        self.string_literals = self._read_metadata_array(
            Il2CppStringLiteral, h.string_literal_offset, h.string_literal_size
        )

        # Field refs (v19+)
        if self.version > 16:
            self.field_refs = self._read_metadata_array(
                Il2CppFieldRef, h.field_refs_offset, h.field_refs_size
            )

            # Metadata usage (v17-26)
            if self.version < 27:
                self._metadata_usage_lists = self._read_metadata_array(
                    Il2CppMetadataUsageList,
                    h.metadata_usage_lists_offset,
                    h.metadata_usage_lists_count
                )
                self._metadata_usage_pairs = self._read_metadata_array(
                    Il2CppMetadataUsagePair,
                    h.metadata_usage_pairs_offset,
                    h.metadata_usage_pairs_count
                )
                self._process_metadata_usage()

        # Attribute type ranges (v21-28)
        if 20 < self.version < 29:
            self.attribute_type_ranges = self._read_metadata_array(
                Il2CppCustomAttributeTypeRange,
                h.attributes_info_offset,
                h.attributes_info_count
            )
            self.attribute_types = self.read_int32_array(
                h.attribute_types_offset, h.attribute_types_count // 4
            )

        # Attribute data ranges (v29+)
        if self.version >= 29:
            self.attribute_data_ranges = self._read_metadata_array(
                Il2CppCustomAttributeDataRange,
                h.attribute_data_range_offset,
                h.attribute_data_range_size
            )

        # Build attribute lookup (v24.1+)
        if self.version > 24:
            self._build_attribute_lookup()

        # RGCTX entries (v16-24.1)
        if self.version <= 24.1:
            self.rgctx_entries = self._read_metadata_array(
                Il2CppRGCTXDefinition,
                h.rgctx_entries_offset,
                h.rgctx_entries_count
            )

        # Calculate metadata usages count
        self.metadata_usages_count = self._calculate_metadata_usages_count()

    def _read_metadata_array(self, cls, offset: int, size: int) -> List:
        """Read an array of metadata structures using optimized batch reading."""
        if offset == 0 or size == 0:
            return []

        element_size = self.size_of(cls)
        if element_size == 0:
            return []

        count = size // element_size
        self.position = offset
        return self.read_class_array_fast(cls, count=count)

    def _build_lookups(self) -> None:
        """Build lookup dictionaries for fast access."""
        self._string_cache: Dict[int, str] = {}

    def _build_attribute_lookup(self) -> None:
        """Build attribute type range lookup by token."""
        self._attribute_type_ranges_dic: Dict[int, Dict[int, int]] = {}

        for image_def in self.image_defs:
            dic: Dict[int, int] = {}
            self._attribute_type_ranges_dic[id(image_def)] = dic

            end = image_def.custom_attribute_start + image_def.custom_attribute_count
            for i in range(image_def.custom_attribute_start, end):
                if self.version >= 29:
                    dic[self.attribute_data_ranges[i].token] = i
                else:
                    dic[self.attribute_type_ranges[i].token] = i

    def _process_metadata_usage(self) -> None:
        """Process metadata usage lists and pairs."""
        self.metadata_usage_dic: Dict[int, Dict[int, int]] = {
            i: {} for i in range(1, 7)
        }

        for usage_list in self._metadata_usage_lists:
            for i in range(usage_list.count):
                offset = usage_list.start + i
                if offset >= len(self._metadata_usage_pairs):
                    continue

                pair = self._metadata_usage_pairs[offset]
                usage = self._get_encoded_index_type(pair.encoded_source_index)
                decoded = self._get_decoded_method_index(pair.encoded_source_index)

                if 1 <= usage <= 6:
                    self.metadata_usage_dic[usage][pair.destination_index] = decoded

    def _calculate_metadata_usages_count(self) -> int:
        """Calculate total metadata usages count."""
        if not hasattr(self, 'metadata_usage_dic'):
            return 0

        max_index = 0
        for dic in self.metadata_usage_dic.values():
            if dic:
                max_index = max(max_index, max(dic.keys()))

        return max_index + 1

    def _get_encoded_index_type(self, index: int) -> int:
        """Get the type from an encoded index."""
        return (index & 0xE0000000) >> 29

    def _get_decoded_method_index(self, index: int) -> int:
        """Decode a method index."""
        if self.version >= 27:
            return (index & 0x1FFFFFFE) >> 1
        return index & 0x1FFFFFFF

    # ========== Public API ==========

    def get_string_from_index(self, index: int) -> str:
        """
        Get a string from the string table by index.

        Args:
            index: Index into the string table

        Returns:
            The decoded string
        """
        if index in self._string_cache:
            return self._string_cache[index]

        result = self.read_string_to_null(self.header.string_offset + index)
        self._string_cache[index] = result
        return result

    def get_string_literal_from_index(self, index: int) -> str:
        """
        Get a string literal by index.

        Args:
            index: Index into the string literals array

        Returns:
            The decoded string literal
        """
        string_literal = self.string_literals[index]
        self.position = self.header.string_literal_data_offset + string_literal.data_index
        return self.read_bytes(string_literal.length).decode('utf-8', errors='replace')

    def get_field_default_value_from_index(self, index: int) -> Optional[Il2CppFieldDefaultValue]:
        """Get field default value by field index."""
        return self._field_default_values_dic.get(index)

    def get_parameter_default_value_from_index(self, index: int) -> Optional[Il2CppParameterDefaultValue]:
        """Get parameter default value by parameter index."""
        return self._param_default_values_dic.get(index)

    def get_default_value_from_index(self, index: int) -> int:
        """Get default value data offset."""
        return self.header.field_and_parameter_default_value_data_offset + index

    def get_custom_attribute_index(
        self,
        image_def: Il2CppImageDefinition,
        custom_attribute_index: int,
        token: int
    ) -> int:
        """
        Get custom attribute index for a token.

        Args:
            image_def: The image definition
            custom_attribute_index: Legacy custom attribute index (for v24 and below)
            token: The metadata token

        Returns:
            The custom attribute index, or -1 if not found
        """
        if self.version > 24:
            dic = self._attribute_type_ranges_dic.get(id(image_def), {})
            return dic.get(token, -1)
        else:
            return custom_attribute_index


class NotSupportedError(Exception):
    """Raised when a metadata version is not supported."""
    pass
