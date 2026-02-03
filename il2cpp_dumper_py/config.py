"""
Configuration handling for IL2CPP Dumper.
"""

from dataclasses import dataclass, field, fields as dataclass_fields
from typing import Optional
import json
from pathlib import Path


@dataclass
class Config:
    """Configuration options for IL2CPP Dumper."""

    # Dump options
    dump_method: bool = True
    dump_field: bool = True
    dump_property: bool = False
    dump_attribute: bool = False
    dump_field_offset: bool = True
    dump_method_offset: bool = True
    dump_type_def_index: bool = True

    # Generation options
    generate_dummy_dll: bool = True
    generate_struct: bool = True
    dummy_dll_add_token: bool = True

    # Runtime options
    require_any_key: bool = True

    # Version override
    force_il2cpp_version: bool = False
    force_version: float = 24.3

    # Advanced options
    force_dump: bool = False
    no_redirected_pointer: bool = False

    @classmethod
    def load(cls, path: Optional[Path] = None) -> 'Config':
        """Load configuration from a JSON file."""
        if path is None:
            path = Path(__file__).parent / 'config.json'

        if not path.exists():
            return cls()

        with open(path, 'r') as f:
            data = json.load(f)

        # Convert camelCase to snake_case
        # Handle special cases like 'Il2Cpp' -> 'il2cpp'
        converted = {}
        for key, value in data.items():
            # Replace Il2Cpp with il2cpp before general conversion
            key = key.replace('Il2Cpp', 'Il2cpp')
            snake_key = ''.join(
                f'_{c.lower()}' if c.isupper() else c
                for c in key
            ).lstrip('_')
            converted[snake_key] = value

        # Filter to only include valid fields
        valid_fields = {f.name for f in dataclass_fields(cls)}
        filtered = {k: v for k, v in converted.items() if k in valid_fields}

        return cls(**filtered)

    def save(self, path: Path) -> None:
        """Save configuration to a JSON file."""
        # Convert snake_case to camelCase for compatibility
        data = {}
        for key, value in self.__dict__.items():
            camel_key = ''.join(
                word.capitalize() if i > 0 else word
                for i, word in enumerate(key.split('_'))
            )
            data[camel_key] = value

        with open(path, 'w') as f:
            json.dump(data, f, indent=2)
