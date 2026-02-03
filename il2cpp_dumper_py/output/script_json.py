"""
Script JSON output structures.

These structures define the JSON format used for IDA/Ghidra integration scripts.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
import json


@dataclass
class ScriptMethod:
    """Method information for script.json."""
    Address: int = 0
    Name: str = ""
    Signature: str = ""
    TypeSignature: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "Address": self.Address,
            "Name": self.Name,
            "Signature": self.Signature,
            "TypeSignature": self.TypeSignature
        }


@dataclass
class ScriptString:
    """String literal information for stringliteral.json."""
    Address: int = 0
    Value: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "Address": self.Address,
            "Value": self.Value
        }


@dataclass
class ScriptMetadata:
    """Metadata usage information."""
    Address: int = 0
    Name: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "Address": self.Address,
            "Name": self.Name
        }


@dataclass
class ScriptMetadataMethod:
    """Metadata method information."""
    Address: int = 0
    Name: str = ""
    MethodAddress: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "Address": self.Address,
            "Name": self.Name,
            "MethodAddress": self.MethodAddress
        }


@dataclass
class ScriptJson:
    """
    Complete script.json structure for IDA/Ghidra scripts.

    This contains all the information needed to annotate the
    binary in a reverse engineering tool.
    """
    ScriptMethod: List[ScriptMethod] = field(default_factory=list)
    ScriptString: List[ScriptString] = field(default_factory=list)
    ScriptMetadata: List[ScriptMetadata] = field(default_factory=list)
    ScriptMetadataMethod: List[ScriptMetadataMethod] = field(default_factory=list)
    Addresses: List[int] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ScriptMethod": [m.to_dict() for m in self.ScriptMethod],
            "ScriptString": [s.to_dict() for s in self.ScriptString],
            "ScriptMetadata": [m.to_dict() for m in self.ScriptMetadata],
            "ScriptMetadataMethod": [m.to_dict() for m in self.ScriptMetadataMethod],
            "Addresses": self.Addresses
        }

    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def save(self, path: str) -> None:
        """Save to file."""
        with open(path, 'w', encoding='utf-8') as f:
            f.write(self.to_json())


@dataclass
class StringLiteralJson:
    """String literal JSON output."""
    Address: int = 0
    Value: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "Address": self.Address,
            "Value": self.Value
        }
