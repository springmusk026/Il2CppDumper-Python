"""
String utility functions.
"""


def escape_string(s: str) -> str:
    """
    Escape a string for C# output.

    Args:
        s: Input string

    Returns:
        Escaped string safe for inclusion in C# source
    """
    result = []
    for char in s:
        if char == '\\':
            result.append('\\\\')
        elif char == '"':
            result.append('\\"')
        elif char == '\n':
            result.append('\\n')
        elif char == '\r':
            result.append('\\r')
        elif char == '\t':
            result.append('\\t')
        elif char == '\0':
            result.append('\\0')
        elif ord(char) < 32 or ord(char) > 126:
            # Non-printable characters
            result.append(f'\\x{ord(char):02x}')
        else:
            result.append(char)
    return ''.join(result)


def to_camel_case(snake_str: str) -> str:
    """
    Convert snake_case to camelCase.

    Args:
        snake_str: String in snake_case

    Returns:
        String in camelCase
    """
    components = snake_str.split('_')
    return components[0] + ''.join(x.title() for x in components[1:])


def to_pascal_case(snake_str: str) -> str:
    """
    Convert snake_case to PascalCase.

    Args:
        snake_str: String in snake_case

    Returns:
        String in PascalCase
    """
    components = snake_str.split('_')
    return ''.join(x.title() for x in components)


def to_snake_case(camel_str: str) -> str:
    """
    Convert camelCase or PascalCase to snake_case.

    Args:
        camel_str: String in camelCase or PascalCase

    Returns:
        String in snake_case
    """
    result = []
    for i, char in enumerate(camel_str):
        if char.isupper() and i > 0:
            result.append('_')
        result.append(char.lower())
    return ''.join(result)
