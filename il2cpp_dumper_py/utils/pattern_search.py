"""
Pattern search utilities including Boyer-Moore-Horspool algorithm.
"""

from typing import List, Iterator, Optional


def search_pattern(data: bytes, pattern: str) -> List[int]:
    """
    Search for a pattern in binary data.

    The pattern can contain wildcards (?) for any byte value.
    Format: "? 10 ? E7" where ? matches any byte.

    Args:
        data: Binary data to search
        pattern: Pattern string with hex bytes and wildcards

    Returns:
        List of matching indices
    """
    parts = pattern.split()
    pattern_bytes = []
    mask = []

    for part in parts:
        if part == '?':
            pattern_bytes.append(0)
            mask.append(False)
        else:
            # Handle hex values like "0x10" or "10"
            if part.startswith('0x'):
                pattern_bytes.append(int(part, 16))
            else:
                pattern_bytes.append(int(part, 16))
            mask.append(True)

    return boyer_moore_horspool(data, pattern_bytes, mask)


def boyer_moore_horspool(
    data: bytes,
    pattern: List[int],
    mask: Optional[List[bool]] = None
) -> List[int]:
    """
    Boyer-Moore-Horspool pattern matching with wildcard support.

    Args:
        data: Binary data to search
        pattern: Pattern bytes to find
        mask: Boolean mask indicating which bytes to match (True = match, False = wildcard)

    Returns:
        List of matching indices
    """
    if not pattern:
        return []

    if mask is None:
        mask = [True] * len(pattern)

    pattern_len = len(pattern)
    data_len = len(data)

    if pattern_len > data_len:
        return []

    # Build the bad character shift table
    # For wildcards, we use 1 as shift (most conservative)
    shift_table = [pattern_len] * 256

    for i in range(pattern_len - 1):
        if mask[i]:
            shift_table[pattern[i]] = pattern_len - 1 - i

    # Search
    results = []
    i = pattern_len - 1

    while i < data_len:
        j = pattern_len - 1
        k = i

        while j >= 0 and (not mask[j] or data[k] == pattern[j]):
            j -= 1
            k -= 1

        if j < 0:
            results.append(k + 1)
            i += 1
        else:
            # Shift based on the character in data
            i += max(1, shift_table[data[i]])

    return results


def search_bytes(data: bytes, pattern: bytes) -> Iterator[int]:
    """
    Simple byte pattern search.

    Args:
        data: Binary data to search
        pattern: Exact pattern to find

    Yields:
        Indices where pattern was found
    """
    start = 0
    while True:
        index = data.find(pattern, start)
        if index == -1:
            break
        yield index
        start = index + 1


def hex_to_bytes(hex_string: str) -> bytes:
    """
    Convert a hex string to bytes.

    Args:
        hex_string: Hex string (e.g., "48656C6C6F")

    Returns:
        Bytes representation
    """
    return bytes.fromhex(hex_string.replace(' ', ''))


def hex_to_bin(byte: int) -> str:
    """
    Convert a byte to binary string.

    Args:
        byte: Byte value (0-255)

    Returns:
        8-character binary string
    """
    return format(byte, '08b')
