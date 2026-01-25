"""Text processing utilities."""

from __future__ import annotations

import re

from snyk_ai.utils.markdown import Block, BlockType


# sentence boundary: period/exclamation/question followed by space and capital
_SENTENCE_BOUNDARY = re.compile(r"(?<=[.!?])\s+(?=[A-Z])")


def split_into_sentences(text: str) -> list[str]:
    """Split text into sentences.

    Uses a simple heuristic: split on sentence-ending punctuation (.!?)
    followed by whitespace and a capital letter.

    Args:
        text: The text to split.

    Returns:
        List of sentences (stripped of leading/trailing whitespace).
        Returns empty list if text is empty or whitespace-only.
    """
    if not text or not (text := text.strip()):
        return []
    sentences = _SENTENCE_BOUNDARY.split(text)
    return [s.strip() for s in sentences if s.strip()]


def format_table_row(headers: list[str], values: list[str]) -> str:
    """Format a table row as a key-value string.

    Converts a table row into a string like: key1: "val1", key2: "val2"
    where keys are derived from headers (lowercased, spaces replaced with underscores).

    Args:
        headers: Column headers for the table.
        values: Cell values for this row.

    Returns:
        Formatted string representation of the row.
    """
    parts = []
    for header, value in zip(headers, values):
        key = header.lower().replace(" ", "_")
        parts.append(f'{key}: "{value}"')
    return ", ".join(parts)


def format_table_block(block: Block) -> list[str]:
    """Format a table block as a list of key-value strings.

    Converts each data row in the table to a key-value string representation.

    Args:
        block: A Block of type TABLE with header and rows attributes.

    Returns:
        List of formatted strings, one per data row.

    Raises:
        ValueError: If block is not of type TABLE, or has no header, or has no rows.
    """
    if block.type is not BlockType.TABLE:
        raise ValueError(f"Expected TABLE block, got {block.type.value}")
    if block.header is None:
        raise ValueError("TABLE block has no header")
    if block.rows is None:
        raise ValueError("TABLE block has no rows")
    return [format_table_row(block.header, row) for row in block.rows]
