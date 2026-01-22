"""Utility for parsing markdown documents into structured blocks."""

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class BlockType(Enum):
    HEADER = "header"
    PARAGRAPH = "paragraph"
    CODE_BLOCK = "code_block"
    TABLE = "table"
    LIST = "list"


@dataclass
class Block:
    """A parsed markdown block."""

    type: BlockType
    content: str
    level: int | None = None  # for headers (1-6) and lists (indentation)
    language: str | None = None  # for code blocks
    lines: list[str] = field(default_factory=list)  # Raw lines for tables/lists

    # for tables:
    table_header: list[str] | None = None  # column headers
    table_rows: list[list[str]] | None = None  # data rows


def parse_markdown_document(doc_path: Path) -> list[Block]:
    """
    Parse a markdown document into a list of blocks headers, paragraphs,
    code blocks, tables and lists.
    """
    content = doc_path.read_text(encoding="utf-8")
    lines = content.split("\n")

    blocks: list[Block] = []
    i = 0  # line index

    while i < len(lines):
        # blank?
        if not (stripped := lines[i].strip()):
            i += 1
            continue

        # code block?
        if stripped.startswith("```"):
            block, i = _parse_code_block(lines, i)
            blocks.append(block)
            continue

        # header?
        if stripped.startswith("#"):
            block = _parse_header(stripped)
            if block:
                blocks.append(block)
                i += 1
                continue

        # table?
        if _is_table_line(stripped):
            # the following line is header separator?
            if i + 1 < len(lines) and _is_table_separator(lines[i + 1]):
                block, i = _parse_table(lines, i)
                blocks.append(block)
                continue

        # list? (unordered oder ordered)
        if _is_list_item(lines[i]):
            block, i = _parse_list(lines, i)
            blocks.append(block)
            continue

        # if none of the above: paragraph
        block, i = _parse_paragraph(lines, i)
        blocks.append(block)

    return blocks


def _parse_header(line: str) -> Block | None:
    match = re.match(r"^(#{1,6})\s+(.+)$", line)  # levels 1 to 6
    if match:
        level = len(match.group(1))
        content = match.group(2).strip()
        return Block(type=BlockType.HEADER, content=content, level=level)
    return None


def _parse_code_block(lines: list[str], start: int) -> tuple[Block, int]:
    first_line = lines[start].strip()
    language = first_line[3:].strip() or None

    code_lines = []
    i = start + 1  # line index

    while i < len(lines):
        if lines[i].strip().startswith("```"):
            break
        code_lines.append(lines[i])
        i += 1

    content = "\n".join(code_lines)
    return Block(
        type=BlockType.CODE_BLOCK,
        content=content,
        language=language,
        lines=code_lines,
    ), i + 1

def _is_table_line(line: str) -> bool:
    return line.startswith("|") and line.endswith("|") and len(line) > 1


def _is_table_separator(line: str) -> bool:
    # check for |---|---| pattern
    return bool(re.match(r"^\|[\s\-:|]+\|$", line.strip()))


def _parse_table_row(line: str) -> list[str]:
    cells = line.strip().strip("|").split("|")
    return [cell.strip() for cell in cells]


def _parse_table(lines: list[str], start: int) -> tuple[Block, int]:
    """Parse a markdown table.

    Expected structure:
    - First line: header row
    - Second line: separator row (|---|---|)
    - Remaining lines: one or more data rows
    All rows must have the same number of columns

    Raises:
        ValueError: If table structure is invalid.
    """
    table_lines = []
    i = start

    while i < len(lines):
        line = lines[i]
        if _is_table_line(line):
            table_lines.append(line)
            i += 1
        elif not line.strip():
            # blank line ends the table
            break
        else:
            # non-blank line immediately following the table (ill-formatted)
            break

    # validate minimum structure:
    # header + separator + at least one data row
    if len(table_lines) < 3:
        raise ValueError(
            f"Table at line {start + 1} must have header, separator, and at least one data row"
        )

    # parse header row
    header_cells = _parse_table_row(table_lines[0])
    num_columns = len(header_cells)

    if num_columns == 0:
        raise ValueError(f"Table at line {start + 1} has empty header row")

    # check separator row
    if not _is_table_separator(table_lines[1]):
        raise ValueError(f"Table at line {start + 1} missing separator row")

    separator_cells = _parse_table_row(table_lines[1])
    if len(separator_cells) != num_columns:
        raise ValueError(
            f"Table at line {start + 1}: separator has {len(separator_cells)} columns, "
            f"expected {num_columns}"
        )

    # parse-validate data rows
    data_rows: list[list[str]] = []
    for row_idx, row_line in enumerate(table_lines[2:], start=3):
        row_cells = _parse_table_row(row_line)
        if len(row_cells) != num_columns:
            raise ValueError(
                f"Table at line {start + 1}, row {row_idx}: has {len(row_cells)} columns, "
                f"expected {num_columns}"
            )
        data_rows.append(row_cells)

    content = "\n".join(table_lines)
    return Block(
        type=BlockType.TABLE,
        content=content,
        lines=table_lines,
        table_header=header_cells,
        table_rows=data_rows,
    ), i


def _is_list_item(line: str) -> bool:
    """Check if a line is a list item."""
    stripped = line.lstrip()
    # Unordered: -, *, +
    if re.match(r"^[-*+]\s+", stripped):
        return True
    # Ordered: 1., 2., etc.
    if re.match(r"^\d+\.\s+", stripped):
        return True
    return False


def _get_list_indent(line: str) -> int:
    """Get the indentation level of a line."""
    return len(line) - len(line.lstrip())


def _parse_list(lines: list[str], start: int) -> tuple[Block, int]:
    """Parse a list (ordered or unordered)."""
    list_lines = []
    i = start  # line index
    base_indent = _get_list_indent(lines[start])

    while i < len(lines):
        line = lines[i]

        if not line.strip():
            # this line is blank; is the following line blank as well?
            if i + 1 < len(lines) and _is_list_item(lines[i + 1]):
                i += 1
                continue
            break

        current_indent = _get_list_indent(line)

        # Continue if it's a list item or indented continuation
        if _is_list_item(line) or current_indent > base_indent:
            list_lines.append(line)
            i += 1
        else:
            break

    content = "\n".join(list_lines)
    return Block(
        type=BlockType.LIST,
        content=content,
        level=base_indent,
        lines=list_lines,
    ), i


def _parse_paragraph(lines: list[str], start: int) -> tuple[Block, int]:
    # paragraph: consecutive non-empty, non-special lines

    paragraph_lines = []
    i = start  # line index

    while i < len(lines):
        line = lines[i]

        # blank line ends paragraph
        if not (stripped := line.strip()):
            break

        # special block starts end paragraph
        # fmt:off
        if ( line.startswith("#")
          or stripped.startswith("```")
          or _is_list_item(line)
          or _is_table_line(line) and i + 1 < len(lines) and _is_table_separator(lines[i + 1])
        ): break  # noqa: E701
        # fmt:on

        paragraph_lines.append(line)
        i += 1

    content = " ".join(paragraph_lines)
    return Block(type=BlockType.PARAGRAPH, content=content, lines=paragraph_lines), i
