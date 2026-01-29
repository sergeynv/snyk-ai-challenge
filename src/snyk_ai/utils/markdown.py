"""Utility for parsing markdown documents into structured blocks."""

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from snyk_ai.utils.log import log

class BlockType(Enum):
    HEADER = "header"
    PARAGRAPH = "paragraph"
    CODE_BLOCK = "code_block"
    TABLE = "table"
    LIST_ITEM = "list_item"


@dataclass
class Block:
    """A parsed markdown block."""

    type: BlockType
    content: str
    level: int | None = None  # for headers (1-6) and lists (indentation)
    language: str | None = None  # for code blocks
    lines: list[str] = field(default_factory=list)  # Raw lines for tables/lists

    # for tables:
    header: list[str] | None = None  # column headers
    rows: list[list[str]] | None = None  # data rows


def parse_markdown_document(doc_path: Path) -> list[Block]:
    """
    Parse a markdown document into a list of blocks headers, paragraphs,
    code blocks, tables and lists.
    """
    log(f"Parsing {doc_path}...")

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
            # the parsed out blocks can be either LIST_ITEM-s (most of the actually are)
            # or CODE_BLOCK-s (embedded into the list items)
            list_blocks, i = _parse_list(lines, i)
            blocks.extend(list_blocks)
            continue

        # if none of the above: paragraph
        block, i = _parse_paragraph(lines, i)
        blocks.append(block)

    __validate_block_counts(lines, blocks)

    log(f"Parsed {doc_path.name}: {len(blocks)} Markdown blocks")

    return blocks


def __validate_block_counts(lines: list[str], blocks: list[Block]):
    """Quick and easy sanity check to make sure we don't skip over any code blocks again."""
    in_code_block = False
    num_headers = 0
    num_code_fences = 0

    for line in lines:
        if line.strip().startswith("```"):
            num_code_fences += 1
            in_code_block = not in_code_block
        elif not in_code_block and line.startswith("#"):
            num_headers += 1

    assert not in_code_block

    assert sum(1 for b in blocks if b.type is BlockType.HEADER) == num_headers
    assert sum(1 for b in blocks if b.type is BlockType.CODE_BLOCK) == num_code_fences // 2  # fmt: skip


def _parse_header(line: str) -> Block | None:
    match = re.match(r"^(#{1,6})\s+(.+)$", line)  # levels 1 to 6
    if match:
        level = len(match.group(1))
        content = match.group(2).strip()
        return Block(type=BlockType.HEADER, content=content, level=level)
    return None


def _parse_code_block(lines: list[str], start: int) -> tuple[Block, int]:
    first_line = lines[start]
    fence_indent = _get_indent(first_line)
    first_line = first_line.strip()
    language = first_line[3:].strip() or None

    code_lines = []
    i = start + 1  # line index

    while i < len(lines):
        if lines[i].strip().startswith("```"):
            break
        code_lines.append(_strip_indent(lines[i], fence_indent))
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
        header=header_cells,
        rows=data_rows,
    ), i

def _is_list_item(line: str) -> bool:
    return _check_if_list_item_line(line)[0]

def _check_if_list_item_line(line: str) -> tuple[bool, str]:
    """Check if a line is a list item, and strip the marker if so.

    Returns:
        Tuple of (is_list_item, content) where:
        - If list item: (True, content with marker stripped)
        - If not: (False, original line unchanged)
    """
    stripped = line.lstrip()
    # unordered (-, *, +)?
    match = re.match(r"^[-*+]\s+(.*)$", stripped)
    if match:
        return True, match.group(1)
    # ordered (1., 2., etc.)?
    match = re.match(r"^\d+\.\s+(.*)$", stripped)
    if match:
        return True, match.group(1)
    # continuation line
    return False, line


def _get_indent(line: str) -> int:
    """Get the indentation level (leading whitespace count) of a line."""
    return len(line) - len(line.lstrip())


def _strip_indent(line: str, indent: int) -> str:
    """Strip up to `indent` leading whitespace characters from line."""
    if indent <= 0:
        return line
    leading = len(line) - len(line.lstrip())
    strip_count = min(leading, indent)
    return line[strip_count:]


def _parse_list(lines: list[str], start: int) -> tuple[list[Block], int]:
    """Parse a list (ordered or unordered), returning LIST_ITEM and CODE_BLOCK blocks."""
    blocks: list[Block] = []
    i = start  # line index
    base_indent = _get_indent(lines[start])

    current_item_lines: list[str] = []

    def flush_current_item():
        if current_item_lines:
            content = " ".join(current_item_lines)
            blocks.append(
                Block(
                    type=BlockType.LIST_ITEM,
                    content=content,
                    level=base_indent,
                    lines=list(current_item_lines),
                )
            )
            current_item_lines.clear()

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        if not stripped:
            # blank line - check if next line continues the list
            if i + 1 < len(lines) and _is_list_item(lines[i + 1]):
                i += 1
                continue
            break

        # code block within the list?
        if stripped.startswith("```"):
            flush_current_item()
            code_block, i = _parse_code_block(lines, i)
            blocks.append(code_block)
            continue

        current_indent = _get_indent(line)

        # if a list item, will also strip indent and/or list marker
        is_list_item, line = _check_if_list_item_line(line)

        if is_list_item or current_indent > base_indent:
            if is_list_item and current_item_lines:
                flush_current_item()
            current_item_lines.append(line)
            i += 1
        else:
            break

    flush_current_item()
    return blocks, i


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
