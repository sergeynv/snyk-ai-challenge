"""Security advisory document parsing and management."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from snyk_ai.utils.markdown import (
    Block,
    BlockType,
    parse_markdown_document,
)

if TYPE_CHECKING:
    from snyk_ai.models import Model


# Sentence boundary: period/exclamation/question followed by space and capital
_SENTENCE_BOUNDARY = re.compile(r'(?<=[.!?])\s+(?=[A-Z])')


def _split_into_sentences(text: str) -> list[str]:
    """Split text into sentences."""
    if not text or not (text := text.strip()):
        return []
    sentences = _SENTENCE_BOUNDARY.split(text)
    return [s.strip() for s in sentences if s.strip()]


def _table_row_to_chunk_text(headers: list[str], values: list[str]) -> str:
    """Convert a table row to chunk text: key1: "val1", key2: "val2", ..."""
    parts = []
    for header, value in zip(headers, values):
        key = header.lower().replace(" ", "_")
        parts.append(f'{key}: "{value}"')
    return ", ".join(parts)


def _table_to_chunks(block: Block) -> list[str]:
    """Convert a table block into chunk texts, one per data row."""
    if block.header is None or block.rows is None:
        return []
    return [
        _table_row_to_chunk_text(block.header, row)
        for row in block.rows
    ]


@dataclass
class _Chunk:
    """A text chunk for embedding, pointing back to its source section."""

    text: str
    section: _Section
    source_type: BlockType

    def __repr__(self) -> str:
        preview = self.text[:50] + "..." if len(self.text) > 50 else self.text
        return f"_Chunk({self.source_type.value}: {preview!r})"


@dataclass
class _Section:
    """A section of an advisory: all blocks between two headers.

    Used for RAG to provide coherent chunks of context to the LLM.
    """

    header: Block
    """The header that starts this section."""

    blocks: list[Block] = field(default_factory=list)
    """All blocks in this section (until the next header)."""

    def to_text(self) -> str:
        """Render section as text for retrieval."""
        parts = [f"## {self.header.content}"]
        for block in self.blocks:
            if block.type is BlockType.PARAGRAPH:
                parts.append(block.content)
            elif block.type is BlockType.CODE_BLOCK:
                lang = block.language or ""
                parts.append(f"```{lang}\n{block.content}\n```")
            elif block.type is BlockType.LIST_ITEM:
                parts.append(block.content)
            elif block.type is BlockType.TABLE:
                parts.append(block.content)
        return "\n\n".join(parts)

    @property
    def has_code_blocks(self) -> bool:
        """Return True if this section contains code blocks."""
        return any(b.type is BlockType.CODE_BLOCK for b in self.blocks)

    def get_chunks(self, model: Model | None = None) -> list[_Chunk]:
        """Generate chunks from this section.

        - Paragraphs and list items: split into sentences
        - Tables: one chunk per row as key-value pairs
        - Code blocks: summarized using the provided model

        Args:
            model: Model for summarizing code blocks. Required if section
                contains code blocks.

        Returns:
            List of chunks extracted from this section.

        Raises:
            ValueError: If section contains code blocks but model is None.
        """
        # Fail fast if we have code blocks but no model
        if self.has_code_blocks and model is None:
            raise ValueError(
                f"Section '{self.header.content}' contains code blocks but no model "
                "was provided for summarization"
            )

        chunks: list[_Chunk] = []

        for block in self.blocks:
            if block.type is BlockType.PARAGRAPH:
                for sentence in _split_into_sentences(block.content):
                    chunks.append(_Chunk(sentence, self, BlockType.PARAGRAPH))

            elif block.type is BlockType.LIST_ITEM:
                for sentence in _split_into_sentences(block.content):
                    chunks.append(_Chunk(sentence, self, BlockType.LIST_ITEM))

            elif block.type is BlockType.TABLE:
                for row_text in _table_to_chunks(block):
                    chunks.append(_Chunk(row_text, self, BlockType.TABLE))

            elif block.type is BlockType.CODE_BLOCK:
                from snyk_ai.utils.summarize import summarize_code_snippet
                summary = summarize_code_snippet(block.content, model)
                chunks.append(_Chunk(summary, self, BlockType.CODE_BLOCK))

        return chunks


def _extract_sections(blocks: list[Block]) -> list[_Section]:
    """Extract sections: each section is all blocks between two headers.

    Skips the "References" section (header + list items) at the end.
    The "Credits" section is preserved.
    """
    # Handle end structure (validated by _validate_structure):
    # ... -> "References" header -> list items -> "Credits" header -> paragraph
    credits_section = _Section(header=blocks[-2], blocks=[blocks[-1]])

    # Find "References" header by iterating backwards, skipping list items
    references_idx = len(blocks) - 3
    while references_idx >= 0:
        block = blocks[references_idx]
        if block.type is BlockType.HEADER and block.content == "References":
            break
        references_idx -= 1

    # Process blocks up to (not including) "References" header
    sections: list[_Section] = []
    current_section: _Section | None = None
    header: Block | None = None

    for block in blocks[:references_idx]:
        if block.type is BlockType.HEADER:
            if current_section:
                sections.append(current_section)
                current_section = None
            header = block
        else:
            if current_section is None:
                current_section = _Section(header=header, blocks=[block])
            else:
                current_section.blocks.append(block)

    if current_section:
        sections.append(current_section)

    # Add Credits section at the end
    sections.append(credits_section)

    return sections


@dataclass
class Advisory:
    """A parsed security advisory document."""

    filename: str
    path: Path
    blocks: list[Block]
    title: str
    executive_summary: str
    _sections: list[_Section] = field(default_factory=list)

    @property
    def sections(self) -> list[_Section]:
        """Return all sections for RAG retrieval."""
        return self._sections

    @property
    def code_blocks(self) -> list[Block]:
        """Return all code blocks from the advisory."""
        return [b for b in self.blocks if b.type is BlockType.CODE_BLOCK]

    @property
    def headers(self) -> list[Block]:
        """Return all headers from the advisory."""
        return [b for b in self.blocks if b.type is BlockType.HEADER]

    def get_chunks(self, model: Model | None = None) -> list[_Chunk]:
        """Generate chunks from all sections in this advisory.

        Args:
            model: Model for summarizing code blocks. Required if any
                section contains code blocks.

        Returns:
            List of all chunks from all sections.

        Raises:
            ValueError: If any section contains code blocks but model is None.
        """
        chunks: list[_Chunk] = []
        for section in self._sections:
            chunks.extend(section.get_chunks(model))
        return chunks


def _validate_structure(filename: str, blocks: list[Block]) -> None:
    """Validate the structure of an advisory document.

    Expected markdown structure:
    - 1st block: Header starting with "Security Advisory: "
    - 2nd block: Header "Executive Summary"
    - 3rd block: Paragraph (executive summary content)
    - Ends with: References header, list items, Credits header, paragraph

    Args:
        filename: Name of the file (for error messages).
        blocks: Parsed markdown blocks.

    Raises:
        ValueError: If structure validation fails.
    """
    # Must have minimum blocks
    if len(blocks) < 4:
        raise ValueError(f"{filename}: Advisory too short")

    # First header: "Security Advisory: <title>"
    if blocks[0].type is not BlockType.HEADER:
        raise ValueError(f"{filename}: First block must be a header")
    if not blocks[0].content.startswith("Security Advisory: "):
        raise ValueError(
            f"{filename}: First header must start with 'Security Advisory: '"
        )

    # Executive summary section
    if (
        blocks[2].type is not BlockType.HEADER
        or blocks[2].content != "Executive Summary"
    ):
        raise ValueError(f"{filename}: blocks[2] must be 'Executive Summary' header")
    if blocks[3].type is not BlockType.PARAGRAPH:
        raise ValueError(f"{filename}: blocks[3] must be executive summary paragraph")

    # Ending: Credits header + paragraph
    if blocks[-1].type is not BlockType.PARAGRAPH:
        raise ValueError(
            f"{filename}: Last block must be a paragraph (Credits content)"
        )
    if blocks[-2].type is not BlockType.HEADER or blocks[-2].content != "Credits":
        raise ValueError(f"{filename}: Second-to-last block must be 'Credits' header")

    # References header with list items before Credits
    references_idx = None
    for i in range(len(blocks) - 3, -1, -1):
        if blocks[i].type is BlockType.HEADER and blocks[i].content == "References":
            references_idx = i
            break
    if references_idx is None:
        raise ValueError(f"{filename}: Missing 'References' header")

    has_list_items = any(
        blocks[i].type is BlockType.LIST_ITEM
        for i in range(references_idx + 1, len(blocks) - 2)
    )
    if not has_list_items:
        raise ValueError(f"{filename}: 'References' section must contain list items")


class Advisories:
    """Collection of parsed security advisory documents."""

    def __init__(
        self,
        directory: Path | str,
        model: Model | None = None,
    ):
        """Initialize advisories from a directory.

        Args:
            directory: Path to directory containing advisory markdown files.
            model: Model for summarizing code blocks when chunking. Required
                if calling get_all_chunks() on advisories that contain code blocks.
        """
        self.directory = Path(directory).resolve()
        self._model = model

        if not self.directory.is_dir():
            raise FileNotFoundError(f"Directory not found: {self.directory}")

        self._advisories: dict[str, Advisory] = {}
        self._load_advisories()

    def _load_advisories(self) -> None:
        """Load and parse all markdown files from the directory."""
        for path in sorted(self.directory.glob("*.md")):
            blocks = parse_markdown_document(path)
            advisory = self._parse_advisory(path, blocks)
            self._advisories[path.name] = advisory

    def _parse_advisory(self, path: Path, blocks: list[Block]) -> Advisory:
        """Parse blocks into an Advisory, validating structure."""
        filename = path.name

        _validate_structure(filename, blocks)

        title = blocks[0].content.removeprefix("Security Advisory: ")
        executive_summary = blocks[3].content
        sections = _extract_sections(blocks)

        return Advisory(
            filename=filename,
            path=path,
            blocks=blocks,
            title=title,
            executive_summary=executive_summary,
            _sections=sections,
        )

    def __getitem__(self, filename: str) -> Advisory:
        return self._advisories[filename]

    def __iter__(self):
        return iter(self._advisories.values())

    def __len__(self) -> int:
        return len(self._advisories)

    def __contains__(self, filename: str) -> bool:
        return filename in self._advisories

    @property
    def filenames(self) -> list[str]:
        return list(self._advisories.keys())

    def get_all_chunks(self, model: Model | None = None) -> list[_Chunk]:
        """Generate chunks from all advisories.

        Args:
            model: Model for summarizing code blocks. If None, uses the model
                passed to constructor. Required if any advisory contains code blocks.

        Returns:
            List of all chunks from all advisories.

        Raises:
            ValueError: If any section contains code blocks but no model is available.
        """
        effective_model = model if model is not None else self._model
        chunks: list[_Chunk] = []
        for advisory in self._advisories.values():
            chunks.extend(advisory.get_chunks(effective_model))
        return chunks
