from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import chromadb
from chromadb.utils import embedding_functions

from snyk_ai.models import Model
from snyk_ai.utils.log import log
from snyk_ai.utils.markdown import (
    Block,
    BlockType,
    parse_markdown_document,
)
from snyk_ai.utils.text import (
    format_table_block,
    split_into_sentences,
)


class Advisories:
    """Collection of parsed security advisory documents prepared for semantic search."""

    def __init__(self, directory: Path | str):
        """Load advisories from a directory."""
        self.directory = Path(directory).resolve()

        if not self.directory.is_dir():
            raise FileNotFoundError(f"Directory not found: {self.directory}")

        self._advisories: dict[str, _Advisory] = {}
        self._load_advisories()

        # vector DB (initialized lazily via init_vectordb)
        self._chroma_client: chromadb.Client | None = None
        self._collection: chromadb.Collection | None = None

    def _load_advisories(self) -> None:
        log("Loading advisory markdown documents...")
        for path in sorted(self.directory.glob("*.md")):
            blocks = parse_markdown_document(path)
            advisory = self._parse_advisory(path, blocks)
            self._advisories[path.name] = advisory
        log(f"Loaded {len(self._advisories)} documents")

    def _parse_advisory(self, path: Path, blocks: list[Block]) -> _Advisory:
        filename = path.name

        _validate_structure(filename, blocks)

        title = blocks[0].content.removeprefix("Security Advisory: ")
        executive_summary = blocks[3].content
        sections = _extract_sections(blocks)

        log(f"Parsed {filename} advisory: {len(sections)} sections")

        return _Advisory(
            filename=filename,
            path=path,
            blocks=blocks,
            title=title,
            executive_summary=executive_summary,
            _sections=sections,
        )

    @property
    def filenames(self) -> list[str]:
        return list(self._advisories.keys())

    def get_summaries(self) -> list[tuple[str, str]]:
        """Return (title, executive_summary) for each advisory."""
        return [
            (adv.title, adv.executive_summary)
            for adv in self._advisories.values()
        ]

    def init_vectordb(self, model: Model) -> None:
        """Initialize the vector database with all advisory chunks.

        Uses a persistent ChromaDB instance stored in .chroma directory.
        If the database already exists and has data, it is loaded instead
        of being rebuilt.

        This must be called before search().

        Args:
            model: LLM model for summarizing code blocks during chunking.

        Raises:
            ValueError: If any advisory contains code blocks but no model
                is available for summarization.
        """
        # 1. Use PersistentClient with dot-directory
        chroma_path = self.directory / ".chroma"
        self._chroma_client = chromadb.PersistentClient(path=str(chroma_path))

        # 2. Set up sentence-transformer embedding function
        embedding_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name="all-MiniLM-L6-v2"
        )

        # 3. Get or create collection
        self._collection = self._chroma_client.get_or_create_collection(
            name="advisories",
            embedding_function=embedding_fn,
        )

        # 4. Skip if already populated
        if self._collection.count() > 0:
            log(f"Loaded persisted vector DB ({self._collection.count()} chunks)")
            return

        log("Building vector DB (this may take a while)...")

        # 5. Prepare data for batch insert
        ids: list[str] = []
        documents: list[str] = []
        metadatas: list[dict] = []

        for advisory in self._advisories.values():
            for section_idx, section in enumerate(advisory.sections):
                section_chunks = section.get_chunks(model)
                for chunk_idx, chunk in enumerate(section_chunks):
                    # Unique ID: filename_sectionIdx_chunkIdx
                    chunk_id = f"{advisory.filename}_{section_idx}_{chunk_idx}"

                    ids.append(chunk_id)
                    documents.append(chunk.text)
                    metadatas.append(
                        {
                            "advisory_filename": advisory.filename,
                            "section_index": section_idx,
                        }
                    )

        # 6. Add all chunks to collection in one batch
        if ids:
            self._collection.add(
                ids=ids,
                documents=documents,
                metadatas=metadatas,
            )
            log(f"Vector DB built ({len(ids)} chunks)")

    def search(self, query: str) -> list[str]:
        """Search for relevant sections matching the query.

        Queries the vector database for chunks semantically similar to the
        query, then returns formatted context strings for each matching advisory.

        Args:
            query: The search query text.

        Returns:
            List of formatted context strings, one per matching advisory,
            sorted by relevance (best match first). Each string contains
            the advisory title header and relevant sections.

        Raises:
            RuntimeError: If init_vectordb() has not been called.
        """
        if self._collection is None:
            raise RuntimeError(
                "Vector database not initialized. Call init_vectordb() first."
            )

        TOP_K = 3  # maximum number of advisories to return

        # query for more chunks than needed to ensure enough unique advisories
        results = self._collection.query(
            query_texts=[query],
            n_results=min(TOP_K * 10, self._collection.count()),
            include=["metadatas", "distances"],
        )

        # group by advisory, collecting section indices and tracking best distance
        #   advisory_filename -> (best_distance, set of section_indices)
        advisory_matches: dict[str, tuple[float, set[int]]] = {}

        for metadata, distance in zip(results["metadatas"][0], results["distances"][0]):
            filename = metadata["advisory_filename"]
            section_index = metadata["section_index"]

            if filename not in advisory_matches:
                advisory_matches[filename] = (distance, {section_index})
            else:
                best_dist, indices = advisory_matches[filename]
                indices.add(section_index)
                # keep the best (lowest) distance
                if distance < best_dist:
                    advisory_matches[filename] = (distance, indices)

        # sort by best distance and take TOP_K advisories
        sorted_matches = sorted(advisory_matches.items(), key=lambda x: x[1][0])[:TOP_K]

        # build formatted context strings
        search_results: list[str] = []

        for filename, (_, section_indices) in sorted_matches:
            if 1 not in section_indices:
                # the second section (at index 1) is the "Executive Summary" - we always want to render it.
                section_indices.add(1)
            sorted_indices = sorted(section_indices)

            sections = self._advisories[filename].sections
            parts: list[str] = []

            if sorted_indices[0] != 0:
                # the header of the first section (index 0) is the title of the document:
                # if we are not including the whole section, we should still render the title
                parts.append(sections[0].to_text(skip_content=True))
                parts.append("")

            for idx in sorted_indices:
                section_text = sections[idx].to_text()
                if section_text.strip():
                    parts.append(section_text)
                    parts.append("")

            search_results.append("\n".join(parts))

        return search_results


@dataclass
class Section:
    """A section of an advisory: all blocks between two headers.

    Used for RAG to provide coherent context to the LLM.
    """

    header: Block
    """The header that starts this section."""

    blocks: list[Block] = field(default_factory=list)
    """All content blocks in this section (until the next header)."""

    def to_text(self, skip_header: bool = False, skip_content: bool = False) -> str:
        """Render section as markdown text for retrieval."""
        parts = []
        if not skip_header:
            h = self.header
            parts.append(f"{'#' * h.level} {h.content}")

        if not skip_content:
            for block in self.blocks:
                if block.type is BlockType.PARAGRAPH:
                    parts.append(block.content)
                elif block.type is BlockType.CODE_BLOCK:
                    lang = block.language or ""
                    parts.append(f"```{lang}\n{block.content}\n```")
                elif block.type is BlockType.LIST_ITEM:
                    parts.extend(block.lines)
                elif block.type is BlockType.TABLE:
                    parts.extend(block.lines)

        return "\n\n".join(parts)

    @property
    def has_code_blocks(self) -> bool:
        """Return True if this section contains code blocks."""
        return any(b.type is BlockType.CODE_BLOCK for b in self.blocks)

    def get_chunks(self, model: Model) -> list[_Chunk]:
        """Generate chunks from this section.

        - Paragraphs and list items: split into sentences
        - Tables: one chunk per row as key-value pairs
        - Code blocks: summarized using the provided model

        Args:
            model: Model for summarizing code blocks.

        Returns:
            List of chunks extracted from this section.
        """
        chunks: list[_Chunk] = []

        for block in self.blocks:
            if block.type is BlockType.PARAGRAPH:
                for sentence in split_into_sentences(block.content):
                    chunks.append(_Chunk(sentence, self, BlockType.PARAGRAPH, block))

            elif block.type is BlockType.LIST_ITEM:
                for sentence in split_into_sentences(block.content):
                    chunks.append(_Chunk(sentence, self, BlockType.LIST_ITEM, block))

            elif block.type is BlockType.TABLE:
                for row_text in format_table_block(block):
                    chunks.append(_Chunk(row_text, self, BlockType.TABLE, block))

            elif block.type is BlockType.CODE_BLOCK:
                from snyk_ai.utils.summarize import summarize_code_snippet

                summary = summarize_code_snippet(block.content, model)
                chunks.append(_Chunk(summary, self, BlockType.CODE_BLOCK, block))

        return chunks


@dataclass
class _Chunk:
    """A text chunk for embedding, pointing back to its source."""

    text: str
    section: Section
    source_type: BlockType
    block: Block
    """The specific block this chunk was extracted from."""

    def __repr__(self) -> str:
        preview = self.text[:50] + "..." if len(self.text) > 50 else self.text
        return f"_Chunk({self.source_type.value}: {preview!r})"


def _extract_sections(blocks: list[Block]) -> list[Section]:
    """Extract sections: each section is all blocks between two headers.

    Skips the "References" section (header + list items) at the end.
    The "Credits" section is preserved.
    """

    # handle "footer" of the document (validated by _validate_structure):
    # -  [everything above the footer]
    # - "References" header
    # -  list items
    # - "Credits" header
    # -  paragraph
    credits_section = Section(header=blocks[-2], blocks=[blocks[-1]])

    # find "References" header by iterating backwards, skipping list items
    references_idx = len(blocks) - 3
    while references_idx >= 0:
        block = blocks[references_idx]
        if block.type is BlockType.HEADER and block.content == "References":
            break
        references_idx -= 1

    # process blocks up to (but excluding) the "References" header
    sections: list[Section] = []
    current_section: Section | None = None
    header: Block | None = None

    for block in blocks[:references_idx]:
        if block.type is BlockType.HEADER:
            if current_section:
                sections.append(current_section)
                current_section = None
            header = block
        else:
            if current_section is None:
                current_section = Section(header=header, blocks=[block])
            else:
                current_section.blocks.append(block)

    if current_section:
        sections.append(current_section)

    # add the "Credits" section at the end
    sections.append(credits_section)

    return sections


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


@dataclass
class _Advisory:
    """A parsed security advisory document."""

    filename: str
    path: Path
    blocks: list[Block]
    title: str
    executive_summary: str
    _sections: list[Section] = field(default_factory=list)

    @property
    def sections(self) -> list[Section]:
        return self._sections

    @property
    def code_blocks(self) -> list[Block]:
        return [b for b in self.blocks if b.type is BlockType.CODE_BLOCK]

    @property
    def headers(self) -> list[Block]:
        return [b for b in self.blocks if b.type is BlockType.HEADER]

    def get_chunks(self, model: Model) -> list[_Chunk]:
        """Generate chunks from all sections in this advisory.

        Args:
            model: Model for summarizing code blocks.

        Returns:
            List of all chunks from all sections.

        Raises:
            ValueError: If any section contains code blocks but model is None.
        """
        chunks: list[_Chunk] = []
        for section in self._sections:
            chunks.extend(section.get_chunks(model))
        return chunks
