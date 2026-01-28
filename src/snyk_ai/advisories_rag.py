"""Advisory query handler for unstructured RAG queries.

Public API
----------
AdvisoryHandler
    Handles unstructured queries using semantic search over advisories.

    Constructor:
        AdvisoryHandler(model, advisories)

    Methods:
        query(unstructured_query) -> AdvisoryResult
            Search advisories and synthesize an answer.

AdvisoryResult
    Result of an advisory query.
    - answer: str - The synthesized answer
    - sources: list[SourceReference] - Advisory sections used
    - query: str - The original query

SourceReference
    Reference to a source advisory section.
    - advisory_title: str
    - section_header: str
    - advisory_filename: str
"""

from dataclasses import dataclass

from snyk_ai.advisories import Advisories, Advisory
from snyk_ai.models import Model


@dataclass
class SourceReference:
    """Reference to a source advisory section."""

    advisory_title: str
    section_header: str
    advisory_filename: str


@dataclass
class AdvisoryResult:
    """Result of querying advisories."""

    answer: str
    sources: list[SourceReference]
    query: str


_ADVISORY_PROMPT = """You are a security expert answering questions based on security advisory documents.

CONTEXT FROM SECURITY ADVISORIES:
{context}

USER QUESTION: {query}

INSTRUCTIONS:
1. Answer the question using ONLY the information provided in the context above
2. If the context doesn't contain enough information to fully answer, say so clearly
3. Be specific - mention CVE IDs, package names, version numbers when relevant
4. For remediation questions, include concrete steps (upgrade commands, code fixes)
5. Keep your answer focused and concise

ANSWER:""".strip()


class AdvisoriesRag:
    """Handles unstructured queries using semantic search over advisories."""

    def __init__(self, model: Model, advisories: Advisories):
        """Initialize handler with model and advisories.

        Args:
            model: LLM model for answer synthesis.
            advisories: Loaded advisories with initialized vector DB.
        """
        self._model = model
        self._advisories = advisories

    def query(
        self,
        unstructured_query: str,
        top_k: int = 3,
        model: Model | None = None,
    ) -> AdvisoryResult:
        """Search advisories and synthesize an answer.

        Args:
            unstructured_query: Natural language query about advisories.
            top_k: Maximum number of advisories to retrieve (default: 3).
            model: Optional model override for synthesis.

        Returns:
            AdvisoryResult with answer and source references.
        """
        if model is None:
            model = self._model

        # 1. Semantic search
        search_results = self._advisories.search(unstructured_query, top_k=top_k)

        # 2. Handle no results
        if not search_results:
            return AdvisoryResult(
                answer="I couldn't find any relevant security advisory information "
                "for your question. Try rephrasing or asking about specific "
                "vulnerability types (XSS, SQL injection, RCE) or CVE IDs.",
                sources=[],
                query=unstructured_query,
            )

        # 3. Build context and collect sources
        context, sources = self._format_context(search_results)

        # 4. Build prompt and generate answer
        prompt = _ADVISORY_PROMPT.format(context=context, query=unstructured_query)
        answer = model.generate(prompt)

        return AdvisoryResult(
            answer=answer.strip(),
            sources=sources,
            query=unstructured_query,
        )

    def _format_context(
        self, search_results: list[tuple[Advisory, list[int]]]
    ) -> tuple[str, list[SourceReference]]:
        """Format search results into context string and collect sources.

        Args:
            search_results: List of (Advisory, section_indices) tuples.

        Returns:
            Tuple of (context_string, source_references).
        """
        context_parts: list[str] = []
        sources: list[SourceReference] = []

        for advisory, section_indices in search_results:
            # Add advisory header
            context_parts.append(f"=== ADVISORY: {advisory.title} ===\n")

            # Add relevant sections
            for idx in section_indices:
                section = advisory.sections[idx]
                section_text = section.to_text()
                if section_text.strip():
                    context_parts.append(section_text)
                    context_parts.append("")  # blank line between sections

                    # Track source reference
                    sources.append(
                        SourceReference(
                            advisory_title=advisory.title,
                            section_header=section.header.content,
                            advisory_filename=advisory.filename,
                        )
                    )

            context_parts.append("---\n")

        return "\n".join(context_parts).strip(), sources
