from snyk_ai.advisories import Advisories
from snyk_ai.models import Model


_ADVISORY_PROMPT = """
You are a security expert answering questions based on security advisory documents.

CONTEXT FROM SECURITY ADVISORIES:
================================================================================

{context}

================================================================================

USER QUESTION: {query}

INSTRUCTIONS:
1. Answer the question using ONLY the information provided in the context above
2. If the context doesn't contain enough information to fully answer, say so clearly
3. Be specific - mention CVE IDs, package names, version numbers when relevant
4. For remediation questions, include concrete steps (upgrade commands, code fixes)
5. Keep your answer focused and concise

ANSWER:
""".strip()

_NO_SOURCES_ANSWER = """
I couldn't find any relevant security advisory information for your question.
""".strip()


class AdvisoriesRag:
    """Handles unstructured queries using semantic search over advisories."""

    def __init__(self, model: Model, advisories: Advisories):
        """
        Args:
            model: LLM model for answer synthesis.
            advisories: Loaded advisories with initialized vector DB.
        """
        self._model = model
        self._advisories = advisories

    def query(
        self,
        unstructured_query: str,
        model: Model | None = None,
    ) -> str:
        """Search advisories and synthesize an answer.

        Args:
            unstructured_query: Natural language query about advisories.
            model: Optional model override (useful for testing)
        """
        if model is None:
            model = self._model

        # semantic search
        search_results = self._advisories.search(unstructured_query)
        if not search_results:
            return _NO_SOURCES_ANSWER
        context = "\n---\n\n".join(search_results)

        # build prompt and generate answer
        prompt = _ADVISORY_PROMPT.format(context=context, query=unstructured_query)
        answer = model.generate(prompt)

        return answer.strip()
