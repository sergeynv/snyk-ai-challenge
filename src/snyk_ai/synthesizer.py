from snyk_ai.models import Model
from snyk_ai.utils.log import log

_SYNTHESIS_PROMPT = """You are synthesizing information from two sources into a single coherent answer.

USER QUESTION: {query}

WHY BOTH SOURCES WERE NEEDED: {reasoning}

ANSWER FROM SECURITY ADVISORIES (explanations, attack patterns, remediation guidance):
{unstructured_answer}

ANSWER FROM VULNERABILITY DATABASE (CVE records, statistics, package data):
{structured_answer}

INSTRUCTIONS:
1. Combine both answers into a single, coherent response
2. Weave the information together naturally - don't just concatenate
3. Use database facts (CVE IDs, counts, versions) to ground the advisory context
4. Use advisory explanations to give meaning to the database facts
5. If information conflicts, prefer database for hard facts, advisories for context
6. Keep the response focused on what the user actually asked

COMBINED ANSWER:""".strip()


class Synthesizer:
    """Synthesizes outputs from both RAG systems into a unified answer."""

    def __init__(self, model: Model):
        """Initialize synthesizer with model.

        Args:
            model: LLM model for answer synthesis.
        """
        self._model = model

    def synthesize(
        self,
        user_query: str,
        router_reasoning: str,
        unstructured_answer: str,
        structured_answer: str,
    ) -> str:
        """Synthesize a unified answer from both RAG outputs.

        Args:
            user_query: The original user question.
            router_reasoning: Why the router classified this as HYBRID.
            unstructured_answer: Answer from AdvisoriesRag.
            structured_answer: Answer from DatabaseRag.

        Returns:
            Combined answer string.
        """
        log("Synthesizing answers from both sources...")

        prompt = _SYNTHESIS_PROMPT.format(
            query=user_query,
            reasoning=router_reasoning,
            unstructured_answer=unstructured_answer,
            structured_answer=structured_answer,
        )

        answer = self._model.generate(prompt)
        log("Synthesis complete")

        return answer.strip()
