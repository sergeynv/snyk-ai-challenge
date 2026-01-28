"""RAG orchestrator that combines all components.

Public API
----------
Agent
    Main orchestrator for the hybrid RAG system.

    Constructor:
        Agent(model, advisories_dir, csv_dir)

    Methods:
        process_user_query(query) -> str
            Process a user query through the RAG pipeline.
"""

from pathlib import Path

from snyk_ai.advisories import Advisories
from snyk_ai.advisories_rag import AdvisoriesRag
from snyk_ai.database import Database
from snyk_ai.models import Model
from snyk_ai.router import Router, RouteType


class Agent:
    """RAG orchestrator combining router, advisories, and database."""

    def __init__(
        self,
        advisories_dir: Path | str,
        csv_dir: Path | str,
        router_model: Model,
        advisories_rag_model: Model,
        code_summarizing_model: Model,
        db_query_model: Model,
    ):
        """Initialize the agent with all components.

        Args:
            model: LLM model for all components.
            advisories_dir: Path to directory containing advisory markdown files.
            csv_dir: Path to directory containing CSV files for the database.
        """
        self._advisories = Advisories(advisories_dir)
        self._advisories.init_vectordb(code_summarizing_model)
        self._advisories_rag = AdvisoriesRag(advisories_rag_model, self._advisories)

        self._database = Database(csv_dir)

        self._router = Router(router_model, self._advisories)

    def process_user_query(self, query: str) -> str:
        """Process a user query through the RAG pipeline.

        Args:
            query: User's natural language query.

        Returns:
            Response string with answer and sources (if applicable).
        """
        # 1. Route the query
        route_result = self._router.route(query)

        # 2. Handle based on route type
        if route_result.route_type is RouteType.NONE:
            return self._handle_none(route_result.reasoning)

        if route_result.route_type is RouteType.UNSTRUCTURED:
            result = self._advisories_rag.query(route_result.unstructured_query)
            return result.answer

        # STRUCTURED or HYBRID - not yet implemented
        return f"I cannot handle {route_result.route_type.value.upper()} queries yet."

    def _handle_none(self, reasoning: str) -> str:
        """Format response for off-topic queries."""
        return (
            f"I'm a security vulnerability assistant.\n"
            f"Your question appears to be off-topic: {reasoning}\n"
            f"\n"
            f"I can help with:\n"
            f"- Security advisories and vulnerability explanations\n"
            f"- CVE lookups and vulnerability statistics\n"
            f"- Remediation guidance"
        )
