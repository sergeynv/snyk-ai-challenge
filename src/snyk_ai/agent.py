from pathlib import Path

from snyk_ai.advisories import Advisories
from snyk_ai.advisories_rag import AdvisoriesRag
from snyk_ai.database import Database
from snyk_ai.models import Model
from snyk_ai.router import Router, RouteType
from snyk_ai.utils.log import log


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
        _log("Initializing components...")

        self._advisories = Advisories(advisories_dir)
        self._advisories.init_vectordb(code_summarizing_model)
        _log("Advisories (incl. vector DB) initialized ✅")

        self._advisories_rag = AdvisoriesRag(advisories_rag_model, self._advisories)
        self._database = Database(csv_dir)
        self._router = Router(router_model, self._advisories)
        _log("RAG, DB and Router initialized ✅")

    def process_user_query(self, query: str) -> str:
        _log("Routing query...")
        routing = self._router.route(query)
        _log(
            f'Routing completed: {routing.route_type.value.upper()} ("{routing.reasoning}")'
        )

        if routing.route_type is RouteType.NONE:
            return (
                f"Your question appears to be off-topic: {routing.reasoning}\n"
                f"\n"
                f"I can help with:\n"
                f"- Security advisories and vulnerability explanations\n"
                f"- CVE lookups and vulnerability statistics\n"
                f"- Remediation guidance\n"
            )

        if routing.route_type is RouteType.UNSTRUCTURED:
            result = self._advisories_rag.query(routing.unstructured_query)
            return result.answer

        # STRUCTURED or HYBRID - not yet implemented
        return f"I cannot handle {routing.route_type.value.upper()} queries yet."


def _log(message):
    log("agent", message)
