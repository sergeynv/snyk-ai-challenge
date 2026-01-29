from pathlib import Path

from snyk_ai.advisories import Advisories
from snyk_ai.advisories_rag import AdvisoriesRag
from snyk_ai.database import Database
from snyk_ai.database_rag import DatabaseRag
from snyk_ai.models import Model
from snyk_ai.router import Router, RouteType
from snyk_ai.synthesizer import Synthesizer
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
        synthesizer_model: Model,
    ):
        log("Initializing Advisories...")
        self._advisories = Advisories(advisories_dir)
        log("Initializing Advisories' Vector DB...")
        self._advisories.init_vectordb(code_summarizing_model)
        log("Advisories initialized")

        log("Initializing other components...")
        self._database = Database(csv_dir)
        self._advisories_rag = AdvisoriesRag(advisories_rag_model, self._advisories)
        self._database_rag = DatabaseRag(db_query_model, self._database)
        self._synthesizer = Synthesizer(synthesizer_model)
        self._router = Router(router_model, self._advisories)
        log("All components initialized")

    def process_user_query(self, query: str) -> str:
        log("Routing query...")
        routing = self._router.route(query)
        log(
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
            log("Querying advisories...")
            result = self._advisories_rag.query(routing.unstructured_query)
            return result.answer

        if routing.route_type is RouteType.STRUCTURED:
            log("Querying database...")
            return self._database_rag.query(routing.structured_query)

        if routing.route_type is RouteType.HYBRID:
            log("Querying both sources...")
            unstructured_answer = self._advisories_rag.query(routing.unstructured_query).answer
            structured_answer = self._database_rag.query(routing.structured_query)
            log("Synthesizing answers...")
            return self._synthesizer.synthesize(
                user_query=query,
                router_reasoning=routing.reasoning,
                unstructured_answer=unstructured_answer,
                structured_answer=structured_answer,
            )

        # Should never reach here
        return "Unable to process query."
