"""Query router for hybrid RAG system.

Public API
----------
Router
    Routes user queries to appropriate data sources.

    Constructor:
        Router(model, advisories)

    Methods:
        route(query) -> RouteResult
            Analyze query and determine routing + transform query.
            Raises RouteValidationError if LLM response is invalid.

RouteResult
    Result of routing decision.
    - route_type: RouteType (UNSTRUCTURED, STRUCTURED, HYBRID, NONE)
    - unstructured_query: str | None - natural language query for advisory search
    - structured_query: str | None - natural language query for database lookup
    - reasoning: str - explanation of routing decision

RouteType
    Enum: UNSTRUCTURED, STRUCTURED, HYBRID, NONE

RouteValidationError
    Raised when LLM response doesn't match expected format.
"""

import json
import re
from dataclasses import dataclass
from enum import Enum

from snyk_ai.advisories import Advisories
from snyk_ai.database import SCHEMAS, TABLES
from snyk_ai.models import Model

_DATABASE_OPERATIONS = """
Available operations:
- Look up specific CVE details
- Search/filter vulnerabilities by ecosystem, severity, type, CVSS range
- List packages by ecosystem
- Get statistics grouped by ecosystem, severity, or type
""".strip()


def _build_database_schema() -> str:
    """Build database schema description from TABLES and SCHEMAS."""
    lines = ["Schema:"]
    for table, columns in zip(TABLES, SCHEMAS):
        cols = ", ".join(columns)
        lines.append(f"- **{table}**: {cols}")
    lines.append("")
    lines.append(_DATABASE_OPERATIONS)
    return "\n".join(lines)


_ROUTER_PROMPT = f"""
You route user questions to the appropriate data source. Respond with a single JSON object.

DATA SOURCES:
1. Advisories (unstructured): vulnerability explanations, attack patterns, remediation

{{advisory_summaries}}

2. Database (structured): CVE records, packages, statistics

{_build_database_schema()}

FIELD REQUIREMENTS BY ROUTE TYPE:
| route_type   | unstructured_query | structured_query |
|--------------|--------------------| -----------------|
| unstructured | required string    | must be null     |
| structured   | must be null       | required string  |
| hybrid       | required string    | required string  |
| none         | must be null       | must be null     |

WARNING: Your response will be validated. If validation fails, the request fails.

OUTPUT: a single JSON object with these fields:
- route_type: one of "unstructured", "structured", "hybrid", "none"
- unstructured_query: plain English question for advisories, or null
- structured_query: plain English description of data needed, or null
- reasoning: brief explanation (REQUIRED, never empty)

RULES:
- Query fields must be PLAIN ENGLISH sentences (never SQL, never JSON, never code)
- When in doubt, prefer "hybrid" - combining data with context gives more complete answers
- Only use "structured" or "unstructured" alone when clearly one-dimensional

EXAMPLES:

For "unstructured" (how attacks work, remediation, best practices):
{{"route_type": "unstructured", "unstructured_query": "How does SQL injection work?", "structured_query": null, "reasoning": "Asking about attack concepts"}}

For "structured" (data lookups, counts, filtering, specific CVEs):
{{"route_type": "structured", "unstructured_query": null, "structured_query": "List all critical severity vulnerabilities in npm packages", "reasoning": "Needs database filtering"}}

For "hybrid" - BOTH query fields REQUIRED (check yourself before responding):
- unstructured_query: non-empty string? YES
- structured_query: non-empty string? YES
{{"route_type": "hybrid", "unstructured_query": "How to remediate XSS vulnerabilities?", "structured_query": "Get details for CVE-2024-1234", "reasoning": "Needs both CVE data and remediation advice"}}

For "none" (off-topic, not about security):
{{"route_type": "none", "unstructured_query": null, "structured_query": null, "reasoning": "Not about security"}}

USER QUESTION: {{query}}

BEFORE RESPONDING: If route_type="hybrid", verify BOTH query fields are non-empty strings.

JSON:
""".strip()


class RouteType(Enum):
    """Query routing destination."""

    UNSTRUCTURED = "unstructured"  # advisories
    STRUCTURED = "structured"  # csv-s
    HYBRID = "hybrid"
    NONE = "none"  # irrelevant query


@dataclass
class RouteResult:
    """Result of routing a query."""

    route_type: RouteType
    unstructured_query: str | None  # transformed query for advisory semantic search
    structured_query: str | None  # transformed query describing what to look up
    reasoning: str  # Explanation of why this routing was chosen


def _format_advisory_summaries(advisories: Advisories) -> str:
    lines = []
    for advisory in advisories:
        lines.append(f"- **{advisory.title}**")
        lines.append(f"  {advisory.executive_summary}")
    return "\n".join(lines)


class Router:
    """Routes user queries to appropriate data sources using LLM classification."""

    def __init__(self, model: Model, advisories: Advisories):
        """Initialize router with model and data sources.

        Args:
            model: LLM model for query classification.
            advisories: Loaded security advisories (used to build prompt, not stored).
        """
        self._model = model
        # pre-build prompt with the advisory summaries, leaving {query} placeholder
        self._prompt_template = _ROUTER_PROMPT.replace(
            "{advisory_summaries}", _format_advisory_summaries(advisories)
        )

    def route(self, query: str, model: Model | None = None) -> RouteResult:
        """Route a user query to appropriate data source(s).

        Uses the LLM to classify the query and transform it for downstream
        processing.

        Args:
            query: User's natural language query.
            model: Optional model override. If None, uses the default model
                from constructor. Useful for testing with different models.

        Returns:
            RouteResult with routing decision and transformed queries.

        Raises:
            RouteValidationError: If LLM response doesn't match expected format.
            ValueError: If no model is available (none provided and no default).
        """
        if model is None:
            model = self._model
        if model is None:
            raise ValueError("No model available: none provided and no default set")

        prompt = self._prompt_template.replace("{query}", query)
        response = model.generate(prompt)
        result = self._parse_response(response)
        self._validate_result(result)
        return result

    def _parse_response(self, response: str) -> RouteResult:
        """Parse LLM response into RouteResult.

        Raises:
            RouteValidationError: If response cannot be parsed or is malformed.
        """
        # Extract JSON from response (handle markdown code blocks)
        json_match = re.search(r"\{[\s\S]*\}", response)
        if not json_match:
            raise RouteValidationError(f"No JSON object found in response: {response[:200]}")

        try:
            data = json.loads(json_match.group())
        except json.JSONDecodeError as e:
            raise RouteValidationError(f"Invalid JSON: {e}")

        # Require route_type field
        if "route_type" not in data:
            raise RouteValidationError("Missing required field: route_type")

        route_type_str = data["route_type"]
        if not isinstance(route_type_str, str):
            raise RouteValidationError(f"route_type must be a string, got {type(route_type_str).__name__}")

        route_type_map = {
            "unstructured": RouteType.UNSTRUCTURED,
            "structured": RouteType.STRUCTURED,
            "hybrid": RouteType.HYBRID,
            "none": RouteType.NONE,
        }
        route_type = route_type_map.get(route_type_str.lower())
        if route_type is None:
            valid = ", ".join(route_type_map.keys())
            raise RouteValidationError(f"Unknown route_type: '{route_type_str}'. Must be one of: {valid}")

        return RouteResult(
            route_type=route_type,
            unstructured_query=data.get("unstructured_query"),
            structured_query=data.get("structured_query"),
            reasoning=data.get("reasoning", ""),
        )

    def _validate_result(self, result: RouteResult) -> None:
        """Validate that RouteResult fields are consistent with route_type.

        Raises:
            RouteValidationError: If validation fails.
        """

        def report(message: str) -> None:
            raise RouteValidationError(message)

        # fmt: off
        if not result.reasoning:
            report("reasoning is required")

        if result.route_type is RouteType.NONE:
            if result.unstructured_query is not None:
                report("unstructured_query must be null when route_type is 'none'")
            if result.structured_query is not None:
                report("structured_query must be null when route_type is 'none'")

        elif result.route_type is RouteType.UNSTRUCTURED:
            if not result.unstructured_query:
                report("unstructured_query is required when route_type is 'unstructured'")
            if result.structured_query is not None:
                report("structured_query must be null when route_type is 'unstructured'")

        elif result.route_type is RouteType.STRUCTURED:
            if result.unstructured_query is not None:
                report("unstructured_query must be null when route_type is 'structured'")
            if not result.structured_query:
                report("structured_query is required when route_type is 'structured'")

        elif result.route_type is RouteType.HYBRID:
            if not result.unstructured_query:
                report("unstructured_query is required when route_type is 'hybrid'")
            if not result.structured_query:
                report("structured_query is required when route_type is 'hybrid'")
        # fmt: on


class RouteValidationError(Exception):
    """Raised when LLM response doesn't match expected format."""

    pass