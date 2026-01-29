"""Database query handler for structured RAG queries.

Public API
----------
DatabaseRag
    Handles structured queries using tool-based access to the vulnerability database.

    Constructor:
        DatabaseRag(model, database)

    Methods:
        query(structured_query) -> str
            Query the database and synthesize an answer.
"""

import json
import re

from snyk_ai.database import Database
from snyk_ai.models import Model
from snyk_ai.utils.log import log

_TOOLS_DESCRIPTION = """
1. get_vulnerability(cve_id: string)
   Get detailed information about a specific CVE vulnerability.
   Example: {"tool": "get_vulnerability", "arguments": {"cve_id": "CVE-2024-1234"}}

2. search_vulnerabilities(ecosystem?: string, severity?: string, type?: string, min_cvss?: number, max_cvss?: number)
   Search and filter vulnerabilities. All parameters are optional.
   - ecosystem: "npm", "pip", "maven", etc.
   - severity: "Critical", "High", "Medium", "Low"
   - type: "SQL Injection", "XSS", "RCE", etc.
   Example: {"tool": "search_vulnerabilities", "arguments": {"severity": "Critical", "ecosystem": "npm"}}

3. list_packages(ecosystem?: string)
   List all packages, optionally filtered by ecosystem.
   Example: {"tool": "list_packages", "arguments": {"ecosystem": "pip"}}

4. get_statistics(group_by?: "ecosystem" | "severity" | "type")
   Get aggregate statistics about vulnerabilities.
   Example: {"tool": "get_statistics", "arguments": {"group_by": "severity"}}
""".strip()

_SYSTEM_PROMPT = """You are a data analyst with access to a vulnerability database.

AVAILABLE TOOLS:
{tools}

RESPONSE FORMAT:
- To call a tool, respond with ONLY a JSON object: {{"tool": "name", "arguments": {{...}}}}
- To give your final answer, respond with ONLY a JSON object: {{"answer": "your answer here"}}

RULES:
- Call ONE tool at a time
- After receiving tool results, either call another tool or provide your final answer
- Base your answer strictly on the data returned by tools
- If no data is found, say so clearly
""".strip()

_QUERY_PROMPT = """
{system}

{history}

USER QUESTION: {query}

Respond with a single JSON object (tool call or answer):
""".strip()


def _log(message: str) -> None:
    log(message, "db_rag")


class DatabaseRag:
    """Handles structured queries using tool-based access to the database."""

    def __init__(self, model: Model, database: Database):
        """Initialize handler with model and database.

        Args:
            model: LLM model for query planning and answer synthesis.
            database: Loaded vulnerability database.
        """
        self._model = model
        self._database = database

    def query(self, structured_query: str, max_iterations: int = 5) -> str:
        """Query the database and synthesize an answer.

        Uses an agentic loop where the LLM can call database tools
        until it has enough information to answer.

        Args:
            structured_query: Natural language query about vulnerability data.
            max_iterations: Maximum tool calls before forcing an answer.

        Returns:
            Synthesized answer string.
        """
        system = _SYSTEM_PROMPT.format(tools=_TOOLS_DESCRIPTION)
        history: list[str] = []

        for i in range(max_iterations):
            history_text = "\n".join(history) if history else ""
            prompt = _QUERY_PROMPT.format(
                system=system,
                history=history_text,
                query=structured_query,
            )

            response = self._model.generate(prompt)
            parsed = self._parse_response(response)

            if parsed is None:
                _log(f"Failed to parse response, treating as answer")
                return response.strip()

            if "answer" in parsed:
                _log(f"Got final answer")
                return parsed["answer"]

            if "tool" in parsed:
                tool_name = parsed["tool"]
                tool_args = parsed.get("arguments", {})
                _log(f"Tool call: {tool_name}({tool_args})")

                try:
                    result = self._database.call_tool(tool_name, tool_args)
                    history.append(f"TOOL CALL: {tool_name}({json.dumps(tool_args)})")
                    history.append(f"RESULT:\n{result}\n")
                except ValueError as e:
                    history.append(f"TOOL CALL: {tool_name}({json.dumps(tool_args)})")
                    history.append(f"ERROR: {e}\n")

        # Max iterations reached - ask for final answer
        _log(f"Max iterations reached, forcing final answer")
        history.append("You must now provide your final answer based on the data collected.")
        prompt = _QUERY_PROMPT.format(
            system=system,
            history="\n".join(history),
            query=structured_query,
        )
        response = self._model.generate(prompt)
        parsed = self._parse_response(response)

        if parsed and "answer" in parsed:
            return parsed["answer"]
        return response.strip()

    def _parse_response(self, response: str) -> dict | None:
        """Parse LLM response as JSON.

        Handles responses that may have markdown code blocks or extra text.
        """
        # Try to extract JSON from response
        # First, try the whole response
        text = response.strip()

        # Remove markdown code blocks if present
        if text.startswith("```"):
            match = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL)
            if match:
                text = match.group(1).strip()

        # Find JSON object
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if not match:
            return None

        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            return None
