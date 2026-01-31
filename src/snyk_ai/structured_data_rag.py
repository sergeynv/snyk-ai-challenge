import json
import re

from snyk_ai.structured_data_store import StructuredDataStore, TOOLS_DESCRIPTION
from snyk_ai.models import Model
from snyk_ai.utils.log import log

_SYSTEM_PROMPT = """You are a data analyst answering questions about a vulnerability database.

{tools}

RESPONSE FORMAT - You MUST respond with EXACTLY ONE of these:
  A) Tool call: ONLY a JSON object, nothing else
     {{"tool": "name", "arguments": {{...}}}}
  B) Final answer: ONLY plain text, no JSON anywhere

CRITICAL: Never mix text with JSON. Never include explanations with tool calls.

RULES:
- Call ONE tool at a time
- When you have enough data, answer IMMEDIATELY
- NEVER repeat a tool call
- NEVER call get_statistics with arguments other than group_by
- Final answers must be ONE sentence only
- NEVER include JSON, lists, or raw data in your answer - summarize in plain English
- NEVER do your own math - report values exactly as returned by tools
""".strip()

_QUERY_PROMPT = """
{system}

{history}

USER QUESTION: {query}

Respond with a JSON tool call OR a one-sentence plain text answer:
""".strip()

_FINAL_ANSWER_PROMPT = """
Answer in exactly ONE sentence using the data below.
NEVER include JSON, code, or lists. Summarize in plain English only.

DATA:
{history}

QUESTION: {query}

ONE SENTENCE ANSWER:
""".strip()

_MAX_ITERATIONS = 5


class StructuredDataRag:
    """Uses structured data to answer user's queries with tool-based access to the data store."""

    def __init__(self, model: Model, store: StructuredDataStore):
        """
        Args:
            model: LLM model for query planning and answer synthesis.
            store: Loaded vulnerability data store.
        """
        self._model = model
        self._store = store

    def handle_query(self, query: str) -> str:
        system = _SYSTEM_PROMPT.format(tools=TOOLS_DESCRIPTION)
        history: list[str] = []
        previous_calls: set[str] = set()

        for i in range(_MAX_ITERATIONS):
            history_text = "\n".join(history) if history else ""
            prompt = _QUERY_PROMPT.format(
                system=system,
                history=history_text,
                query=query,
            )

            response = self._model.generate(prompt)

            try:
                tool_call = self._parse_response(response)
            except ValueError as e:
                _log(f"Invalid response: {e}")
                history.append(f"ERROR: Your response was invalid: {e}")
                history.append(
                    "Respond with EITHER a JSON tool call OR plain text answer, not both."
                )
                continue

            if tool_call is None:
                _log("Got final answer")
                return response.strip()

            tool_name = tool_call["tool"]
            tool_args = tool_call.get("arguments", {})
            call_key = f"{tool_name}:{json.dumps(tool_args, sort_keys=True)}"

            _log("Tool call request:")
            _log(f"  {tool_name}({tool_args})")

            if call_key in previous_calls:
                _log("  -> [duplicate] forcing answer")
                break

            previous_calls.add(call_key)

            try:
                result = self._store.call_tool(tool_name, tool_args)
                _log(f"  -> [success]:\n{result}")
                history.append(f"TOOL CALL: {tool_name}({json.dumps(tool_args)})")
                history.append(f"RESULT:\n{result}\n")

            except ValueError as e:
                _log(f"  -> [error]:\n{e}")
                history.append(f"TOOL CALL: {tool_name}({json.dumps(tool_args)})")
                history.append(f"ERROR: {e}\n")

        # Force final answer with simplified prompt (no tools)
        _log("Forcing final answer")
        prompt = _FINAL_ANSWER_PROMPT.format(
            history="\n".join(history),
            query=query,
        )
        response = self._model.generate(prompt)
        return response.strip()

    def _parse_response(self, response: str) -> dict | None:
        text = response.strip()

        if not text:
            raise ValueError("Empty response from LLM")

        if (json_match := re.search(r"\{.*\}", text, re.DOTALL)) is None:
            # No JSON found - must be plain text answer
            return None

        # JSON found - check if there's text outside it
        json_str = json_match.group()
        before = text[: json_match.start()].strip()
        after = text[json_match.end() :].strip()

        if before or after:
            raise ValueError(
                f"Response contains both JSON and text. "
                f"Before: {before[:50]!r}, After: {after[:50]!r}"
            )

        # Pure JSON - parse it
        try:
            parsed = json.loads(json_str)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in response: {e}")

        if "tool" not in parsed:
            raise ValueError(f"JSON response missing 'tool' key: {json_str[:100]}")

        return parsed


def _log(message: str) -> None:
    log(message, "structured_rag")
