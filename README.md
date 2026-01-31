# snyk-ai

A hybrid RAG system for security vulnerability data.

## Usage

```bash
uv run snyk-ai [--verbose | -v] [--model | -m MODEL] <data_dir>
```

- `data_dir` - Path to data directory (must contain `advisories/` and `csv/` subdirectories)
- `--model`, `-m` - Model spec in `provider:model` format (default: `ollama:llama3.2`)
- `--verbose`, `-v` - Enable verbose logging

Examples:

```bash
uv run snyk-ai data/
uv run snyk-ai -m anthropic:claude-haiku-4-5 data/
uv run snyk-ai -v -m openai:gpt-5.2-mini data/
```

## Setup

This project uses [uv](https://docs.astral.sh/uv/) for package management.

```bash
uv sync
```

For local inference with Ollama (default):

```bash
brew install ollama
ollama serve
ollama pull llama3.2
```

## Supported Models

Default: `ollama:llama3.2`

### Ollama (local)

```bash
ollama serve        # start server on port 11434
ollama pull MODEL   # download a model
```

### Anthropic

Requires `ANTHROPIC_API_KEY` environment variable.

Models: `claude-haiku-4-5`, `claude-sonnet-4-5`, `claude-opus-4-5`

### OpenAI

Requires `OPENAI_API_KEY` environment variable.

Models: `gpt-5.2`, `gpt-5.2-mini`

## Architecture

### Overview

```
+-------------+                                           +----------+
| Advisories* |                                           | Database |
|  (ChromaDB) |                                           | (SQLite) |
+------+------+                                           +----+-----+
       ^ search                                                ^ call_tool
       |                                                       |
+------+--------+                                        +-----+-------+
|AdvisoriesRag* |                                        | DatabaseRag*|
+------+--------+                                        +-----+-------+
       ^                                                       ^
       | UNSTRUCTURED                               STRUCTURED |
       | or HYBRID                                   or HYBRID |
       |                 +----------+                          |
       +-----------------+ Router*  +--------------------------+
                         +----+-----+
                              ^
                              |
                         User Query


For HYBRID queries only:
AdvisoriesRag ---+
                 +--> Synthesizer* --> Answer
DatabaseRag -----+

* = uses LLM (Advisories* uses LLM at init to summarize code for embedding)
```

The system routes queries to the appropriate data source(s):

- **UNSTRUCTURED** - Advisory documents (explanations, attack patterns, remediation)
- **STRUCTURED** - Database (CVE lookups, filtering, statistics)
- **HYBRID** - Both sources, then synthesized
- **NONE** - Off-topic queries

### Models (`models.py`)

LLM provider abstraction layer. Providers: Ollama (local), OpenAI, Anthropic.

**Public API:**

```python
create_model(spec: str) -> Model  # Factory: "ollama:llama3.2", "anthropic:claude-haiku-4-5"
Model.generate(prompt: str) -> str  # Send prompt, get response
```

### Advisories (`advisories.py`)

Unstructured data: parses security advisory markdown files into sections, builds ChromaDB vector index. Vector DB persisted in `.chroma/` directory for fast subsequent loads.

Uses LLM during `init_vectordb()` to summarize code snippets before embedding (code doesn't embed well as-is).

**Public API:**

```python
Advisories(directory: Path | str)  # Load and parse .md files
  .init_vectordb(model: Model) -> None  # Build/load ChromaDB embeddings
  .search(query: str, top_k: int = 5) -> list[str]  # Semantic search
  .get_summaries() -> list[tuple[str, str]]  # (title, executive_summary) pairs
  .filenames -> list[str]  # List of loaded advisory filenames
```

### Database (`database.py`)

Structured data: loads CSV files into SQLite, exposes tool-use interface.

Tables: `vulnerabilities`, `packages`, `severity_levels`, `vulnerability_types`

**Public API:**

```python
Database(directory: Path | str)  # Load CSVs into SQLite
  .tools -> list[dict]  # OpenAI-compatible tool definitions
  .call_tool(name: str, arguments: dict) -> str  # Execute tool, get JSON result
```

Tools: `get_vulnerability`, `search_vulnerabilities`, `list_packages`, `get_statistics`

### Router (`router.py`)

LLM-based query classification. The router prompt includes advisory summaries and database schema to make informed routing decisions.

**Public API:**

```python
Router(model: Model, advisories: Advisories)
  .route(query: str) -> RouteResult  # Classify query

RouteResult:
  .route_type: RouteType  # UNSTRUCTURED | STRUCTURED | HYBRID | NONE
  .unstructured_query: str | None  # Transformed query for advisories
  .structured_query: str | None  # Transformed query for database
  .reasoning: str  # Explanation of routing decision
```

### AdvisoriesRag (`advisories_rag.py`)

Handles unstructured queries via semantic search + LLM synthesis.

**Public API:**

```python
AdvisoriesRag(model: Model, advisories: Advisories)
  .query(unstructured_query: str, top_k: int = 3) -> str  # Search + synthesize answer
```

### DatabaseRag (`database_rag.py`)

Handles structured queries via agentic tool-use loop (max 5 iterations).

**Public API:**

```python
DatabaseRag(model: Model, database: Database)
  .query(structured_query: str) -> str  # Tool loop + synthesize answer
```

### Synthesizer (`synthesizer.py`)

Combines outputs from both RAG systems for hybrid queries.

**Public API:**

```python
Synthesizer(model: Model)
  .synthesize(user_query, router_reasoning, unstructured_answer, structured_answer) -> str
```

### Agent (`agent.py`)

Main orchestrator coordinating all components. Supports different models for different roles.

**Public API:**

```python
Agent(advisories_dir, csv_dir, router_model, advisories_rag_model,
      code_summarizing_model, db_query_model, synthesizer_model)
  .process_user_query(query: str) -> str  # Route and process through pipeline
```

## Notebooks

Dedicated notebooks in `notebooks/` for in-depth exploration:

- `advisories.ipynb` - Explores the `Advisories` class: parsing, chunking, vector DB, search
- `router.ipynb` - Explores the `Router` class: query classification and routing decisions

```bash
uv run jupyter notebook notebooks/advisories.ipynb
uv run jupyter notebook notebooks/router.ipynb
```
