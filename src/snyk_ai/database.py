"""Structured vulnerability database with tool-use interface for LLMs.

Public API
----------
Database
    Main class for loading and querying vulnerability data.

    Constructor:
        Database(directory)
            Load CSV files from directory into SQLite (in-memory).
            Expects: vulnerabilities.csv, packages.csv,
                     severity_levels.csv, vulnerability_types.csv

    Properties:
        tools -> list[dict]
            Tool definitions for LLM function calling (OpenAI-compatible format).

    Methods:
        call_tool(name, arguments) -> str
            Execute a tool call and return results as formatted string.

Available Tools:
    get_vulnerability(cve_id) - Get details for a specific CVE
    search_vulnerabilities(ecosystem?, severity?, type?, min_cvss?, max_cvss?) - Filter vulnerabilities
    list_packages(ecosystem?) - List packages
    get_statistics(group_by?) - Aggregate statistics by ecosystem/severity/type
"""

from __future__ import annotations

import csv
import json
import sqlite3
from pathlib import Path

TABLES = [
    "vulnerabilities",
    "packages",
    "severity_levels",
    "vulnerability_types",
]

SCHEMAS: list[list[str]] = [
    # vulnerabilities
    [
        "cve_id",
        "package_id",
        "vulnerability_type_id",
        "severity_id",
        "cvss_score",
        "affected_versions",
        "fixed_version",
        "description",
        "published_date",
    ],
    # packages
    ["package_id", "name", "ecosystem"],
    # severity_levels
    ["severity_id", "severity_name", "min_cvss", "max_cvss"],
    # vulnerability_types
    ["type_id", "type_name", "description"],
]


class Database:
    """Structured vulnerability data with tool-use interface for LLMs."""

    def __init__(self, directory: Path | str):
        """Load CSV files from directory into SQLite.

        Args:
            directory: Path to directory containing CSV files.

        Raises:
            FileNotFoundError: If directory or required CSV files don't exist.
        """
        self._directory = Path(directory).resolve()

        if not self._directory.is_dir():
            raise FileNotFoundError(f"Directory not found: {self._directory}")

        for table in TABLES:
            csv_path = self._directory / f"{table}.csv"
            if not csv_path.exists():
                raise FileNotFoundError(f"Required file not found: {csv_path}")

        self._conn = sqlite3.connect(":memory:")
        self._conn.row_factory = sqlite3.Row
        self._load_data()

    def _load_data(self) -> None:
        """Load all CSV files into SQLite tables."""
        cursor = self._conn.cursor()

        # Create tables and load data
        for table, columns in zip(TABLES, SCHEMAS):
            # Create table
            cols_def = ", ".join(columns)
            cursor.execute(f"CREATE TABLE {table} ({cols_def})")

            # Load data from CSV
            csv_path = self._directory / f"{table}.csv"
            with open(csv_path, newline="") as f:
                reader = csv.DictReader(f)
                placeholders = ", ".join("?" for _ in columns)
                for row in reader:
                    values = tuple(row[col] for col in columns)
                    cursor.execute(
                        f"INSERT INTO {table} VALUES ({placeholders})", values
                    )

        self._conn.commit()

    @property
    def tools(self) -> list[dict]:
        """Return tool definitions for LLM function calling.

        Returns OpenAI-compatible tool definitions that can also be
        adapted for Anthropic and other providers.
        """
        return [
            {
                "type": "function",
                "function": {
                    "name": "get_vulnerability",
                    "description": "Get detailed information about a specific CVE vulnerability, including package, severity, and type details.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "cve_id": {
                                "type": "string",
                                "description": "The CVE identifier (e.g., 'CVE-2024-1234')",
                            }
                        },
                        "required": ["cve_id"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "search_vulnerabilities",
                    "description": "Search and filter vulnerabilities by ecosystem, severity, type, or CVSS score range.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "ecosystem": {
                                "type": "string",
                                "description": "Filter by package ecosystem (e.g., 'npm', 'pip', 'maven')",
                            },
                            "severity": {
                                "type": "string",
                                "description": "Filter by severity level (e.g., 'Critical', 'High', 'Medium', 'Low')",
                            },
                            "type": {
                                "type": "string",
                                "description": "Filter by vulnerability type (e.g., 'SQL Injection', 'XSS')",
                            },
                            "min_cvss": {
                                "type": "number",
                                "description": "Minimum CVSS score (0.0 to 10.0)",
                            },
                            "max_cvss": {
                                "type": "number",
                                "description": "Maximum CVSS score (0.0 to 10.0)",
                            },
                        },
                        "required": [],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "list_packages",
                    "description": "List all packages in the database, optionally filtered by ecosystem.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "ecosystem": {
                                "type": "string",
                                "description": "Filter by package ecosystem (e.g., 'npm', 'pip', 'maven')",
                            }
                        },
                        "required": [],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "get_statistics",
                    "description": "Get aggregate statistics about vulnerabilities, grouped by a dimension.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "group_by": {
                                "type": "string",
                                "enum": ["ecosystem", "severity", "type"],
                                "description": "Dimension to group by: 'ecosystem', 'severity', or 'type'",
                            }
                        },
                        "required": [],
                    },
                },
            },
        ]

    def call_tool(self, name: str, arguments: dict) -> str:
        """Execute a tool call and return results as formatted string.

        Args:
            name: Tool name (get_vulnerability, search_vulnerabilities, etc.)
            arguments: Tool arguments as dictionary.

        Returns:
            JSON-formatted string with results.

        Raises:
            ValueError: If tool name is not recognized.
        """
        handlers = {
            "get_vulnerability": self._get_vulnerability,
            "search_vulnerabilities": self._search_vulnerabilities,
            "list_packages": self._list_packages,
            "get_statistics": self._get_statistics,
        }

        if name not in handlers:
            raise ValueError(f"Unknown tool: {name}")

        result = handlers[name](arguments)
        return json.dumps(result, indent=2)

    def _get_vulnerability(self, args: dict) -> dict:
        """Get details for a specific CVE."""
        cve_id = args.get("cve_id")
        if not cve_id:
            return {"error": "cve_id is required"}

        cursor = self._conn.cursor()
        cursor.execute(
            """
            SELECT
                v.cve_id,
                v.cvss_score,
                v.affected_versions,
                v.fixed_version,
                v.description,
                v.published_date,
                p.name AS package_name,
                p.ecosystem,
                s.severity_name,
                t.type_name
            FROM vulnerabilities v
            JOIN packages p ON v.package_id = p.package_id
            JOIN severity_levels s ON v.severity_id = s.severity_id
            JOIN vulnerability_types t ON v.vulnerability_type_id = t.type_id
            WHERE v.cve_id = ?
            """,
            (cve_id,),
        )

        row = cursor.fetchone()
        if not row:
            return {"error": f"CVE not found: {cve_id}"}

        return dict(row)

    def _search_vulnerabilities(self, args: dict) -> dict:
        """Search and filter vulnerabilities."""
        conditions = []
        params = []

        if "ecosystem" in args:
            conditions.append("p.ecosystem = ?")
            params.append(args["ecosystem"])

        if "severity" in args:
            conditions.append("s.severity_name = ?")
            params.append(args["severity"])

        if "type" in args:
            conditions.append("t.type_name = ?")
            params.append(args["type"])

        if "min_cvss" in args:
            conditions.append("CAST(v.cvss_score AS REAL) >= ?")
            params.append(args["min_cvss"])

        if "max_cvss" in args:
            conditions.append("CAST(v.cvss_score AS REAL) <= ?")
            params.append(args["max_cvss"])

        where_clause = " AND ".join(conditions) if conditions else "1=1"

        cursor = self._conn.cursor()
        cursor.execute(
            f"""
            SELECT
                v.cve_id,
                v.cvss_score,
                v.affected_versions,
                v.fixed_version,
                v.description,
                p.name AS package_name,
                p.ecosystem,
                s.severity_name,
                t.type_name
            FROM vulnerabilities v
            JOIN packages p ON v.package_id = p.package_id
            JOIN severity_levels s ON v.severity_id = s.severity_id
            JOIN vulnerability_types t ON v.vulnerability_type_id = t.type_id
            WHERE {where_clause}
            ORDER BY CAST(v.cvss_score AS REAL) DESC
            """,
            params,
        )

        rows = cursor.fetchall()
        return {
            "count": len(rows),
            "vulnerabilities": [dict(row) for row in rows],
        }

    def _list_packages(self, args: dict) -> dict:
        """List packages, optionally filtered by ecosystem."""
        cursor = self._conn.cursor()

        if "ecosystem" in args:
            cursor.execute(
                "SELECT * FROM packages WHERE ecosystem = ? ORDER BY name",
                (args["ecosystem"],),
            )
        else:
            cursor.execute("SELECT * FROM packages ORDER BY ecosystem, name")

        rows = cursor.fetchall()
        return {
            "count": len(rows),
            "packages": [dict(row) for row in rows],
        }

    def _get_statistics(self, args: dict) -> dict:
        """Get aggregate statistics."""
        group_by = args.get("group_by")
        cursor = self._conn.cursor()

        if group_by == "ecosystem":
            cursor.execute(
                """
                SELECT p.ecosystem, COUNT(*) as count, AVG(v.cvss_score) as avg_cvss
                FROM vulnerabilities v
                JOIN packages p ON v.package_id = p.package_id
                GROUP BY p.ecosystem
                ORDER BY count DESC
                """
            )
        elif group_by == "severity":
            cursor.execute(
                """
                SELECT s.severity_name, COUNT(*) as count, AVG(v.cvss_score) as avg_cvss
                FROM vulnerabilities v
                JOIN severity_levels s ON v.severity_id = s.severity_id
                GROUP BY s.severity_name
                ORDER BY AVG(v.cvss_score) DESC
                """
            )
        elif group_by == "type":
            cursor.execute(
                """
                SELECT t.type_name, COUNT(*) as count, AVG(v.cvss_score) as avg_cvss
                FROM vulnerabilities v
                JOIN vulnerability_types t ON v.vulnerability_type_id = t.type_id
                GROUP BY t.type_name
                ORDER BY count DESC
                """
            )
        else:
            # Overall statistics
            cursor.execute(
                """
                SELECT
                    COUNT(*) as total_vulnerabilities,
                    AVG(cvss_score) as avg_cvss,
                    MIN(cvss_score) as min_cvss,
                    MAX(cvss_score) as max_cvss
                FROM vulnerabilities
                """
            )
            row = cursor.fetchone()
            return dict(row)

        rows = cursor.fetchall()
        return {
            "group_by": group_by,
            "statistics": [dict(row) for row in rows],
        }
