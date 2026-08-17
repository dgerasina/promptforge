"""Pinned MCP adapters для Confluence, Jira и Airflow backend protocols."""

from __future__ import annotations

import re
from typing import Mapping, Protocol

from promptforge.core.project_profile import ProjectProfile
from urllib.parse import urlparse

from promptforge.platform.mcp_hub import McpAdapterCall, McpAdapterResponse, McpCapability


_VERSION = "1.0.0"
_SAFE_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_AIRFLOW_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+-]{0,249}$")
_PROJECT_KEY = re.compile(r"^[A-Z][A-Z0-9_]{0,31}$")


def _object_schema(
    properties: Mapping[str, object],
    required: tuple[str, ...] = (),
) -> dict[str, object]:
    return {
        "type": "object", "properties": dict(properties), "required": list(required),
        "additionalProperties": False,
    }


def _array_schema(item_schema: Mapping[str, object], max_items: int = 100) -> dict[str, object]:
    return {"type": "array", "items": dict(item_schema), "maxItems": max_items}


_STRING = {"type": "string", "maxLength": 4096}
_SHORT_STRING = {"type": "string", "maxLength": 256}
_LIMIT_20 = {"type": "integer", "minimum": 1, "maximum": 20}
_LIMIT_50 = {"type": "integer", "minimum": 1, "maximum": 50}

_PAGE_SUMMARY = _object_schema(
    {
        "id": _SHORT_STRING, "title": _SHORT_STRING, "space_key": _SHORT_STRING,
        "version": {"type": "integer", "minimum": 0}, "url": _STRING,
        "content_trust": {"type": "string", "enum": ["untrusted_external_data"]},
    },
    ("id", "title", "space_key", "version", "url", "content_trust"),
)
_PAGE = _object_schema(
    {**_PAGE_SUMMARY["properties"], "text": {"type": "string", "maxLength": 20000}},
    ("id", "title", "space_key", "version", "url", "content_trust", "text"),
)
_ISSUE_SUMMARY = _object_schema(
    {
        "key": _SHORT_STRING, "summary": _SHORT_STRING, "status": _SHORT_STRING,
        "issue_type": _SHORT_STRING, "assignee": _SHORT_STRING, "url": _STRING,
        "content_trust": {"type": "string", "enum": ["untrusted_external_data"]},
    },
    ("key", "summary", "status", "issue_type", "assignee", "url", "content_trust"),
)
_ISSUE = _object_schema(
    {**_ISSUE_SUMMARY["properties"], "description": {"type": "string", "maxLength": 20000}},
    ("key", "summary", "status", "issue_type", "assignee", "url", "content_trust", "description"),
)
_DAG = _object_schema(
    {"dag_id": _SHORT_STRING, "is_paused": {"type": "boolean"}}, ("dag_id", "is_paused"),
)
_DAG_RUN = _object_schema(
    {"dag_id": _SHORT_STRING, "run_id": _SHORT_STRING, "state": _SHORT_STRING},
    ("dag_id", "run_id", "state"),
)


def integration_capabilities() -> tuple[McpCapability, ...]:
    """Возвращает pinned capabilities в порядке Confluence → Jira → Airflow."""

    readers = ("owner", "maintainer", "engineer", "analyst")
    return (
        McpCapability.attested(
            "confluence.search_pages", "resource", "confluence", _VERSION,
            "Search approved Confluence pages before opening a page.", "read", "low", readers, "promptforge",
            _object_schema({"query": _SHORT_STRING, "space_key": _SHORT_STRING, "limit": _LIMIT_20},
                           ("query", "space_key", "limit")),
            _object_schema({"pages": _array_schema(_PAGE_SUMMARY, 20)}, ("pages",)),
        ),
        McpCapability.attested(
            "confluence.get_page", "resource", "confluence", _VERSION,
            "Read one approved Confluence page by numeric ID.", "read", "low", readers, "promptforge",
            _object_schema({"space_key": _SHORT_STRING, "page_id": _SHORT_STRING}, ("space_key", "page_id")), _PAGE,
        ),
        McpCapability.attested(
            "jira.search_issues", "tool", "jira", _VERSION,
            "Search one approved Jira project with structured text filters.", "read", "low", readers, "promptforge",
            _object_schema(
                {"project_key": _SHORT_STRING, "query": _SHORT_STRING, "limit": _LIMIT_50},
                ("project_key", "query", "limit"),
            ),
            _object_schema({"issues": _array_schema(_ISSUE_SUMMARY, 50)}, ("issues",)),
        ),
        McpCapability.attested(
            "jira.get_issue", "resource", "jira", _VERSION,
            "Read one visible Jira issue by exact issue key.", "read", "low", readers, "promptforge",
            _object_schema({"issue_key": _SHORT_STRING}, ("issue_key",)), _ISSUE,
        ),
        McpCapability.attested(
            "airflow.list_dags", "resource", "airflow", _VERSION,
            "List visible Airflow DAGs without changing scheduler state.", "read", "low", readers, "promptforge",
            _object_schema({"limit": _LIMIT_50}, ("limit",)),
            _object_schema({"dags": _array_schema(_DAG, 50)}, ("dags",)),
        ),
        McpCapability.attested(
            "airflow.list_dag_runs", "resource", "airflow", _VERSION,
            "List recent runs for one visible Airflow DAG.", "read", "low", readers, "promptforge",
            _object_schema({"dag_id": _SHORT_STRING, "limit": _LIMIT_50}, ("dag_id", "limit")),
            _object_schema({"dag_runs": _array_schema(_DAG_RUN, 50)}, ("dag_runs",)),
        ),
    )


def capabilities_for_project_profile(profile: ProjectProfile) -> tuple[McpCapability, ...]:
    """Возвращает только integration capabilities, включённые выбранным pack."""

    enabled = frozenset(profile.pack.integrations)
    capabilities = tuple(item for item in integration_capabilities() if item.server in enabled)
    if frozenset(item.server for item in capabilities) != enabled:
        raise ValueError("project pack requests an unavailable integration")
    return capabilities


class ConfluenceBackend(Protocol):
    def search_pages(self, query: str, space_key: str | None, limit: int) -> Mapping[str, object]: ...
    def get_page(self, space_key: str, page_id: str) -> Mapping[str, object]: ...


class JiraBackend(Protocol):
    def search_issues(self, project_key: str, query: str, limit: int) -> Mapping[str, object]: ...
    def get_issue(self, issue_key: str) -> Mapping[str, object]: ...


class AirflowBackend(Protocol):
    def list_dags(self, limit: int) -> Mapping[str, object]: ...
    def list_dag_runs(self, dag_id: str, limit: int) -> Mapping[str, object]: ...


class _BaseAdapter:
    def __init__(self, backend: object) -> None:
        self._backend = backend

    @staticmethod
    def _require_call(call: McpAdapterCall, server: str, capabilities: frozenset[str]) -> None:
        if call.version != _VERSION or call.capability_id not in capabilities:
            raise ValueError(f"unsupported {server} capability")


class ConfluenceMcpAdapter(_BaseAdapter):
    """Нормализует read-only Confluence backend без раскрытия credentials."""

    def __init__(self, backend: ConfluenceBackend, base_url: str, allowed_spaces: frozenset[str]) -> None:
        super().__init__(backend)
        self._base_url = _https_base_url(base_url)
        self._allowed_spaces = _safe_allowlist(allowed_spaces, "Confluence space")

    def invoke(self, call: McpAdapterCall) -> McpAdapterResponse:
        self._require_call(call, "Confluence", frozenset({"confluence.search_pages", "confluence.get_page"}))
        if call.operation != "read":
            raise ValueError("Confluence adapter is read-only")
        if call.capability_id == "confluence.search_pages":
            space_key = str(call.arguments["space_key"])
            if space_key not in self._allowed_spaces:
                raise PermissionError("Confluence space is not allowed")
            raw = self._backend.search_pages(
                str(call.arguments["query"]), space_key, int(call.arguments["limit"]),
            )
            pages = tuple(self._page_summary(item) for item in _items(raw, "results", 20))
            return McpAdapterResponse({"pages": pages})
        space_key = str(call.arguments["space_key"])
        if space_key not in self._allowed_spaces:
            raise PermissionError("Confluence space is not allowed")
        raw = self._backend.get_page(space_key, str(call.arguments["page_id"]))
        return McpAdapterResponse(self._page(raw))

    def _page_summary(self, value: Mapping[str, object]) -> dict[str, object]:
        page_id = _safe_value(value, "id")
        space_key = _safe_value(value, "space_key")
        if space_key not in self._allowed_spaces:
            raise PermissionError("Confluence response space is not allowed")
        return {
            "id": page_id, "title": str(value.get("title", ""))[:256],
            "space_key": space_key, "version": _nonnegative_int(value.get("version")),
            "url": f"{self._base_url}/pages/{page_id}", "content_trust": "untrusted_external_data",
        }

    def _page(self, value: Mapping[str, object]) -> dict[str, object]:
        return {**self._page_summary(value), "text": str(value.get("text", ""))[:20000]}


class JiraMcpAdapter(_BaseAdapter):
    """Нормализует два read-only Jira operations."""

    def __init__(
        self, backend: JiraBackend, base_url: str, allowed_projects: frozenset[str], *, account_visible: bool = False,
    ) -> None:
        super().__init__(backend)
        self._base_url = _https_base_url(base_url)
        self._allowed_projects = _safe_scope(allowed_projects, "Jira project", _PROJECT_KEY, account_visible)
        self._account_visible = account_visible

    def invoke(self, call: McpAdapterCall) -> McpAdapterResponse:
        self._require_call(call, "Jira", frozenset({"jira.search_issues", "jira.get_issue"}))
        if call.operation != "read":
            raise ValueError("Jira adapter is read-only")
        if call.capability_id == "jira.search_issues":
            project_key = str(call.arguments["project_key"])
            self._require_project(project_key)
            raw = self._backend.search_issues(
                project_key, str(call.arguments["query"]), int(call.arguments["limit"]),
            )
            issues = tuple(self._issue_summary(item, project_key) for item in _items(raw, "issues", 50))
            return McpAdapterResponse({"issues": issues})
        issue_key = str(call.arguments["issue_key"])
        self._require_project(issue_key.partition("-")[0])
        return McpAdapterResponse(self._issue(self._backend.get_issue(issue_key), issue_key))

    def _require_project(self, project_key: str) -> None:
        if not _PROJECT_KEY.fullmatch(project_key) or (
            not self._account_visible and project_key not in self._allowed_projects
        ):
            raise PermissionError("Jira project is not allowed")

    def _issue_summary(self, value: Mapping[str, object], expected_project: str) -> dict[str, str]:
        issue_key = _safe_value(value, "key")
        self._require_project(issue_key.partition("-")[0])
        if issue_key.partition("-")[0] != expected_project:
            raise PermissionError("Jira response project does not match request")
        return {
            "key": issue_key, "summary": str(value.get("summary", ""))[:256],
            "status": str(value.get("status", ""))[:256], "issue_type": str(value.get("issue_type", ""))[:256],
            "assignee": str(value.get("assignee", ""))[:256], "url": f"{self._base_url}/browse/{issue_key}",
            "content_trust": "untrusted_external_data",
        }

    def _issue(self, value: Mapping[str, object], expected_issue: str) -> dict[str, str]:
        result = self._issue_summary(value, expected_issue.partition("-")[0])
        if result["key"] != expected_issue:
            raise PermissionError("Jira response issue does not match request")
        return {**result, "description": str(value.get("description", ""))[:20000]}


class AirflowMcpAdapter(_BaseAdapter):
    """Предоставляет только allowlisted Airflow reads без side effects."""

    def __init__(
        self, backend: AirflowBackend, allowed_dags: frozenset[str], *, account_visible: bool = False,
    ) -> None:
        super().__init__(backend)
        self._allowed_dags = _safe_scope(allowed_dags, "Airflow DAG", _SAFE_KEY, account_visible)
        self._account_visible = account_visible

    def invoke(self, call: McpAdapterCall) -> McpAdapterResponse:
        self._require_call(
            call, "Airflow",
            frozenset({"airflow.list_dags", "airflow.list_dag_runs"}),
        )
        if call.capability_id == "airflow.list_dags" and call.operation == "read":
            raw = self._backend.list_dags(int(call.arguments["limit"]))
            dags = tuple(
                self._dag(item) for item in _items(raw, "dags", 50)
                if self._account_visible or item.get("dag_id") in self._allowed_dags
            )
            return McpAdapterResponse({"dags": dags})
        if call.capability_id == "airflow.list_dag_runs" and call.operation == "read":
            dag_id = str(call.arguments["dag_id"])
            self._require_dag(dag_id)
            raw = self._backend.list_dag_runs(dag_id, int(call.arguments["limit"]))
            runs = tuple(self._run(item, dag_id) for item in _items(raw, "dag_runs", 50))
            return McpAdapterResponse({"dag_runs": runs})
        raise ValueError("Airflow capability/operation mismatch")

    def _require_dag(self, dag_id: str) -> None:
        if not _SAFE_KEY.fullmatch(dag_id) or (not self._account_visible and dag_id not in self._allowed_dags):
            raise PermissionError("Airflow DAG is not allowed")

    @staticmethod
    def _dag(value: Mapping[str, object]) -> dict[str, object]:
        is_paused = value.get("is_paused")
        if not isinstance(is_paused, bool):
            raise ValueError("integration returned invalid is_paused")
        return {"dag_id": _safe_value(value, "dag_id"), "is_paused": is_paused}

    @staticmethod
    def _run(value: Mapping[str, object], expected_dag_id: str) -> dict[str, str]:
        dag_id = _safe_value(value, "dag_id")
        if dag_id != expected_dag_id:
            raise PermissionError("Airflow response DAG does not match request")
        return {
            "dag_id": dag_id, "run_id": _safe_value(value, "run_id", _AIRFLOW_RUN_ID),
            "state": str(value.get("state", ""))[:256],
        }


def _safe_allowlist(
    values: frozenset[str], label: str, pattern: re.Pattern[str] = _SAFE_KEY,
) -> frozenset[str]:
    if not values or any(not isinstance(value, str) or not pattern.fullmatch(value) for value in values):
        raise ValueError(f"{label} allowlist must contain safe identifiers")
    return frozenset(values)


def _safe_scope(
    values: frozenset[str], label: str, pattern: re.Pattern[str], account_visible: bool,
) -> frozenset[str]:
    if account_visible:
        if values:
            raise ValueError(f"{label} account-visible scope must not contain an allowlist")
        return frozenset()
    return _safe_allowlist(values, label, pattern)


def _https_base_url(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("integration base URL must be credential-free HTTPS")
    return value.rstrip("/")


def _items(value: Mapping[str, object], key: str, limit: int) -> tuple[Mapping[str, object], ...]:
    if not isinstance(value, Mapping) or not isinstance(value.get(key), (list, tuple)):
        raise ValueError("integration backend returned an invalid collection")
    items = tuple(value[key])[:limit]
    if any(not isinstance(item, Mapping) for item in items):
        raise ValueError("integration backend returned an invalid item")
    return items


def _safe_value(
    value: Mapping[str, object], key: str, pattern: re.Pattern[str] = _SAFE_KEY,
) -> str:
    result = value.get(key)
    if not isinstance(result, str) or not pattern.fullmatch(result):
        raise ValueError(f"integration returned unsafe {key}")
    return result


def _nonnegative_int(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        return 0
    return value
