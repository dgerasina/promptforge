"""Read-only stdlib HTTPS backends for approved corporate integrations."""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import ssl
import stat
from types import MappingProxyType
from typing import Mapping, Protocol
from urllib.parse import quote, urlencode, urlsplit

from promptforge.platform.integrations import AirflowMcpAdapter, ConfluenceMcpAdapter, JiraMcpAdapter
from promptforge.platform.secure_filesystem import SECURE_FILESYSTEM


_ENV_PREFIX = "PF_INTEGRATION_"
_SERVICES = frozenset({"confluence", "jira", "airflow"})
_RESOURCE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_ISSUE_KEY = re.compile(r"^[A-Z][A-Z0-9_]{0,31}-[1-9][0-9]{0,18}$")
_PAGE_ID = re.compile(r"^[1-9][0-9]{0,30}$")
_HOST = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$")
_COMMON_ENV_KEYS = frozenset({
    "PF_INTEGRATION_TIMEOUT_SECONDS",
    "PF_INTEGRATION_MAX_RESPONSE_BYTES",
    "PF_INTEGRATION_CA_FILE",
})
_RESOURCE_ENV_NAMES = {
    "confluence": "ALLOWED_SPACES",
    "jira": "ALLOWED_PROJECTS",
    "airflow": "ALLOWED_DAGS",
}
_AUTH_MODES = frozenset({"basic", "bearer-token", "session-cookie-file"})
_SCOPE_MODES = frozenset({"exact", "account-visible-read-only"})
_PROJECT_KEY = re.compile(r"^[A-Z][A-Z0-9_]{0,31}$")


def _service_env_keys(service: str) -> frozenset[str]:
    prefix = f"{_ENV_PREFIX}{service.upper()}_"
    return frozenset({
        f"{prefix}URL", f"{prefix}USERNAME", f"{prefix}TOKEN",
        f"{prefix}AUTH_MODE", f"{prefix}SESSION_FILE", f"{prefix}SCOPE_MODE",
        f"{prefix}{_RESOURCE_ENV_NAMES[service]}",
    })


_ALL_ENV_KEYS = _COMMON_ENV_KEYS.union(*(_service_env_keys(service) for service in _SERVICES))


@dataclass(frozen=True)
class IntegrationHttpConfig:
    """Validated endpoint, credentials and resource scope for one integration."""

    service: str
    base_url: str
    username: str = field(repr=False)
    token: str = field(repr=False)
    allowed_resources: frozenset[str]
    auth_mode: str = "basic"
    scope_mode: str = "exact"
    session_cookie: str = field(default="", repr=False)
    timeout_seconds: int = 10
    max_response_bytes: int = 1_000_000
    ca_file: str = field(default="", repr=False)
    host: str = field(init=False)
    port: int | None = field(init=False)
    base_path: str = field(init=False)
    ca_digest: str = field(init=False)
    ca_data: str = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.service not in _SERVICES:
            raise ValueError("unsupported integration service")
        parsed = urlsplit(self.base_url)
        path = parsed.path.rstrip("/")
        if (
            parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.query or parsed.fragment or parsed.path != path
            or "%" in path or "\\" in path or "//" in path
            or any(segment in {".", ".."} for segment in path.split("/"))
        ):
            raise ValueError("integration URL must be canonical credential-free HTTPS")
        try:
            port = parsed.port
        except ValueError as error:
            raise ValueError("integration URL has an invalid port") from error
        if port is not None and not 1 <= port <= 65_535:
            raise ValueError("integration URL has an invalid port")
        host = (parsed.hostname or "").lower()
        if not _HOST.fullmatch(host) or host.endswith(".") or ".." in host:
            raise ValueError("integration hostname is not canonical")
        if self.auth_mode not in _AUTH_MODES:
            raise ValueError("integration authentication mode is invalid")
        if self.auth_mode == "basic":
            if (
                not 1 <= len(self.username) <= 256 or not 1 <= len(self.token) <= 8_192 or self.session_cookie
                or any(ord(char) < 0x20 or ord(char) == 0x7F for char in self.username + self.token)
            ):
                raise ValueError("integration credentials are missing or invalid")
        elif self.auth_mode == "bearer-token":
            if (
                self.service != "jira" or self.username or self.session_cookie
                or not _valid_secret(self.token)
            ):
                raise ValueError("integration bearer credentials are missing or invalid")
        elif self.username or self.token or not _valid_cookie(self.session_cookie):
            raise ValueError("integration session credentials are missing or conflicting")
        if self.scope_mode not in _SCOPE_MODES:
            raise ValueError("integration scope mode is invalid")
        if self.scope_mode == "account-visible-read-only" and self.service == "confluence":
            raise ValueError("Confluence requires an exact space allowlist")
        if self.scope_mode == "exact" and not self.allowed_resources:
            raise ValueError("integration resource allowlist is empty")
        if any(not _RESOURCE_NAME.fullmatch(item) for item in self.allowed_resources):
            raise ValueError("integration resource allowlist is invalid")
        if self.scope_mode == "account-visible-read-only" and self.allowed_resources:
            raise ValueError("account-visible scope must not contain an allowlist")
        if (not isinstance(self.timeout_seconds, int) or isinstance(self.timeout_seconds, bool)
                or not 1 <= self.timeout_seconds <= 60):
            raise ValueError("integration timeout is invalid")
        if (not isinstance(self.max_response_bytes, int) or isinstance(self.max_response_bytes, bool)
                or not 1 <= self.max_response_bytes <= 10_000_000):
            raise ValueError("integration response limit is invalid")
        ca_digest, ca_data = _ca_material(self.ca_file)
        object.__setattr__(self, "host", host)
        object.__setattr__(self, "port", port)
        object.__setattr__(self, "base_path", path)
        object.__setattr__(self, "ca_digest", ca_digest)
        object.__setattr__(self, "ca_data", ca_data)

    @classmethod
    def from_env(
        cls, service: str, environment: Mapping[str, str] | None = None, *, validate_unknown: bool = True,
    ) -> IntegrationHttpConfig:
        """Loads only exact allowlisted variables from an injected environment mapping."""

        if service not in _SERVICES:
            raise ValueError("unsupported integration service")
        source = os.environ if environment is None else environment
        allowed_keys = _service_env_keys(service) | _COMMON_ENV_KEYS
        if validate_unknown:
            unknown = sorted(key for key in source if key.startswith(_ENV_PREFIX) and key not in allowed_keys)
            if unknown:
                raise ValueError(f"unknown integration environment variable: {unknown[0]}")
        prefix = f"{_ENV_PREFIX}{service.upper()}_"
        resource_key = f"{prefix}{_RESOURCE_ENV_NAMES[service]}"
        resources = frozenset(item.strip() for item in source.get(resource_key, "").split(",") if item.strip())
        return cls(
            service=service,
            base_url=source.get(f"{prefix}URL", ""),
            username=source.get(f"{prefix}USERNAME", ""),
            token=source.get(f"{prefix}TOKEN", ""),
            allowed_resources=resources,
            auth_mode=source.get(f"{prefix}AUTH_MODE", "basic"),
            scope_mode=source.get(f"{prefix}SCOPE_MODE", "exact"),
            session_cookie=_load_session_cookie(source.get(f"{prefix}SESSION_FILE", "")),
            timeout_seconds=_env_int(source, "PF_INTEGRATION_TIMEOUT_SECONDS", 10),
            max_response_bytes=_env_int(source, "PF_INTEGRATION_MAX_RESPONSE_BYTES", 1_000_000),
            ca_file=source.get("PF_INTEGRATION_CA_FILE", ""),
        )

    def authorization_headers(self) -> dict[str, str]:
        """Builds a runtime-only authorization header without persisting credentials."""

        if self.auth_mode == "session-cookie-file":
            return {"Accept": "application/json", "Cookie": self.session_cookie}
        if self.auth_mode == "bearer-token":
            return {"Accept": "application/json", "Authorization": f"Bearer {self.token}"}
        encoded = base64.b64encode(f"{self.username}:{self.token}".encode("utf-8")).decode("ascii")
        return {"Accept": "application/json", "Authorization": f"Basic {encoded}"}

    def allows(self, resource: str) -> bool:
        """Checks exact scope or a safe server-authorized identifier."""

        if not isinstance(resource, str) or not _RESOURCE_NAME.fullmatch(resource):
            return False
        if self.service == "jira" and not _PROJECT_KEY.fullmatch(resource):
            return False
        return self.scope_mode == "account-visible-read-only" or resource in self.allowed_resources

    def smoke_resource(self, candidate: str | None) -> str:
        """Resolves one bounded read probe without guessing an account-visible resource."""

        if candidate is None:
            if self.scope_mode == "account-visible-read-only":
                raise ValueError("account-visible smoke requires an explicit resource")
            candidate = sorted(self.allowed_resources)[0]
        if not self.allows(candidate):
            raise PermissionError("integration smoke resource is not allowed")
        return candidate


def _valid_cookie(value: str) -> bool:
    return 1 <= len(value) <= 8_192 and all(0x20 <= ord(char) < 0x7F for char in value)


def _valid_secret(value: str) -> bool:
    return 1 <= len(value) <= 8_192 and all(0x21 <= ord(char) < 0x7F for char in value)


def _load_session_cookie(raw_path: str) -> str:
    if not raw_path:
        return ""
    if not os.path.isabs(raw_path):
        raise ValueError("integration session file must be an absolute regular file")
    path = Path(raw_path)
    try:
        if path.is_symlink() or path.resolve(strict=True) != path:
            raise ValueError("integration session file path must not contain symlinks")
    except OSError as error:
        raise ValueError("integration session file is unavailable") from error
    try:
        raw = SECURE_FILESYSTEM.read_private(path, 8_192)
        value = raw.decode("utf-8")
    except (OSError, UnicodeError) as error:
        raise ValueError("integration session file is unavailable") from error
    if not _valid_cookie(value):
        raise ValueError("integration session file content is invalid")
    return value


def _env_int(source: Mapping[str, str], key: str, default: int) -> int:
    try:
        return int(source.get(key, str(default)))
    except (TypeError, ValueError) as error:
        raise ValueError(f"{key} must be an integer") from error


def _ca_material(raw_path: str) -> tuple[str, str]:
    if not raw_path:
        return "system", ""
    path = Path(raw_path)
    try:
        canonical = path.resolve(strict=True)
    except OSError as error:
        raise ValueError("integration CA file is unavailable") from error
    if not path.is_absolute() or path.is_symlink() or canonical != path:
        raise ValueError("integration CA file must be an absolute regular file")
    try:
        content = SECURE_FILESYSTEM.read_trusted(path, 2_000_000)
    except OSError as error:
        raise ValueError("integration CA file is unavailable") from error
    try:
        ca_data = content.decode("ascii")
        ssl.create_default_context(cadata=ca_data)
    except (UnicodeError, ssl.SSLError) as error:
        raise ValueError("integration CA file is not valid PEM") from error
    return "sha256:" + hashlib.sha256(content).hexdigest(), ca_data


def _verified_ssl_context(ca_data: str = "") -> ssl.SSLContext:
    """Build a verified context, allowing an explicitly trusted legacy corporate CA."""

    context = ssl.create_default_context(cadata=ca_data) if ca_data else ssl.create_default_context()
    strict = getattr(ssl, "VERIFY_X509_STRICT", 0)
    if ca_data and strict:
        context.verify_flags &= ~strict
    if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
        raise RuntimeError("integration TLS verification is unavailable")
    return context


class IntegrationTransport(Protocol):
    def get_json(
        self, url: str, headers: dict[str, str], timeout_seconds: int, max_response_bytes: int,
    ) -> Mapping[str, object]: ...


@dataclass(frozen=True)
class StdlibHttpsTransport:
    """Performs one direct HTTPS GET without proxies or redirect handling."""

    allowed_host: str
    allowed_path_prefixes: str | tuple[str, ...]
    allowed_port: int | None = None
    ca_data: str = field(default="", repr=False, compare=False)
    ssl_context: ssl.SSLContext = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        prefixes = ((self.allowed_path_prefixes,) if isinstance(self.allowed_path_prefixes, str)
                    else self.allowed_path_prefixes)
        if not self.allowed_host or not prefixes or any(not path.startswith("/") for path in prefixes):
            raise ValueError("transport allowlist is invalid")
        object.__setattr__(self, "allowed_path_prefixes", tuple(path.rstrip("/") or "/" for path in prefixes))
        object.__setattr__(self, "ssl_context", _verified_ssl_context(self.ca_data))

    def get_json(
        self, url: str, headers: dict[str, str], timeout_seconds: int, max_response_bytes: int,
    ) -> Mapping[str, object]:
        parsed = urlsplit(url)
        try:
            port = parsed.port
        except ValueError:
            port = -1
        valid_path = any(
            parsed.path == prefix or parsed.path.startswith(f"{prefix}/")
            for prefix in self.allowed_path_prefixes
        )
        if (
            parsed.scheme != "https"
            or (parsed.hostname or "").lower() != self.allowed_host
            or port != self.allowed_port
            or parsed.username is not None or parsed.password is not None or parsed.fragment or not valid_path
        ):
            raise RuntimeError("integration transport target is not allowed")
        connection = http.client.HTTPSConnection(
            self.allowed_host, self.allowed_port, timeout=timeout_seconds, context=self.ssl_context,
        )
        try:
            target = parsed.path + (f"?{parsed.query}" if parsed.query else "")
            connection.request("GET", target, headers=headers)
            response = connection.getresponse()
            content_type = response.getheader("Content-Type", "").split(";", 1)[0].strip().lower()
            if response.status != 200 or content_type != "application/json":
                raise RuntimeError("integration returned an invalid response")
            content_length = response.getheader("Content-Length")
            if content_length is not None:
                try:
                    if int(content_length) < 0 or int(content_length) > max_response_bytes:
                        raise RuntimeError("integration response exceeds configured limit")
                except ValueError as error:
                    raise RuntimeError("integration returned an invalid content length") from error
            body = response.read(max_response_bytes + 1)
            if len(body) > max_response_bytes:
                raise RuntimeError("integration response exceeds configured limit")
            value = json.loads(
                body.decode("utf-8"), object_pairs_hook=_unique_object,
                parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("non-finite JSON number")),
            )
            if not isinstance(value, dict):
                raise ValueError("JSON root is not an object")
            return MappingProxyType(value)
        except Exception:
            raise RuntimeError("integration HTTPS request failed") from None
        finally:
            connection.close()


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


class _HttpBackend:
    def __init__(self, config: IntegrationHttpConfig, transport: IntegrationTransport | None, api_path: str) -> None:
        if config.service != self.service:
            raise ValueError("integration config does not match backend")
        self._config = config
        self._transport = transport or StdlibHttpsTransport(
            config.host, f"{config.base_path}{api_path}", config.port, config.ca_data,
        )

    @property
    def service(self) -> str:
        raise NotImplementedError

    def _get(self, path: str, query: Mapping[str, object] | None = None) -> Mapping[str, object]:
        suffix = f"?{urlencode(query)}" if query else ""
        return self._transport.get_json(
            f"{self._config.base_url}{path}{suffix}", self._config.authorization_headers(),
            self._config.timeout_seconds, self._config.max_response_bytes,
        )

    def _require_allowed(self, resource: str, label: str) -> None:
        if not self._config.allows(resource):
            raise PermissionError(f"{label} is not allowed")


class ConfluenceHttpBackend(_HttpBackend):
    """Reads allowlisted Confluence spaces through REST API v1."""

    service = "confluence"

    def __init__(self, config: IntegrationHttpConfig, transport: IntegrationTransport | None = None) -> None:
        super().__init__(config, transport, "/rest/api")

    def search_pages(self, query: str, space_key: str | None, limit: int) -> Mapping[str, object]:
        if space_key is None:
            raise PermissionError("Confluence space is required")
        self._require_allowed(space_key, "Confluence space")
        _require_limit(limit, 20)
        cql = f'space={space_key} AND text~"{_cql_text(query)}"'
        payload = self._get("/rest/api/content/search", {"cql": cql, "limit": limit, "expand": "space,version"})
        results = _list(payload, "results", 20)
        return {"results": [self._page(item, include_text=False) for item in results]}

    def get_page(self, space_key: str, page_id: str) -> Mapping[str, object]:
        self._require_allowed(space_key, "Confluence space")
        if not _PAGE_ID.fullmatch(page_id):
            raise ValueError("Confluence page ID is invalid")
        payload = self._get(f"/rest/api/content/{quote(page_id, safe='')}", {"expand": "space,version,body.storage"})
        page = self._page(payload, include_text=True)
        if page["space_key"] != space_key:
            raise PermissionError("Confluence response space is not allowed")
        return page

    @staticmethod
    def _page(value: Mapping[str, object], include_text: bool) -> dict[str, object]:
        space = _mapping(value, "space")
        version = _mapping(value, "version")
        result: dict[str, object] = {
            "id": _string(value, "id"), "title": _string(value, "title"),
            "space_key": _string(space, "key"), "version": _integer(version, "number", minimum=0),
        }
        if include_text:
            result["text"] = _string(_mapping(_mapping(value, "body"), "storage"), "value")
        return result


def _cql_text(value: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 256 or any(char in value for char in '\\"\r\n'):
        raise ValueError("Confluence query is invalid")
    return value


class JiraHttpBackend(_HttpBackend):
    """Reads allowlisted Jira projects through REST API v2."""

    service = "jira"

    def __init__(self, config: IntegrationHttpConfig, transport: IntegrationTransport | None = None) -> None:
        super().__init__(config, transport, "/rest/api/2")

    def search_issues(self, project_key: str, query: str, limit: int) -> Mapping[str, object]:
        self._require_allowed(project_key, "Jira project")
        _require_limit(limit, 50)
        if not isinstance(query, str) or len(query) > 256 or any(char in query for char in '\\"\r\n'):
            raise ValueError("Jira query is invalid")
        jql = f'project = "{project_key}" AND text ~ "{query}"'
        payload = self._get("/rest/api/2/search", {"jql": jql, "maxResults": limit})
        issues = [self._issue(item) for item in _list(payload, "issues", 50)]
        if any(str(item["key"]).partition("-")[0] != project_key for item in issues):
            raise PermissionError("Jira response project does not match request")
        return {"issues": issues}

    def get_issue(self, issue_key: str) -> Mapping[str, object]:
        project = issue_key.partition("-")[0]
        if not _ISSUE_KEY.fullmatch(issue_key):
            raise ValueError("Jira issue key is invalid")
        self._require_allowed(project, "Jira project")
        issue = self._issue(self._get(f"/rest/api/2/issue/{quote(issue_key, safe='')}"))
        if issue["key"] != issue_key:
            raise PermissionError("Jira response issue does not match request")
        return issue

    def _issue(self, value: Mapping[str, object]) -> dict[str, object]:
        key = _string(value, "key")
        if not _ISSUE_KEY.fullmatch(key):
            raise ValueError("Jira response issue key is invalid")
        self._require_allowed(key.partition("-")[0], "Jira project")
        fields = _mapping(value, "fields")
        assignee = fields.get("assignee")
        description = fields.get("description", "")
        return {
            "key": key, "summary": _string(fields, "summary"),
            "status": _string(_mapping(fields, "status"), "name"),
            "issue_type": _string(_mapping(fields, "issuetype"), "name"),
            "assignee": "" if assignee is None else _string(_as_mapping(assignee), "displayName"),
            "description": description if isinstance(description, str) else json.dumps(description, sort_keys=True),
        }


class AirflowHttpBackend(_HttpBackend):
    """Reads allowlisted DAG metadata and runs through stable Airflow API v1."""

    service = "airflow"

    def __init__(self, config: IntegrationHttpConfig, transport: IntegrationTransport | None = None) -> None:
        super().__init__(config, transport, "/api/v1")

    def list_dags(self, limit: int) -> Mapping[str, object]:
        _require_limit(limit, 50)
        payload = self._get("/api/v1/dags", {"limit": limit, "only_active": "true"})
        dags = [self._dag(item) for item in _list(payload, "dags", 50)]
        return {"dags": [item for item in dags if self._config.allows(str(item["dag_id"]))]}

    def list_dag_runs(self, dag_id: str, limit: int) -> Mapping[str, object]:
        self._require_allowed(dag_id, "Airflow DAG")
        _require_limit(limit, 50)
        payload = self._get(f"/api/v1/dags/{quote(dag_id, safe='')}/dagRuns", {"limit": limit})
        runs = [self._run(item) for item in _list(payload, "dag_runs", 50)]
        if any(item["dag_id"] != dag_id for item in runs):
            raise PermissionError("Airflow response DAG is not allowed")
        return {"dag_runs": runs}

    @staticmethod
    def _dag(value: Mapping[str, object]) -> dict[str, object]:
        paused = value.get("is_paused")
        if not isinstance(paused, bool):
            raise ValueError("Airflow pause state is invalid")
        return {"dag_id": _string(value, "dag_id"), "is_paused": paused}

    @staticmethod
    def _run(value: Mapping[str, object]) -> dict[str, object]:
        return {
            "dag_id": _string(value, "dag_id"), "run_id": _string(value, "dag_run_id"),
            "state": _string(value, "state"),
        }


@dataclass(frozen=True)
class IntegrationBackendConfig:
    """Aggregate validated configuration for all three production integrations."""

    confluence: IntegrationHttpConfig
    jira: IntegrationHttpConfig
    airflow: IntegrationHttpConfig

    @classmethod
    def from_env(cls, environment: Mapping[str, str] | None = None) -> IntegrationBackendConfig:
        source = os.environ if environment is None else environment
        unknown = sorted(key for key in source if key.startswith(_ENV_PREFIX) and key not in _ALL_ENV_KEYS)
        if unknown:
            raise ValueError(f"unknown integration environment variable: {unknown[0]}")
        return cls(*(IntegrationHttpConfig.from_env(name, source, validate_unknown=False)
                     for name in ("confluence", "jira", "airflow")))

    def readiness_receipt(self) -> dict[str, object]:
        """Returns a stable metadata-only receipt without endpoint or credential values."""

        configs = (self.confluence, self.jira, self.airflow)
        services = [
            {
                "id": item.service, "resources": len(item.allowed_resources), "scope_mode": item.scope_mode,
                "auth_mode": item.auth_mode, "tls": True, "read_only": True,
            }
            for item in configs
        ]
        binding = {
            "schema_version": "1.0", "services": [
                {
                    "id": item.service,
                    "endpoint_digest": "sha256:" + hashlib.sha256(item.base_url.encode("utf-8")).hexdigest(),
                    "resources_digest": "sha256:" + hashlib.sha256(
                        "\0".join(sorted(item.allowed_resources)).encode("utf-8"),
                    ).hexdigest(),
                    "scope_mode": item.scope_mode, "auth_mode": item.auth_mode,
                    "ca_digest": item.ca_digest,
                    "timeout_seconds": item.timeout_seconds, "max_response_bytes": item.max_response_bytes,
                }
                for item in configs
            ],
            "transport": "https-pinned-read-only", "redirects_allowed": False, "synthetic_fallback": False,
        }
        digest = hashlib.sha256(
            json.dumps(binding, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8"),
        ).hexdigest()
        return {
            "schema_version": "1.0", "status": "ready", "services": services,
            "transport": "https-pinned-read-only", "redirects_allowed": False,
            "synthetic_fallback": False, "credentials_exposed": False,
            "config_digest": "sha256:" + digest, "network_used": False,
        }


@dataclass(frozen=True)
class IntegrationBackendBundle:
    """Owns production backends and their existing read-only MCP adapters."""

    confluence_backend: ConfluenceHttpBackend
    jira_backend: JiraHttpBackend
    airflow_backend: AirflowHttpBackend
    confluence_adapter: ConfluenceMcpAdapter
    jira_adapter: JiraMcpAdapter
    airflow_adapter: AirflowMcpAdapter

    @classmethod
    def from_env(cls, environment: Mapping[str, str] | None = None) -> IntegrationBackendBundle:
        config = IntegrationBackendConfig.from_env(environment)
        confluence = ConfluenceHttpBackend(config.confluence)
        jira = JiraHttpBackend(config.jira)
        airflow = AirflowHttpBackend(config.airflow)
        return cls(
            confluence, jira, airflow,
            ConfluenceMcpAdapter(confluence, config.confluence.base_url, config.confluence.allowed_resources),
            JiraMcpAdapter(
                jira, config.jira.base_url, config.jira.allowed_resources,
                account_visible=config.jira.scope_mode == "account-visible-read-only",
            ),
            AirflowMcpAdapter(
                airflow, config.airflow.allowed_resources,
                account_visible=config.airflow.scope_mode == "account-visible-read-only",
            ),
        )


def _require_limit(value: int, maximum: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= maximum:
        raise ValueError("integration limit is invalid")


def _as_mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError("integration response object is invalid")
    return value


def _mapping(value: Mapping[str, object], key: str) -> Mapping[str, object]:
    return _as_mapping(value.get(key))


def _string(value: Mapping[str, object], key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str):
        raise ValueError("integration response string is invalid")
    return item


def _integer(value: Mapping[str, object], key: str, minimum: int) -> int:
    item = value.get(key)
    if not isinstance(item, int) or isinstance(item, bool) or item < minimum:
        raise ValueError("integration response integer is invalid")
    return item


def _list(value: Mapping[str, object], key: str, maximum: int) -> list[Mapping[str, object]]:
    items = value.get(key)
    if not isinstance(items, list) or len(items) > maximum:
        raise ValueError("integration response list is invalid")
    return [_as_mapping(item) for item in items]
