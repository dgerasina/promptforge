"""Fail-closed gate для versioned production documentation."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from types import MappingProxyType
from typing import Mapping

from promptforge.platform.security import inspect_text


_MANIFEST_FIELDS = frozenset({"schema_version", "manifest_version", "threat_model_version", "documents"})
_DOCUMENT_FIELDS = frozenset({"id", "path", "version", "required_sections"})
_SAFE_ID = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_SAFE_VERSION = re.compile(r"^[a-z][a-z0-9-]{0,63}-v[1-9][0-9]*$")
_SAFE_PATH = re.compile(r"^[A-Za-z0-9._/-]{1,256}$")
_REQUIRED_DOCUMENTS = MappingProxyType({
    "architecture": "docs/architecture.md",
    "threat-model": "docs/security/threat-model.md",
    "production-readiness": "docs/runbooks/production-readiness.md",
})


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("production docs manifest contains duplicate fields")
        result[key] = value
    return result


@dataclass(frozen=True)
class ProductionDocument:
    id: str
    path: str
    version: str
    required_sections: tuple[str, ...]

    @classmethod
    def from_payload(cls, payload: object) -> ProductionDocument:
        if not isinstance(payload, dict) or set(payload) != _DOCUMENT_FIELDS:
            raise ValueError("production document contract is invalid")
        identifier, path, version = payload["id"], payload["path"], payload["version"]
        sections = payload["required_sections"]
        if not isinstance(identifier, str) or not _SAFE_ID.fullmatch(identifier):
            raise ValueError("production document id is invalid")
        if (
            not isinstance(path, str)
            or not _SAFE_PATH.fullmatch(path)
            or path.startswith(("/", "../"))
            or "/../" in path
        ):
            raise ValueError("production document path is unsafe")
        if not isinstance(version, str) or not _SAFE_VERSION.fullmatch(version):
            raise ValueError("production document version is invalid")
        if (
            not isinstance(sections, list)
            or not sections
            or len(sections) != len(set(sections))
            or any(not isinstance(item, str) or not 2 <= len(item) <= 64 for item in sections)
        ):
            raise ValueError("production document sections are invalid")
        return cls(identifier, path, version, tuple(sections))


@dataclass(frozen=True)
class ProductionDocumentationReport:
    status: str
    threat_model_version: str
    documents: int
    passed_documents: int
    documents_digest: str

    def to_payload(self) -> dict[str, object]:
        return {
            "schema_version": "1.0",
            "status": self.status,
            "threat_model_version": self.threat_model_version,
            "documents": self.documents,
            "passed_documents": self.passed_documents,
            "documents_digest": self.documents_digest,
            "network_used": False,
        }


@dataclass(frozen=True)
class ProductionDocumentationGate:
    repository: Path
    manifest_version: str
    threat_model_version: str
    documents: tuple[ProductionDocument, ...]

    @classmethod
    def from_repository(cls, repository: Path) -> ProductionDocumentationGate:
        root = Path(repository).resolve(strict=True)
        manifest_path = root / "config" / "production-docs.json"
        if manifest_path.is_symlink() or not manifest_path.is_file() or manifest_path.resolve() != manifest_path:
            raise ValueError("production docs manifest must be a regular repository file")
        try:
            payload = json.loads(manifest_path.read_text(encoding="utf-8"), object_pairs_hook=_strict_object)
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise ValueError("production docs manifest is invalid") from error
        return cls.from_payload(root, payload)

    @classmethod
    def from_payload(cls, repository: Path, payload: object) -> ProductionDocumentationGate:
        root = Path(repository).resolve(strict=True)
        if not root.is_dir() or root.is_symlink():
            raise ValueError("production docs repository is invalid")
        if not isinstance(payload, dict) or set(payload) != _MANIFEST_FIELDS or payload.get("schema_version") != "1.0":
            raise ValueError("production docs manifest contract is invalid")
        manifest_version, threat_version, raw_documents = (
            payload["manifest_version"], payload["threat_model_version"], payload["documents"]
        )
        if manifest_version != "production-docs-v1" or threat_version != "threat-model-v1":
            raise ValueError("production docs version is unsupported")
        if not isinstance(raw_documents, list) or not raw_documents:
            raise ValueError("production docs list is invalid")
        documents = tuple(ProductionDocument.from_payload(item) for item in raw_documents)
        if len({item.id for item in documents}) != len(documents) or len({item.path for item in documents}) != len(documents):
            raise ValueError("production docs entries are duplicated")
        actual_documents = {item.id: item.path for item in documents}
        if actual_documents != dict(_REQUIRED_DOCUMENTS):
            raise ValueError("production docs required set is invalid")
        if next((item.version for item in documents if item.id == "threat-model"), None) != threat_version:
            raise ValueError("threat model version is inconsistent")
        return cls(root, manifest_version, threat_version, documents)

    def inspect(self) -> ProductionDocumentationReport:
        evidence: list[Mapping[str, object]] = []
        passed = 0
        for document in self.documents:
            valid, digest = self._inspect_document(document)
            passed += int(valid)
            evidence.append(MappingProxyType({"id": document.id, "version": document.version, "digest": digest}))
        canonical = json.dumps([dict(item) for item in evidence], sort_keys=True, separators=(",", ":")).encode()
        digest = "sha256:" + hashlib.sha256(canonical).hexdigest()
        return ProductionDocumentationReport(
            "passed" if passed == len(self.documents) else "blocked",
            self.threat_model_version,
            len(self.documents),
            passed,
            digest,
        )

    def _inspect_document(self, document: ProductionDocument) -> tuple[bool, str]:
        path = self.repository / document.path
        try:
            resolved = path.resolve(strict=True)
            if path.is_symlink() or not path.is_file() or not resolved.is_relative_to(self.repository):
                return False, "sha256:" + "0" * 64
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            return False, "sha256:" + "0" * 64
        normalized = content.casefold()
        required = all(section.casefold() in normalized for section in document.required_sections)
        version_present = document.version.casefold() in normalized
        digest = "sha256:" + hashlib.sha256(content.encode("utf-8")).hexdigest()
        safe_content = inspect_text(content).outcome == "allow"
        return required and version_present and safe_content, digest
