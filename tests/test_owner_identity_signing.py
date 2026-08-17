from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from promptforge.platform.git_identity import GitIdentityResolver
from promptforge.platform.release_signing import (
    generate_owner_keypair,
    load_json_object,
    sign_release_candidate,
    verify_release_candidate,
)
from promptforge.platform.skill_signatures import SkillSigningKeyRegistry


PRODUCT = Path(__file__).resolve().parents[1]


class OwnerIdentitySigningTest(unittest.TestCase):
    def test_git_identity_is_convenience_claim_not_privileged_authentication(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            subprocess.run(["git", "init", "-q", str(repository)], check=True)
            subprocess.run(["git", "config", "user.name", "owner-local"], cwd=repository, check=True)
            result = GitIdentityResolver(repository, PRODUCT / "config" / "local-auth.json").resolve()

        self.assertEqual("owner-local", result.principal_id)
        self.assertEqual("owner", result.role)
        self.assertEqual("recognized", result.status)
        self.assertEqual("untrusted_git_claim", result.assurance)
        self.assertFalse(result.privileged)

    def test_unknown_git_identity_is_denied_without_leaking_email(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            subprocess.run(["git", "init", "-q", str(repository)], check=True)
            subprocess.run(["git", "config", "user.name", "unknown-user"], cwd=repository, check=True)
            subprocess.run(["git", "config", "user.email", "private@example.test"], cwd=repository, check=True)
            result = GitIdentityResolver(repository, PRODUCT / "config" / "local-auth.json").resolve()

        self.assertEqual("denied", result.status)
        self.assertEqual("", result.principal_id)
        self.assertNotIn("email", json.dumps(result.to_payload()))

    @unittest.skipUnless(shutil.which("openssl"), "openssl is required")
    def test_owner_can_sign_and_offline_verify_exact_accepted_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            private_key, public_key = root / "owner.key.pem", root / "owner.pub.pem"
            generate_owner_keypair(private_key, public_key)
            registry_path = root / "keys.json"
            registry_path.write_text(json.dumps({
                "schema_version": "1.0",
                "keys": [{
                    "key_id": "owner-local-1", "signer_id": "owner-local", "status": "active",
                    "public_key": public_key.name,
                }],
            }))
            registry = SkillSigningKeyRegistry.from_file(registry_path)
            manifest = self._manifest()
            signature = sign_release_candidate(
                manifest, "owner-local", "owner-local-1", private_key, registry, issued_at=100, expires_at=200,
            )

            self.assertTrue(verify_release_candidate(manifest, signature, registry, at_time=150))
            self.assertFalse(verify_release_candidate({**manifest, "agents": 17}, signature, registry, at_time=150))
            self.assertFalse(verify_release_candidate(manifest, signature, registry, at_time=201))

    @unittest.skipUnless(shutil.which("openssl"), "openssl is required")
    def test_signing_rejects_non_owner_and_blocked_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            private_key, public_key = root / "owner.key.pem", root / "owner.pub.pem"
            generate_owner_keypair(private_key, public_key)
            registry_path = root / "keys.json"
            registry_path.write_text(json.dumps({
                "schema_version": "1.0",
                "keys": [{
                    "key_id": "manager-local-1", "signer_id": "maintainer-local", "status": "active",
                    "public_key": public_key.name,
                }],
            }))
            registry = SkillSigningKeyRegistry.from_file(registry_path)
            with self.assertRaises(PermissionError):
                sign_release_candidate(
                    self._manifest(), "maintainer-local", "manager-local-1", private_key, registry,
                    issued_at=100, expires_at=200,
                )
            with self.assertRaises(ValueError):
                sign_release_candidate(
                    {**self._manifest(), "status": "blocked"}, "owner-local", "manager-local-1", private_key,
                    registry, issued_at=100, expires_at=200,
                )

    @unittest.skipUnless(shutil.which("openssl"), "openssl is required")
    def test_signing_rejects_private_key_not_matching_registered_public_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            registered_private, registered_public = root / "registered.key.pem", root / "registered.pub.pem"
            other_private, other_public = root / "other.key.pem", root / "other.pub.pem"
            generate_owner_keypair(registered_private, registered_public)
            generate_owner_keypair(other_private, other_public)
            registry_path = root / "keys.json"
            registry_path.write_text(json.dumps({
                "schema_version": "1.0",
                "keys": [{
                    "key_id": "owner-local-1", "signer_id": "owner-local", "status": "active",
                    "public_key": registered_public.name,
                }],
            }))
            registry = SkillSigningKeyRegistry.from_file(registry_path)

            with self.assertRaises(PermissionError):
                sign_release_candidate(
                    self._manifest(), "owner-local", "owner-local-1", other_private, registry,
                    issued_at=100, expires_at=200,
                )

    @unittest.skipUnless(shutil.which("openssl"), "openssl is required")
    def test_key_generation_rejects_symlinked_parent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            private_directory = root / "private"
            private_directory.mkdir(mode=0o700)
            alias = root / "alias"
            alias.symlink_to(private_directory, target_is_directory=True)

            with self.assertRaises(ValueError):
                generate_owner_keypair(alias / "owner.key.pem", alias / "owner.pub.pem")
            self.assertFalse((private_directory / "owner.key.pem").exists())
            manifest = private_directory / "manifest.json"
            manifest.write_text("{}")
            with self.assertRaises(ValueError):
                load_json_object(alias / "manifest.json")
    @staticmethod
    def _manifest() -> dict[str, object]:
        unsigned = {
            "schema_version": "1.0", "status": "accepted", "reason_codes": [],
            "source_digest": "sha256:" + "1" * 64, "release_scope": {}, "gates": {}, "skills": {},
            "agents": 16, "final_evidence_status": "passed", "assurance_scope": "repository_single_host_mvp",
            "known_limitations": [], "network_used": False,
            "gate_config_digest": "sha256:" + "3" * 64, "portability_digest": "sha256:" + "4" * 64,
            "product_version": "1.0.0", "spec_version": "platform-v1", "evidence": {},
        }
        digest = hashlib.sha256(json.dumps(
            unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        ).encode()).hexdigest()
        return {**unsigned, "release_digest": "sha256:" + digest}


if __name__ == "__main__":
    unittest.main()
