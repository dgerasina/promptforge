from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile
import unittest

from promptforge.platform.release_candidate import MergeRequestScopeChecker


class MergeRequestScopeCheckerTest(unittest.TestCase):
    def test_passes_when_commit_range_touches_only_product_scope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = self._init_repository(Path(directory).resolve())
            base_ref = self._commit(repository, {
                "promptforge/README.md": "base\n",
                "promptforge/tests/test_release.py": "base\n",
                "outside.txt": "base\n",
            })
            self._write(repository, "promptforge/README.md", "changed\n")
            self._write(repository, "promptforge/tests/test_release.py", "changed\n")
            subprocess.run(["git", "add", "."], cwd=repository, check=True)
            subprocess.run(["git", "commit", "-qm", "product-only"], cwd=repository, check=True)

            report = MergeRequestScopeChecker(repository / "promptforge", base_ref).run()

        self.assertEqual("passed", report.status)
        self.assertEqual((), report.reason_codes)
        self.assertEqual(("promptforge/README.md", "promptforge/tests/test_release.py"), report.changed_files)
        self.assertEqual(("promptforge/README.md",), report.deploy_allowlist)
        self.assertEqual(("promptforge/tests/test_release.py",), report.do_not_deploy)

    def test_blocks_when_commit_range_contains_non_product_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = self._init_repository(Path(directory).resolve())
            base_ref = self._commit(repository, {
                "promptforge/README.md": "base\n",
                "outside.txt": "base\n",
            })
            self._write(repository, "promptforge/README.md", "changed\n")
            self._write(repository, "outside.txt", "changed\n")
            subprocess.run(["git", "add", "."], cwd=repository, check=True)
            subprocess.run(["git", "commit", "-qm", "mixed-scope"], cwd=repository, check=True)

            report = MergeRequestScopeChecker(repository / "promptforge", base_ref).run()

        self.assertEqual("blocked", report.status)
        self.assertIn("mr_scope_outside_product", report.reason_codes)
        self.assertEqual(("outside.txt",), report.outside_scope_files)
        self.assertEqual(("promptforge/README.md",), report.deploy_allowlist)

    @staticmethod
    def _init_repository(path: Path) -> Path:
        subprocess.run(["git", "init", "-q", str(path)], check=True)
        subprocess.run(["git", "config", "user.name", "PromptForge Tester"], cwd=path, check=True)
        subprocess.run(["git", "config", "user.email", "tester@example.test"], cwd=path, check=True)
        return path

    @staticmethod
    def _write(repository: Path, relative: str, content: str) -> None:
        target = repository / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    def _commit(self, repository: Path, files: dict[str, str]) -> str:
        for relative, content in files.items():
            self._write(repository, relative, content)
        subprocess.run(["git", "add", "."], cwd=repository, check=True)
        subprocess.run(["git", "commit", "-qm", "base"], cwd=repository, check=True)
        return subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=repository, check=True, capture_output=True, text=True,
        ).stdout.strip()


if __name__ == "__main__":
    unittest.main()
