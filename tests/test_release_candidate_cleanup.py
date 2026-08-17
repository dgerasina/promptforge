from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from promptforge.platform.release_candidate import prune_auto_ignored_release_artifacts


class ReleaseCandidateCleanupTest(unittest.TestCase):
    def test_prunes_auto_ignored_artifacts_and_empty_pycache_dirs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            pycache = root / "pkg" / "__pycache__"
            pycache.mkdir(parents=True)
            (pycache / "module.cpython-314.pyc").write_bytes(b"compiled")
            (root / "pkg" / "module.pyo").write_bytes(b"optimized")
            (root / ".DS_Store").write_bytes(b"finder")
            (root / "keep.txt").write_text("keep", encoding="utf-8")

            removed = prune_auto_ignored_release_artifacts(root)

            self.assertEqual(4, removed)
            self.assertFalse((pycache / "module.cpython-314.pyc").exists())
            self.assertFalse((root / "pkg" / "module.pyo").exists())
            self.assertFalse((root / ".DS_Store").exists())
            self.assertFalse(pycache.exists())
            self.assertTrue((root / "keep.txt").exists())


if __name__ == "__main__":
    unittest.main()
