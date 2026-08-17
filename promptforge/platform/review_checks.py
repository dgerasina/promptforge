"""Embedded deterministic review checks shipped with the production runtime."""

from __future__ import annotations

from promptforge.platform.review import ChangedFile, diff_digest, is_non_prod_deploy_artifact
from promptforge.platform.security import inspect_text


def run_review_check(check_id: str) -> bool:
    """Executes a bounded self-check without importing repository test code."""

    if check_id == "behavior":
        unsafe = ChangedFile("src/example.py", "+unsafe_value = 'sk-" + "synthetic-marker-value'", True)
        non_prod = ChangedFile("etl/dags/calc_1_test.py", "+target = 'sandbox_example.demo'", True)
        clean = ChangedFile("src/example.py", "+VALUE = 1", True)
        return bool(
            inspect_text(unsafe.diff).outcome == "deny"
            and is_non_prod_deploy_artifact(non_prod)
            and not is_non_prod_deploy_artifact(clean)
        )
    if check_id == "contracts":
        changed = ChangedFile("src/example.py", "+VALUE = 1", True)
        digest = diff_digest((changed,))
        try:
            ChangedFile("../escape.py", "+VALUE = 1", True)
        except ValueError:
            return digest.startswith("sha256:") and len(digest) == 71
        return False
    raise ValueError("unknown embedded review check")
