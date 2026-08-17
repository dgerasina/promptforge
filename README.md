# PromptForge Public Starter

PromptForge is a repository-only control plane for agent engineering. It applies identity, privacy, policy, routing,
review, and evidence gates without requiring a separate database or hosted control service.

This public repository ships a sanitized starter distribution intended for teams that want to adapt the model to their
own workflows.

## Included by default

- changed-files review
- documentation sync
- optional read-only Confluence, Jira, and Airflow adapters
- local auth, audit, RC, and operational safety checks

No private state, production credentials, or proprietary content are included.

## Repository layout

- `promptforge/` — Python runtime
- `packs/public-starter/` — active generic pack
- `packs/core/` — minimal reference pack
- `schemas/` — JSON schemas for receipts and manifests
- `tests/` — offline regression suite
- `docs/` — architecture, threat model, and API reference

## Requirements

- Python 3.11+
- Git repository
- a private local state directory with `0700` permissions for execute and lifecycle flows

The base runtime has no required third-party Python dependencies.

## Quick start

From the repository root:

```bash
python3 -m promptforge setup
python3 -m promptforge start
python3 -m promptforge status
```

Stop the local runtime:

```bash
python3 -m promptforge stop
```

`setup` validates config, pack, catalog, and repository state, then prepares a private local manifest.
`start` launches one offline supervisor process.

## Preview-first usage

Preview does not need credentials and does not modify files:

```bash
python3 -m promptforge work \
  --principal-id engineer-local \
  --task-kind review.changed-files
```

Natural-language intake:

```bash
printf '%s' 'сделай ревью изменений' | python3 -m promptforge ask --principal-id engineer-local
```

## Execute changed-files review

```bash
chmod 700 /absolute/private/promptforge-state

PF_EMBEDDED_AUTH_KEY_HEX=<local-auth-key> \
PF_WORK_SESSION=<signed-session> \
PF_LOCAL_AUDIT_KEY_HEX=<local-audit-key> \
python3 -m promptforge work \
  --principal-id engineer-local \
  --task-kind review.changed-files \
  --mode execute \
  --path src/example.py \
  --deploy src/example.py \
  --state-root /absolute/private/promptforge-state
```

Review scope is always explicit. Raw diffs are not stored in durable evidence.

## Default demo identities

- `owner-local`
- `maintainer-local`
- `engineer-local`
- `analyst-local`

These defaults live in `config/local-auth.json` and `config/governance.json`. Replace them for your own team before
using the repository in a production-like environment.

## Public starter routes

- `review.changed-files`
- `documentation.sync`
- `confluence.search`
- `jira.read`
- `confluence.snapshot`

Route definitions live in `packs/public-starter/agent-catalog.yaml`.

## Optional external adapters

The starter pack can use read-only Confluence, Jira, and Airflow adapters through explicit `PF_INTEGRATION_*`
variables or a local state profile. Credentials must stay outside Git.

## Tests

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
```

## Packaging

```bash
pip install -e .
```

## Customizing for your team

1. Copy `packs/public-starter/` or `packs/core/`.
2. Define your own `agent-catalog.yaml` and `task-intents.json`.
3. Point `project-profile.yaml` at the new pack.
4. Replace demo identities in `config/local-auth.json` and `config/governance.json`.
5. Re-run the test suite.

## License

Apache-2.0. See [LICENSE](LICENSE).
