# Threat model

Document version: `threat-model-v1`

Scope: repository-only single-host runtime, его конфигурация, локальное state и разрешённые corporate integrations.
Метод: структурированный анализ assets, actors, trust boundaries, attack surfaces и abuse cases. Модель пересматривается
при изменении authentication, egress, adapters, rehydration, persistent state или administrative capabilities.

## Assets

- исходный код, repository metadata, инженерные документы и результаты tools;
- secrets, signed sessions, audit keys и rehydration mappings;
- policy, governance, role registry, project profile, agent/skill catalogs и approvals;
- model/tool requests, transformed context, responses, token receipts и review evidence;
- integrity локального audit, provenance, repository index и production documentation.

## Actors

- `owner-local` и `maintainer-local`: exact administrative identities;
- engineer и analyst: рабочие роли с различными agent/skill catalogs;
- generic maintainer: рабочая роль без administrative capabilities;
- локальный runtime process и trusted adapters;
- злоумышленник с доступом к CLI, dirty worktree, environment, локальному state либо ответу внешнего endpoint.

## Trust boundaries

- user input → CLI/contracts;
- CLI identity claim → signed authentication session;
- tracked repository → validated config/profile/catalog;
- raw corporate content → privacy and policy decision;
- approved context → model/MCP adapter;
- adapter response → size, identity, review and rehydration checks;
- process memory → owner-private durable state;
- generated docs → human-owned documentation and governance sync.

## Attack surfaces

- path traversal, symlink swap, oversized files/diffs и malicious repository content;
- principal/role spoofing, session tampering/replay и generic-role privilege escalation;
- prompt injection через code, documentation, mail или tool results;
- secret/PII exfiltration, placeholder collision и unauthorized rehydration;
- unapproved provider/endpoint, redirect/proxy abuse и oversized response;
- MCP capability escalation, write without exact approval и malicious tool output;
- audit/provenance tampering, state replacement, rollback и cleanup misuse;
- skill/catalog/config drift, ambiguous routing и poisoned repository index;
- token-budget manipulation, mandatory-context removal и forged usage receipts;
- documentation overwrite, stale source binding и leakage in generated artifacts.

## Abuse cases and controls

| Abuse case | Preventive/detective controls | Verification |
|---|---|---|
| Caller подменяет identity | Signed session, registry lookup on every request, exact identity/role/project match | auth and unified-work tests |
| Caller меняет локальный `git user.name` | Git identity маркируется `untrusted_git_claim`, `privileged=false`; admin actions требуют signed session/owner signature | identity/signing tests |
| RC manifest изменён или подписан не owner | Ed25519 signature полного canonical manifest, active key registry, owner-only signer и 14-day expiry | release signing tests |
| Generic maintainer получает admin | Identity-bound governance allowlist; role alone insufficient | governance security probe |
| Secret отправляется adapter | secret deny, classification escalation, policy before adapter | privacy and final evidence |
| PII выходит без защиты | scoped deterministic placeholders; rehydration only with one-time grant | privacy tests |
| Tool выполняет лишнее действие | exact MCP capabilities, deny by default, write approval binding | MCP Hub tests |
| SSRF/redirect через integration URL | env-only canonical HTTPS, exact host/path pinning, redirect deny | backend tests |
| Утечка integration credentials | secrets вне Git, redacted repr/errors, metadata-only audit | backend tests |
| SSO cookie подменён symlink или доступен группе | no-follow descriptor open, owner UID, regular file, exact `0600`, bounded single header value | backend tests |
| Local integration profile раскрыт или подменён | owner-only `0700/0600`, closed fields, no-follow reads, create-only setup, ephemeral work session | setup tests |
| Trusted CA заменён или TLS отключён | owner-owned bounded non-symlink CA, digest binding, verified SSL context; insecure mode отсутствует | backend/setup tests |
| Account-visible scope превращён в wildcard | literal mode только для Jira/Airflow reads, empty allowlist, identifier validation и server-side authz | backend/adapter tests |
| Prompt injection из wiki/issue | `untrusted_external_data`, read-only capability, запрет tool escalation | integration tests |
| Подмена repository file между generation/apply/rollback | expected SHA-256, descriptor CAS, no-follow open, post-apply CAS rollback | mutation tests |
| Произвольная перезапись документации | configured document id, exact governance identities, generated markers, CAS/review/provenance | documentation executor tests |
| Wiki-текст повторно применён или исполняется как инструкция | HMAC/digest/TTL/principal/source binding, inert escaping, one-time reservation/consumption, separate read/write tasks | documentation snapshot tests |
| Неверный endpoint выдаёт себя за model | allowlisted endpoint and confirmed provider/model identity; bounded response | admission/gateway tests |
| Локальный binary/weights подменены | no-follow regular files, safe modes, SHA-256+inode before/after, fixed argv/env and exact response identity | provisioned inference tests |
| Repository input меняет routing | closed profile/catalog, immutable versions, exact task kind, integrity checks | router tests |
| Подменён approved skill или approval registry | package/release digests плюс detached Ed25519 signature, signer/key allowlist и revocation | skill signature tests |
| Prompt injection требует bypass | model output не является authority; policy, tool permissions and deterministic review remain external | E2E gate |
| State изменён или заменён | owner-only modes, HMAC chain, inode/schema checks, replay denial | audit/provenance tests |
| Concurrent audit writers создают lock starvation | serialized transaction, bounded 30-second busy timeout, zero-failure load gate | final evidence |
| Token optimization удаляет policy context | mandatory context, explicit overflow, attested usage settlement | token runtime tests |
| Generated docs перезаписывают ручной текст | bounded markers, source digest, classification and governance gate | docs automation tests |
| Targeted re-review скрывает параллельные изменения | attested full-worktree baseline, HMAC path tokens, exact parent/principal/project binding, one-time context | review closure tests |
| Release содержит credential или запрещённый product marker | bounded repository text scan, neutrality fingerprints, tracked allowlist and prohibited artifact gate | release candidate gate |
| Копия продукта зависит от исходного monorepo | clean-copy CLI import/check и portable core profile/route | portability gate |

`work --mode execute` разрешён только при signed session и bounded routed task. Documentation mutation доступна только
через `documentation.sync` либо offline `documentation.from-snapshot` с exact governance identity; legacy `docs-sync`
отключена fail closed. `confluence.snapshot` является отдельным read-only task и не пишет в repository.

## Security invariants

- unknown identity, action, task, capability, classification or contract version fails closed;
- raw prompts, responses, diffs, mappings, credentials and sessions are absent from durable evidence;
- no external call occurs before authentication, policy, privacy and budget decisions;
- administrative actions доступны только exact `owner-local`/`maintainer-local` bindings;
- preview has no effects; execute requires signed identity and explicit bounded scope;
- security PASS невозможен при failed probe, E2E failure, invalid audit or exceeded load threshold.
- release acceptance невозможен при unknown required gate, config/source drift, failed portability или secret scan.

## Residual risks

Native Windows private state использует protected DACL `current SID + SYSTEM`, exact owner SID и запрет reparse/junction
components через bundled PowerShell security helper. Path передаётся helper через process environment, не argv.
Workspace singleton использует Windows byte-range lock; POSIX сохраняет `flock` и `0700/0600`. Реальный Windows host
acceptance остаётся обязательным: mocked ACL tests на другой ОС не доказывают поведение конкретного NTFS, domain policy
или endpoint protection.

- локальный владелец host может согласованно откатить audit/state вместе со всеми локальными anchors;
- identity локального model process и exact weights не подтверждаются криптографически;
- compromise процесса после получения secrets раскрывает его memory; требуются host hardening и process isolation;
- внешняя корпоративная система остаётся отдельной trust domain и должна ограничивать service identity с её стороны;
- deterministic gates снижают, но не устраняют semantic prompt injection и ошибочные non-blocking model findings;
- single-host runtime не предоставляет HA, независимый immutable audit anchor или multi-host consistency.
- multi-file repository mutation имеет fsynced owner-private recovery journal, CAS rollback/recovery и блокирует новые
  mutations при незавершённой транзакции; это crash-recoverable single-host boundary, но не ACID multi-host transaction.

Эти риски нельзя скрывать за статусом PASS. Изменение их acceptance требует отдельного governance решения и новой версии
threat model.
