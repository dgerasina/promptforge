# Production-архитектура

Версия документа: `architecture-v1`

PromptForge — переносимый repository-only control и execution layer для детерминированной агентской разработки. Код,
политики, schemas, packs, skills и эксплуатационная документация поставляются одной папкой; отдельная БД, gateway или
новый инфраструктурный сервис не требуются.

## Компоненты

- project profile выбирает pack, integrations, agent catalog и repository-index policy;
- authentication и governance связывают session, exact identity, role, project и administrative capability;
- Git identity используется только как локальный convenience claim; privileged authority из неё не выводится;
- Policy Engine и Privacy Pipeline принимают решение до model/tool boundary;
- Model Gateway и MCP Hub предоставляют provider-neutral и capability-scoped execution;
- production Confluence/Jira/Airflow reads собираются одной factory из injected `PF_INTEGRATION_*` configuration;
- HTTPS transport закрепляет exact host/base path, запрещает redirects и ограничивает response до JSON parse;
- deterministic task router выбирает versioned agent и approved skills только по exact task kind;
- approved skill distribution проверяет detached Ed25519 provenance по repository public-key registry;
- externally provisioned inference runtime допускается только после exact executable/artifact preflight и admission;
- review, documentation automation, token runtime и evidence runner создают проверяемые receipts;
- targeted review closure переоценивает prior findings и сравнивает HMAC-tokenized worktree baseline без хранения paths;
- owner-private local state хранит audit, grants, provenance и ephemeral cache без raw prompts или diffs.

## Границы доверия

`platform/secure_filesystem.py` — единый OS security boundary для private directories/files. POSIX backend проверяет
owner UID и exact modes; native Windows backend применяет и повторно читает protected NTFS ACL для current SID и
`SYSTEM`, отклоняет inheritance, дополнительные principals и reparse path. Integration credentials, CA/session files,
secure runtime state и workspace lifecycle используют этот общий контракт.

1. CLI/process boundary: аргументы недоверенные; secrets и sessions допускаются только через environment.
2. Repository/config boundary: manifest считается доверенным только после closed-schema, path и integrity checks.
3. Identity boundary: caller-controlled principal не является аутентификацией; execute требует signed session.
4. Privacy boundary: внешний model/tool adapter недоступен до classification, policy и placeholdering.
5. Adapter boundary: provider identity, endpoint, response size и usage подтверждаются trusted adapter receipt.
6. State boundary: SQLite и mapping state разрешены только в owner-private локальном каталоге.
7. Documentation boundary: generated content не изменяет human-owned области и требует governance approval для sync.
8. External-document boundary: authenticated read создаёт owner-private attested snapshot; отдельный offline mutation
   принимает его как untrusted inert data, проверяет digest/HMAC/TTL/principal/source и запрещает replay.
9. Review-closure boundary: повторный review связан с parent receipt и допускает изменения только exact targeted paths;
   любой out-of-scope drift требует нового полного review.

## Поток данных

`identity → policy → privacy → token plan → model/tool adapter → review → audit/evidence`.

На каждом переходе передаются минимальные versioned metadata и digests. Raw content живёт только в памяти текущего
workflow; исключение — TTL-bounded external-document snapshot в owner-private state до одноразового применения. Stdout,
audit, usage receipts, repository index и durable review provenance остаются metadata-only.
Rehydration выполняется лишь по одноразовому scoped grant после возврата результата в доверенный контур.

## Развёртывание и состояние

Production bundle включает Python package, schemas, config, selected pack, skills и docs. Runtime keys и signed sessions
инжектируются извне Git. Локальный state создаётся с режимом `0700`, файлы — `0600`; network filesystem запрещён.
Kill switch блокирует adapters, а cleanup не удаляет audit или неизвестные файлы.
Audit writers используют bounded SQLite busy timeout 30 секунд, чтобы сериализованный append не давал ложные failures
на заявленном concurrent load profile; истечение timeout остаётся fail closed.

## Переносимость

Для другого репозитория меняются `project-profile.yaml` и project pack. Core, wire contracts и gates не должны содержать
проектных путей или vendor-specific названий. Все обязательные проверки запускаются стандартной библиотекой Python без
добавления внешних сервисов.
