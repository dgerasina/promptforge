# Готовность к промышленной эксплуатации

Версия документа: `production-readiness-v1`

## Входные критерии

- `check`, `production-docs-check` и полный набор тестов завершаются успешно;
- exact production files просмотрены, а credentials, state и временные артефакты исключены;
- governance administrators подтвердили политики, модель угроз и остаточные риски;
- runtime state расположен в локальном owner-private каталоге;
- private keys и sessions поступают только извне Git;
- выполнение начинается с preview, а mutations требуют подписанной сессии и явного подтверждения.

## Свидетельства проверок

Сохраняйте только metadata-only stdout и связывайте его с точным source digest. Не сохраняйте environment, исходные
запросы и ответы, mappings или значения сессий. После изменения кода, конфигурации или документации проверки нужно
повторить.

Обязательная последовательность:

```bash
python3 -m promptforge check
python3 -m promptforge production-docs-check
python3 -m promptforge neutrality-check
python3 -m unittest discover -s tests -p 'test_*.py'
```

## Процедура выпуска

1. Проверьте deploy list и отсутствие local state, SQLite sidecars, keys, sessions и generated evidence.
2. Сверьте `project-profile.yaml`, выбранный pack, governance bindings и версии каталогов.
3. Запустите проверки на чистом checkout точной revision.
4. Начинайте с preview/read-only workflow; write и rehydration разрешайте отдельными approvals.
5. Наблюдайте только metadata-only audit outcomes, denials, latency, token receipts и review status.

## Откат

При regression включите kill switch, остановите новые executions, сохраните metadata evidence и верните предыдущую
проверенную Git revision вместе с совместимой конфигурацией. Не удаляйте audit/provenance. Перед возобновлением работы
повторите проверки документации, безопасности и E2E.

## Инцидент

При подозрении на утечку или повышение привилегий включите kill switch, отзовите session epoch, ротируйте runtime keys,
запретите rehydration и MCP writes, сохраните audit/provenance digests и проверьте repository/config drift. Не копируйте
чувствительное содержимое запросов в incident artifacts.

## Выходные критерии

- откат проверен и документирован;
- руководство доступно без внешнего сервиса;
- известные ограничения совпадают с моделью угроз;
- нет незакрытых critical/high security findings;
- deploy и do-not-deploy списки подтверждены вручную.
