# PromptForge: публичная стартовая версия

PromptForge — работающий исключительно внутри репозитория центр управления агентской разработкой. Он применяет
проверки идентификации, приватности, политик, маршрутизации, ревью и доказательств выполнения без отдельной базы данных
или облачного управляющего сервиса.

Этот публичный репозиторий содержит обезличенную стартовую поставку, которую команды могут адаптировать под свои
процессы.

## Что доступно по умолчанию

- ревью изменённых файлов;
- синхронизация документации;
- необязательные read-only адаптеры Confluence, Jira и Airflow;
- локальная аутентификация, аудит, проверка release candidate и эксплуатационной безопасности.

Приватное состояние, production credentials и закрытые материалы в поставку не входят.

## Структура репозитория

- `promptforge/` — Python runtime;
- `packs/public-starter/` — активный универсальный pack;
- `packs/core/` — минимальный эталонный pack;
- `schemas/` — JSON schemas для receipts и manifests;
- `tests/` — автономный набор регрессионных тестов;
- `docs/` — архитектура, модель угроз и справочник API.

## Требования

- Python 3.11 или новее;
- Git-репозиторий;
- приватный локальный каталог с правами `0700` для выполнения задач и lifecycle-сценариев.

Базовый runtime не требует сторонних Python-зависимостей.

## Быстрый старт

Из корня репозитория выполните:

```bash
python3 -m promptforge setup
python3 -m promptforge start
python3 -m promptforge status
```

Чтобы остановить локальный runtime:

```bash
python3 -m promptforge stop
```

`setup` проверяет конфигурацию, pack, каталог и состояние репозитория, затем создаёт приватный локальный manifest.
`start` запускает один автономный supervisor process.

## Сначала предварительный просмотр

Предварительный просмотр не требует credentials и не изменяет файлы:

```bash
python3 -m promptforge work \
  --principal-id engineer-local \
  --task-kind review.changed-files
```

Ввод задачи на естественном языке:

```bash
printf '%s' 'сделай ревью изменений' | python3 -m promptforge ask --principal-id engineer-local
```

## Выполнение ревью изменённых файлов

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

Область ревью всегда задаётся явно. Исходные diff не сохраняются в долговременных evidence.

## Демонстрационные пользователи

- `owner-local`;
- `maintainer-local`;
- `engineer-local`;
- `analyst-local`.

Они описаны в `config/local-auth.json` и `config/governance.json`. Перед использованием в среде, близкой к
production, замените их пользователями своей команды.

## Маршруты стартовой версии

- `review.changed-files`;
- `documentation.sync`;
- `confluence.search`;
- `jira.read`;
- `confluence.snapshot`.

Маршруты определены в `packs/public-starter/agent-catalog.yaml`.

## Необязательные внешние адаптеры

Стартовый pack может использовать read-only адаптеры Confluence, Jira и Airflow через явные переменные
`PF_INTEGRATION_*` или локальный профиль состояния. Credentials должны храниться вне Git.

## Тестирование

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
```

## Установка как пакета

```bash
pip install -e .
```

## Адаптация для своей команды

1. Скопируйте `packs/public-starter/` или `packs/core/`.
2. Опишите свои `agent-catalog.yaml` и `task-intents.json`.
3. Укажите новый pack в `project-profile.yaml`.
4. Замените демонстрационных пользователей в `config/local-auth.json` и `config/governance.json`.
5. Повторно запустите тесты.

## Лицензия

Проект распространяется по Apache License 2.0. Полный текст находится в [LICENSE](LICENSE).
