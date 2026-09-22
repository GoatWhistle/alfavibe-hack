# PD-Guard

Сервис идентификации, маскирования и демаскирования персональных данных (ПД) для LLM. Стоит в цепочке «система-потребитель → LLM»: маскирует ПД в запросе, сохраняет соответствие «маска → оригинал» в зашифрованном vault, демаскирует ответ LLM.

## Быстрый старт

```bash
# Секреты
export PDG_MASTER_KEY=$(openssl rand -base64 32)          # 32 байта base64
export PDG_KEY_CRM_SHA256=$(echo -n "crm-secret" | shasum -a 256 | cut -d' ' -f1)
export PDG_ADMIN_TOKEN_SHA256=$(echo -n "admin-token" | shasum -a 256 | cut -d' ' -f1)

cargo run --release
```

## Краткая инструкция по настройке

Добавьте систему в `systems`, указав её `id`, SHA-256 её ключа и профиль правил (`strict`, `cards_only` или свой из `profiles`). Набор маскируемых типов ПД и способ маскирования (`placeholder`, `partial`, `token`, `synthetic`, `redact`) задаётся в профиле, а точечные отличия — в `overrides` системы. Демаскирование включается флагом `demask: true` у системы и маршрута. Какие ручки LLM проверяются, а какие пропускаются (`bypass`) или запрещены (`block`), описывается в `routes`, включая JSON-пути полей для маскирования. Изменения применяются без перезапуска: сервис перечитывает файл автоматически, а при ошибке в конфиге продолжает работать на предыдущей версии.

## API

- `POST /process` — маскирование/демаскирование текста (заголовки `X-System-Id`, `X-System-Key`).
- `ANY /proxy/{route_path}` — прокси-режим к LLM.
- `GET /health/live`, `GET /health/ready` — проверка живости/готовности.
- `GET /metrics` (admin_listen) — метрики Prometheus.
- `POST /admin/config/reload` — горячая перезагрузка конфига.

## Пример

```bash
curl -X POST http://localhost:8080/process \
  -H "Content-Type: application/json" \
  -H "X-System-Id: crm-assistant" \
  -H "X-System-Key: crm-secret" \
  -d '{"operation":"mask","text":"Клиент Иванов Иван Иванович, паспорт 4509 123456"}'
# → {"text":"Клиент [ФИО_1], паспорт [ПАСПОРТ_1]", ...}
```

## Тесты

```bash
cargo test
cargo clippy -- -D warnings
```

## Структура

- `src/controller` — входящие HTTP-запросы (hyper, без фреймворков).
- `src/service` — бизнес-логика: детекторы, resolver, маскирование, демаскирование.
- `src/adapter` — исходящие адаптеры: vault, NER, LLM-клиент.
- `src/domain` — доменная модель и трейты.
- `src/config` — конфигурация (YAML), горячая перезагрузка.
- `config/resources` — словари (имена, города, публичные лица и т.д.).