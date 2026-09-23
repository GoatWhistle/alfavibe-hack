#!/usr/bin/env bash
# Нагрузочный прогон pd-guard по методике Приложения B ТЗ.
#
#   tools/loadgen/run.sh [профиль ...]
#
# Профили: smoke | target | stress | ceiling | large | ratelimit | all (по умолчанию: smoke target)
# Поднимает сервис на config/loadtest.yaml, гоняет loadgen, складывает отчёты
# в target/loadtest/. Внешний сервис: URL=http://host:port tools/loadgen/run.sh …
set -euo pipefail

cd "$(dirname "$0")/../.."
OUT=target/loadtest
mkdir -p "$OUT"

PROFILES=("$@")
if [ ${#PROFILES[@]} -eq 0 ]; then PROFILES=(smoke target); fi
if [ "${PROFILES[0]}" = "all" ]; then PROFILES=(smoke target stress ceiling large ratelimit); fi

URL="${URL:-}"
SYSTEM_ID="${SYSTEM_ID:-crm-assistant}"
SYSTEM_KEY="${SYSTEM_KEY:-loadtest-key}"
MODE="${MODE:-native}"

# SKIP_BUILD=1 — не пересобирать (release-сборка с fat LTO занимает минуты).
if [ "${SKIP_BUILD:-0}" != "1" ]; then
  echo "▶ Сборка release…"
  cargo build --release --bin pd-guard --bin loadgen
fi

SERVER_PID=""
# SIGTERM сервис логирует, но процесс не завершает, поэтому добиваем принудительно.
cleanup() {
  if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    for _ in $(seq 1 20); do
      kill -0 "$SERVER_PID" 2>/dev/null || return 0
      sleep 0.25
    done
    kill -9 "$SERVER_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

# Свой сервис поднимаем сами; внешний (URL задан извне) — трогаем только клиентом.
if [ -z "$URL" ]; then
  URL="http://127.0.0.1:8080"
  export PDG_CONFIG=config/loadtest.yaml
  export PDG_MASTER_KEY="$(head -c 32 /dev/urandom | base64)"
  export PDG_KEY_CRM_SHA256="$(printf '%s' "$SYSTEM_KEY" | shasum -a 256 | cut -d' ' -f1)"
  export PDG_KEY_PAY_SHA256="$PDG_KEY_CRM_SHA256"
  export PDG_KEY_ANALYTICS_SHA256="$PDG_KEY_CRM_SHA256"
  export PDG_ADMIN_TOKEN_SHA256="$(printf 'admin' | shasum -a 256 | cut -d' ' -f1)"
  export PDG_LLM_TOKEN="unused"
  export PDG_REDIS_URL="redis://127.0.0.1:6379"

  echo "▶ Запуск pd-guard (лог: $OUT/server.log)…"
  ./target/release/pd-guard >"$OUT/server.log" 2>&1 &
  SERVER_PID=$!

  for i in $(seq 1 50); do
    if curl -fsS "$URL/health/live" >/dev/null 2>&1; then break; fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
      echo "✗ сервис не поднялся, последние строки лога:"; tail -20 "$OUT/server.log"; exit 1
    fi
    sleep 0.2
    if [ "$i" = 50 ]; then echo "✗ сервис не ответил на /health/live"; exit 1; fi
  done
  echo "✓ сервис готов"
fi

run_profile() {
  local name="$1"; shift
  echo
  echo "════════ профиль: $name ════════"
  set +e
  ./target/release/loadgen \
    --url "$URL" --mode "$MODE" \
    --system-id "$SYSTEM_ID" --system-key "$SYSTEM_KEY" \
    --json "$OUT/$name.json" "$@"
  set -e
  # Вердикт считаем по отчёту: у ratelimit 429 ожидаемы и провалом не считаются.
  local kind=sla
  [ "$name" = "ratelimit" ] && kind=ratelimit
  local rc=0
  python3 tools/loadgen/verdict.py "$OUT/$name.json" "$kind" || rc=$?
  RESULTS+=("$name:$rc")
}

RESULTS=()
for p in "${PROFILES[@]}"; do
  case "$p" in
    # Проверка работоспособности стенда.
    smoke)     run_profile smoke     --rps 50   --duration 10s --warmup 2s ;;
    # Целевой режим ТЗ: RPS 1000, latency ≤ 1 c.
    target)    run_profile target    --rps 1000 --duration 60s --warmup 5s ;;
    # Дополнительный плюс из п. 6 ТЗ: RPS 2000 при latency ≤ 1 c.
    stress)    run_profile stress    --rps 2000 --duration 60s --warmup 5s ;;
    # Крупные массивы текста: п. 4.4 ТЗ, до 100 000 токенов.
    large)     run_profile large     --rps 20   --duration 30s --warmup 2s \
                 --dataset tools/loadgen/datasets/large.jsonl --min-tokens 100000 ;;
    # Потолок пропускной способности: где ломается latency.
    ceiling)   run_profile ceiling   --rps 6000 --duration 30s --warmup 5s ;;
    # Поведение ограничителя: у payments-bot в loadtest.yaml лимит 200 RPS,
    # ждём 429 с Retry-After, а не 5xx и не зависание.
    ratelimit) run_profile ratelimit --rps 1000 --duration 20s --warmup 0s --retries 0 \
                 --system-id payments-bot --stop-after 1000000 --quiet ;;
    *) echo "неизвестный профиль: $p"; exit 2 ;;
  esac
done

echo
echo "════════ итог ════════"
for r in "${RESULTS[@]}"; do
  name="${r%:*}"; rc="${r#*:}"
  if [ "$rc" = "0" ]; then echo "  ✓ $name"; else echo "  ✗ $name (SLA не выдержан)"; fi
done
echo "Отчёты: $OUT/*.json, лог сервиса: $OUT/server.log"
