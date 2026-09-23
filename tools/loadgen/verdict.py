#!/usr/bin/env python3
"""Вердикт по JSON-отчёту loadgen: печатает итог и возвращает 0/1.

    verdict.py <отчёт.json> [sla|ratelimit]

sla        — целевой режим ТЗ: почти все запросы успешны, p99 в пределах секунды.
ratelimit  — проверка ограничителя: 429 ожидаемы, 5xx и таймауты — нет.
"""
import json
import sys


def check_sla(r):
    problems = []
    m, d = r["mask"], r["demask"]
    if r["aborted_after_consecutive_invalid"]:
        problems.append(
            f"прогон остановлен после {r['max_consecutive_invalid']} невалидных ответов подряд"
        )
    if r["scheduler_lag_events"]:
        problems.append(
            f"генератор упёрся в потолок in-flight {r['scheduler_lag_events']} раз — "
            "цифры занижены, поднимите --max-inflight"
        )
    for step, s in (("mask", m), ("demask", d)):
        if s["sent"] == 0:
            continue
        if s["ok_rate"] < 0.99:
            problems.append(f"{step}: успешных {s['ok_rate'] * 100:.2f}% (< 99%)")
        if s["p99_ms"] > 1000:
            problems.append(f"{step}: p99 {s['p99_ms']:.0f} мс (> 1000)")
        if s["timeouts"]:
            problems.append(f"{step}: таймаутов {s['timeouts']}")
        for code, n in sorted(s["http_errors"].items()):
            if int(code) >= 500:
                problems.append(f"{step}: HTTP {code} × {n}")
    ok = (
        f"✓ {r['achieved_rps']:.0f} RPS, mask p99 {m['p99_ms']:.1f} мс, "
        f"успешных {m['ok_rate'] * 100:.2f}%"
    )
    return problems, ok


def check_ratelimit(r):
    problems = []
    m, d = r["mask"], r["demask"]
    if m["rate_limited_responses"] == 0:
        problems.append("ограничитель не сработал: ни одного 429")
    for step, s in (("mask", m), ("demask", d)):
        if s["sent"] == 0:
            continue
        if s["timeouts"]:
            problems.append(f"{step}: таймаутов {s['timeouts']}")
        if s["transport_errors"]:
            problems.append(f"{step}: обрывов соединения {s['transport_errors']}")
        for code, n in sorted(s["http_errors"].items()):
            if int(code) >= 500:
                problems.append(f"{step}: HTTP {code} × {n} вместо 429")
        if s["p99_ms"] > 1000:
            problems.append(f"{step}: p99 {s['p99_ms']:.0f} мс под лимитом")
    ok = (
        f"✓ ограничитель отдал {m['rate_limited_responses']} × 429 с Retry-After, "
        "5xx и таймаутов нет"
    )
    return problems, ok


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    report = json.load(open(sys.argv[1], encoding="utf-8"))
    kind = sys.argv[2] if len(sys.argv) > 2 else "sla"
    problems, ok = (check_ratelimit if kind == "ratelimit" else check_sla)(report)
    if problems:
        for p in problems:
            print(f"  ⚠ {p}")
        return 1
    print(f"  {ok}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
