//! loadgen — нагрузочный генератор по методике Приложения B ТЗ.
//!
//! Модель нагрузки открытая (open loop): запросы уходят по расписанию независимо
//! от того, ответил ли сервис на предыдущие. При закрытой модели замедление
//! сервиса маскируется замедлением генератора (coordinated omission), и p99
//! получается заниженным.
//!
//! Датасет обрабатывается парами по одному payload_id, как это делает
//! проверяющая система: прямой шаг (маскирование) → обратный (демаскирование).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use pd_guard::domain::traits::TokenCounter;
use pd_guard::service::tokens::ApproxTokenCounter;
use serde::{Deserialize, Serialize};

const USAGE: &str = r#"loadgen — нагрузочный генератор для pd-guard (методика Приложения B ТЗ)

ИСПОЛЬЗОВАНИЕ:
    loadgen [ОПЦИИ]

ОПЦИИ:
    --url <URL>            базовый адрес сервиса            [http://127.0.0.1:8080]
    --rps <N>              целевой RPS (HTTP-запросов/с)    [1000]
    --duration <T>         длительность прогона             [60s]
    --warmup <T>           прогрев перед замером            [3s]
    --dataset <PATH>       jsonl с полями text/category/id  [tools/loadgen/datasets/mixed.jsonl]
    --mode <tz|native>     форма контракта                  [native]
    --system-id <ID>       заголовок X-System-Id (native)   [crm-assistant]
    --system-key <KEY>     заголовок X-System-Key (native)  [из PDG_LOAD_KEY]
    --timeout <T>          таймаут одного запроса           [10s]
    --retries <N>          ретраев на запрос                [2]
    --min-tokens <N>       раздуть каждый текст до N токенов [0 = как в датасете]
    --mask-only            только прямой шаг, без демаскирования
    --max-inflight <N>     потолок одновременных запросов   [20000]
    --stop-after <N>       стоп после N невалидных подряд   [5]
    --json <PATH>          сохранить отчёт в JSON
    --quiet                без прогресса раз в секунду
    -h, --help             эта справка

ФОРМЫ КОНТРАКТА:
    tz      {"payload": "...", "payload_id": "..."}  → {"result": "..."}
    native  {"operation":"mask","text":"..."}        → {"text":"...","session_id":"..."}
"#;

// ----------------------------------------------------------------------------
// Аргументы
// ----------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mode {
    Tz,
    Native,
}

impl Mode {
    fn as_str(&self) -> &'static str {
        match self {
            Mode::Tz => "tz",
            Mode::Native => "native",
        }
    }
}

struct Args {
    url: String,
    rps: f64,
    duration: Duration,
    warmup: Duration,
    dataset: PathBuf,
    mode: Mode,
    system_id: String,
    system_key: String,
    timeout: Duration,
    retries: u32,
    min_tokens: usize,
    mask_only: bool,
    max_inflight: u64,
    stop_after: u64,
    json: Option<PathBuf>,
    quiet: bool,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            url: "http://127.0.0.1:8080".into(),
            rps: 1000.0,
            duration: Duration::from_secs(60),
            warmup: Duration::from_secs(3),
            dataset: PathBuf::from("tools/loadgen/datasets/mixed.jsonl"),
            mode: Mode::Native,
            system_id: "crm-assistant".into(),
            system_key: std::env::var("PDG_LOAD_KEY").unwrap_or_default(),
            timeout: Duration::from_secs(10),
            retries: 2,
            min_tokens: 0,
            mask_only: false,
            max_inflight: 20_000,
            stop_after: 5,
            json: None,
            quiet: false,
        }
    }
}

fn parse_duration(s: &str) -> anyhow::Result<Duration> {
    let s = s.trim();
    let (num, mult) = if let Some(v) = s.strip_suffix("ms") {
        (v, 1e-3)
    } else if let Some(v) = s.strip_suffix('s') {
        (v, 1.0)
    } else if let Some(v) = s.strip_suffix('m') {
        (v, 60.0)
    } else {
        (s, 1.0)
    };
    let v: f64 = num
        .parse()
        .map_err(|_| anyhow::anyhow!("не разобрал длительность: {s}"))?;
    Ok(Duration::from_secs_f64(v * mult))
}

fn parse_args() -> anyhow::Result<Option<Args>> {
    let mut args = Args::default();
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < raw.len() {
        let (key, inline) = match raw[i].split_once('=') {
            Some((k, v)) => (k.to_string(), Some(v.to_string())),
            None => (raw[i].clone(), None),
        };
        let value = |i: &mut usize| -> anyhow::Result<String> {
            if let Some(v) = inline.clone() {
                return Ok(v);
            }
            *i += 1;
            raw.get(*i)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("у аргумента {key} нет значения"))
        };
        match raw[i].split('=').next().unwrap() {
            "-h" | "--help" => {
                print!("{USAGE}");
                return Ok(None);
            }
            "--url" => args.url = value(&mut i)?,
            "--rps" => args.rps = value(&mut i)?.parse()?,
            "--duration" => args.duration = parse_duration(&value(&mut i)?)?,
            "--warmup" => args.warmup = parse_duration(&value(&mut i)?)?,
            "--dataset" => args.dataset = PathBuf::from(value(&mut i)?),
            "--mode" => {
                args.mode = match value(&mut i)?.as_str() {
                    "tz" => Mode::Tz,
                    "native" => Mode::Native,
                    other => anyhow::bail!("неизвестный режим: {other} (ожидается tz|native)"),
                }
            }
            "--system-id" => args.system_id = value(&mut i)?,
            "--system-key" => args.system_key = value(&mut i)?,
            "--timeout" => args.timeout = parse_duration(&value(&mut i)?)?,
            "--retries" => args.retries = value(&mut i)?.parse()?,
            "--min-tokens" => args.min_tokens = value(&mut i)?.parse()?,
            "--mask-only" => args.mask_only = true,
            "--max-inflight" => args.max_inflight = value(&mut i)?.parse()?,
            "--stop-after" => args.stop_after = value(&mut i)?.parse()?,
            "--json" => args.json = Some(PathBuf::from(value(&mut i)?)),
            "--quiet" => args.quiet = true,
            other => anyhow::bail!("неизвестный аргумент: {other} (--help для справки)"),
        }
        i += 1;
    }
    Ok(Some(args))
}

// ----------------------------------------------------------------------------
// Датасет
// ----------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct DatasetLine {
    text: String,
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    id: Option<String>,
}

struct Sample {
    id: String,
    category: String,
    text: Arc<String>,
    tokens: u64,
}

fn load_dataset(path: &Path, min_tokens: usize) -> anyhow::Result<Vec<Sample>> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("не прочитал датасет {}: {e}", path.display()))?;
    let counter = ApproxTokenCounter::default();
    let mut out = Vec::new();
    for (n, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parsed: DatasetLine = serde_json::from_str(line)
            .map_err(|e| anyhow::anyhow!("{}:{}: {e}", path.display(), n + 1))?;
        let mut text = parsed.text;
        // Раздуваем текст повтором, чтобы получить нужный объём без гигантских файлов.
        if min_tokens > 0 {
            let unit_tokens = counter.count(&text).max(1);
            let reps = min_tokens.div_ceil(unit_tokens);
            if reps > 1 {
                let mut inflated = String::with_capacity(text.len() * reps + reps);
                for _ in 0..reps {
                    inflated.push_str(&text);
                    inflated.push(' ');
                }
                text = inflated;
            }
        }
        let tokens = counter.count(&text) as u64;
        out.push(Sample {
            id: parsed.id.unwrap_or_else(|| format!("item-{}", n + 1)),
            category: parsed.category.unwrap_or_else(|| "default".into()),
            text: Arc::new(text),
            tokens,
        });
    }
    if out.is_empty() {
        anyhow::bail!("датасет {} пуст", path.display());
    }
    Ok(out)
}

// ----------------------------------------------------------------------------
// HTTP
// ----------------------------------------------------------------------------

type HttpClient = Client<HttpConnector, Full<Bytes>>;

fn build_client() -> HttpClient {
    let mut connector = HttpConnector::new();
    connector.set_nodelay(true);
    connector.set_keepalive(Some(Duration::from_secs(60)));
    connector.set_connect_timeout(Some(Duration::from_secs(5)));
    Client::builder(TokioExecutor::new())
        .pool_max_idle_per_host(4096)
        .pool_idle_timeout(Duration::from_secs(30))
        .build(connector)
}

/// Исход одной попытки.
enum Attempt {
    Ok { body: Bytes },
    RateLimited { retry_after: Option<Duration> },
    Status(u16),
    Timeout,
    Transport,
}

async fn send_once(client: &HttpClient, args: &Args, body: Vec<u8>) -> Attempt {
    let mut builder = Request::builder()
        .method("POST")
        .uri(format!("{}/process", args.url.trim_end_matches('/')))
        .header("content-type", "application/json");
    // Заголовки шлём, если ключ задан: контракт Приложения A работает и с
    // аутентификацией, и без неё. Пустой ключ — проверка анонимного доступа.
    if !args.system_key.is_empty() {
        builder = builder
            .header("X-System-Id", &args.system_id)
            .header("X-System-Key", &args.system_key);
    }
    let req = match builder.body(Full::new(Bytes::from(body))) {
        Ok(r) => r,
        Err(_) => return Attempt::Transport,
    };

    let fut = client.request(req);
    let resp = match tokio::time::timeout(args.timeout, fut).await {
        Err(_) => return Attempt::Timeout,
        Ok(Err(_)) => return Attempt::Transport,
        Ok(Ok(r)) => r,
    };

    let status = resp.status().as_u16();
    let retry_after = resp
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_secs);

    let collected = match tokio::time::timeout(args.timeout, resp.into_body().collect()).await {
        Err(_) => return Attempt::Timeout,
        Ok(Err(_)) => return Attempt::Transport,
        Ok(Ok(b)) => b.to_bytes(),
    };

    match status {
        200 => Attempt::Ok { body: collected },
        429 => Attempt::RateLimited { retry_after },
        s => Attempt::Status(s),
    }
}

/// Результат шага после всех ретраев.
struct StepOutcome {
    kind: OutcomeKind,
    /// Латентность успешной попытки (или последней, если успеха не было).
    latency: Duration,
    attempts: u32,
    rate_limited: u32,
    body: Option<Bytes>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OutcomeKind {
    Ok,
    /// 429 не считается невалидным ответом и не сбрасывает счётчик (Приложение B).
    RateLimited,
    Timeout,
    HttpError(u16),
    Transport,
    BadBody,
}

async fn run_step(client: &HttpClient, args: &Args, body: Vec<u8>) -> StepOutcome {
    let mut attempts = 0;
    let mut rate_limited = 0;
    let mut last = Duration::ZERO;
    let total_attempts = args.retries + 1;

    while attempts < total_attempts {
        attempts += 1;
        let started = Instant::now();
        let attempt = send_once(client, args, body.clone()).await;
        last = started.elapsed();

        match attempt {
            Attempt::Ok { body } => {
                return StepOutcome {
                    kind: OutcomeKind::Ok,
                    latency: last,
                    attempts,
                    rate_limited,
                    body: Some(body),
                }
            }
            Attempt::RateLimited { retry_after } => {
                rate_limited += 1;
                if attempts < total_attempts {
                    // Проверяющая система учитывает Retry-After, но ждёт не дольше таймаута.
                    let wait = retry_after.unwrap_or(Duration::from_millis(100)).min(args.timeout);
                    tokio::time::sleep(wait).await;
                    continue;
                }
                return StepOutcome {
                    kind: OutcomeKind::RateLimited,
                    latency: last,
                    attempts,
                    rate_limited,
                    body: None,
                };
            }
            Attempt::Timeout => {
                if attempts < total_attempts {
                    continue;
                }
                return StepOutcome {
                    kind: OutcomeKind::Timeout,
                    latency: last,
                    attempts,
                    rate_limited,
                    body: None,
                };
            }
            Attempt::Status(s) => {
                if attempts < total_attempts && s >= 500 {
                    continue;
                }
                return StepOutcome {
                    kind: OutcomeKind::HttpError(s),
                    latency: last,
                    attempts,
                    rate_limited,
                    body: None,
                };
            }
            Attempt::Transport => {
                if attempts < total_attempts {
                    continue;
                }
                return StepOutcome {
                    kind: OutcomeKind::Transport,
                    latency: last,
                    attempts,
                    rate_limited,
                    body: None,
                };
            }
        }
    }

    StepOutcome {
        kind: OutcomeKind::Transport,
        latency: last,
        attempts,
        rate_limited,
        body: None,
    }
}

// ----------------------------------------------------------------------------
// Тела запросов и разбор ответов
// ----------------------------------------------------------------------------

fn mask_body(args: &Args, payload_id: &str, text: &str) -> Vec<u8> {
    let v = match args.mode {
        Mode::Tz => serde_json::json!({ "payload": text, "payload_id": payload_id }),
        Mode::Native => serde_json::json!({ "operation": "mask", "text": text }),
    };
    serde_json::to_vec(&v).unwrap_or_default()
}

fn demask_body(args: &Args, payload_id: &str, masked: &str, session_id: &str) -> Vec<u8> {
    let v = match args.mode {
        Mode::Tz => serde_json::json!({ "payload": masked, "payload_id": payload_id }),
        Mode::Native => serde_json::json!({
            "operation": "demask",
            "text": masked,
            "session_id": session_id,
        }),
    };
    serde_json::to_vec(&v).unwrap_or_default()
}

/// Из ответа достаём (текст, session_id).
fn parse_result(args: &Args, body: &Bytes) -> Option<(String, String)> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    match args.mode {
        Mode::Tz => Some((v.get("result")?.as_str()?.to_string(), String::new())),
        Mode::Native => {
            let text = v.get("text")?.as_str()?.to_string();
            let session = v
                .get("session_id")
                .and_then(|s| s.as_str())
                .unwrap_or_default()
                .to_string();
            Some((text, session))
        }
    }
}

// ----------------------------------------------------------------------------
// Статистика
// ----------------------------------------------------------------------------

#[derive(Default)]
struct StepStats {
    sent: u64,
    ok: u64,
    rate_limited_responses: u64,
    rate_limited_final: u64,
    timeouts: u64,
    transport_errors: u64,
    bad_body: u64,
    http_errors: HashMap<u16, u64>,
    retries: u64,
    latencies_us: Vec<u32>,
    tokens: u64,
}

impl StepStats {
    fn record(&mut self, o: &StepOutcome, tokens: u64) {
        self.sent += 1;
        self.retries += (o.attempts - 1) as u64;
        self.rate_limited_responses += o.rate_limited as u64;
        self.tokens += tokens;
        match o.kind {
            OutcomeKind::Ok => {
                self.ok += 1;
                self.latencies_us.push(o.latency.as_micros().min(u32::MAX as u128) as u32);
            }
            OutcomeKind::RateLimited => self.rate_limited_final += 1,
            OutcomeKind::Timeout => self.timeouts += 1,
            OutcomeKind::Transport => self.transport_errors += 1,
            OutcomeKind::BadBody => self.bad_body += 1,
            OutcomeKind::HttpError(s) => *self.http_errors.entry(s).or_insert(0) += 1,
        }
    }
}

#[derive(Default)]
struct CategoryStats {
    mask_ok: u64,
    mask_failed: u64,
    changed: u64,
    demask_ok: u64,
    demask_failed: u64,
    exact: u64,
}

#[derive(Default)]
struct Stats {
    mask: StepStats,
    demask: StepStats,
    per_category: HashMap<String, CategoryStats>,
    consecutive_invalid: u64,
    max_consecutive_invalid: u64,
    aborted: bool,
}

/// Сообщение от рабочей задачи к сборщику.
struct JobReport {
    category: String,
    tokens: u64,
    mask: StepOutcome,
    changed: bool,
    demask: Option<StepOutcome>,
    exact: bool,
}

fn is_invalid(kind: OutcomeKind) -> bool {
    !matches!(kind, OutcomeKind::Ok | OutcomeKind::RateLimited)
}

fn percentile(sorted: &[u32], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let rank = (p / 100.0) * (sorted.len() - 1) as f64;
    let lo = rank.floor() as usize;
    let hi = rank.ceil() as usize;
    let frac = rank - lo as f64;
    let v = sorted[lo] as f64 * (1.0 - frac) + sorted[hi] as f64 * frac;
    v / 1000.0 // мс
}

// ----------------------------------------------------------------------------
// Отчёт
// ----------------------------------------------------------------------------

#[derive(Serialize)]
struct StepReport {
    sent: u64,
    ok: u64,
    ok_rate: f64,
    rate_limited_responses: u64,
    rate_limited_final: u64,
    timeouts: u64,
    transport_errors: u64,
    bad_body: u64,
    http_errors: HashMap<String, u64>,
    retries: u64,
    p50_ms: f64,
    p90_ms: f64,
    p95_ms: f64,
    p99_ms: f64,
    p999_ms: f64,
    max_ms: f64,
    mean_ms: f64,
}

fn step_report(s: &StepStats) -> StepReport {
    let mut lat = s.latencies_us.clone();
    lat.sort_unstable();
    let mean = if lat.is_empty() {
        0.0
    } else {
        lat.iter().map(|v| *v as f64).sum::<f64>() / lat.len() as f64 / 1000.0
    };
    StepReport {
        sent: s.sent,
        ok: s.ok,
        ok_rate: if s.sent == 0 { 0.0 } else { s.ok as f64 / s.sent as f64 },
        rate_limited_responses: s.rate_limited_responses,
        rate_limited_final: s.rate_limited_final,
        timeouts: s.timeouts,
        transport_errors: s.transport_errors,
        bad_body: s.bad_body,
        http_errors: s.http_errors.iter().map(|(k, v)| (k.to_string(), *v)).collect(),
        retries: s.retries,
        p50_ms: percentile(&lat, 50.0),
        p90_ms: percentile(&lat, 90.0),
        p95_ms: percentile(&lat, 95.0),
        p99_ms: percentile(&lat, 99.0),
        p999_ms: percentile(&lat, 99.9),
        max_ms: lat.last().map(|v| *v as f64 / 1000.0).unwrap_or(0.0),
        mean_ms: mean,
    }
}

#[derive(Serialize)]
struct Report {
    mode: String,
    url: String,
    dataset: String,
    target_rps: f64,
    duration_s: f64,
    requests_total: u64,
    achieved_rps: f64,
    tokens_per_second: f64,
    scheduler_lag_events: u64,
    aborted_after_consecutive_invalid: bool,
    max_consecutive_invalid: u64,
    mask: StepReport,
    demask: StepReport,
    masking_rate: f64,
    exact_restore_rate: f64,
    per_category: HashMap<String, CategoryReport>,
}

#[derive(Serialize)]
struct CategoryReport {
    mask_ok: u64,
    mask_failed: u64,
    masking_rate: f64,
    demask_ok: u64,
    demask_failed: u64,
    exact_restore_rate: f64,
}

fn print_report(r: &Report) {
    let line = "─".repeat(78);
    println!("\n{line}");
    println!(
        "Прогон: режим {}, цель {:.0} RPS, {:.1} с, датасет {}",
        r.mode, r.target_rps, r.duration_s, r.dataset
    );
    println!("{line}");
    println!(
        "Запросов: {}   достигнуто {:.0} RPS   {:.0} токенов/с",
        r.requests_total, r.achieved_rps, r.tokens_per_second
    );
    if r.scheduler_lag_events > 0 {
        println!(
            "⚠ генератор упёрся в потолок in-flight {} раз — цифры ниже занижены",
            r.scheduler_lag_events
        );
    }
    if r.aborted_after_consecutive_invalid {
        println!(
            "⛔ прогон остановлен: {} невалидных ответов подряд (условие Приложения B)",
            r.max_consecutive_invalid
        );
    }

    println!("\n{:<10} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8}", "шаг", "ok", "p50", "p90", "p95", "p99", "p99.9", "max");
    for (name, s) in [("mask", &r.mask), ("demask", &r.demask)] {
        if s.sent == 0 {
            continue;
        }
        println!(
            "{:<10} {:>7.2}% {:>7.1} {:>7.1} {:>7.1} {:>7.1} {:>7.1} {:>7.1}",
            name,
            s.ok_rate * 100.0,
            s.p50_ms,
            s.p90_ms,
            s.p95_ms,
            s.p99_ms,
            s.p999_ms,
            s.max_ms
        );
    }
    println!("(латентность в мс, только успешные ответы)");

    println!("\nОшибки:");
    for (name, s) in [("mask", &r.mask), ("demask", &r.demask)] {
        if s.sent == 0 {
            continue;
        }
        let mut parts = vec![format!("отправлено {}", s.sent), format!("ok {}", s.ok)];
        if s.rate_limited_responses > 0 {
            parts.push(format!(
                "429 {} (не прошли после ретраев: {})",
                s.rate_limited_responses, s.rate_limited_final
            ));
        }
        if s.timeouts > 0 {
            parts.push(format!("таймаутов {}", s.timeouts));
        }
        if s.transport_errors > 0 {
            parts.push(format!("транспорт {}", s.transport_errors));
        }
        if s.bad_body > 0 {
            parts.push(format!("тело не разобрано {}", s.bad_body));
        }
        for (code, n) in &s.http_errors {
            parts.push(format!("HTTP {code}: {n}"));
        }
        if s.retries > 0 {
            parts.push(format!("ретраев {}", s.retries));
        }
        println!("  {name:<7} {}", parts.join(", "));
    }

    println!("\nКачество:");
    println!("  текст изменён маскированием: {:.2}%", r.masking_rate * 100.0);
    if r.demask.sent > 0 {
        println!(
            "  демаскирование вернуло исходник: {:.2}%",
            r.exact_restore_rate * 100.0
        );
    }

    if r.per_category.len() > 1 {
        println!("\nПо категориям:");
        println!("  {:<22} {:>9} {:>11} {:>9}", "категория", "masked%", "restored%", "ошибок");
        let mut cats: Vec<_> = r.per_category.iter().collect();
        cats.sort_by_key(|(k, _)| k.as_str());
        for (name, c) in cats {
            println!(
                "  {:<22} {:>8.1}% {:>10.1}% {:>9}",
                name,
                c.masking_rate * 100.0,
                c.exact_restore_rate * 100.0,
                c.mask_failed + c.demask_failed
            );
        }
    }
    println!("{line}\n");
}

// ----------------------------------------------------------------------------
// Прогон
// ----------------------------------------------------------------------------

async fn run(args: Args) -> anyhow::Result<()> {
    let samples = Arc::new(load_dataset(&args.dataset, args.min_tokens)?);
    let args = Arc::new(args);
    let client = Arc::new(build_client());

    let total_tokens: u64 = samples.iter().map(|s| s.tokens).sum();
    println!(
        "Датасет: {} примеров, {} токенов суммарно, ~{} токенов на запрос",
        samples.len(),
        total_tokens,
        total_tokens / samples.len() as u64
    );

    // Прогрев: прогреваем пул соединений и кэши сервиса, в статистику не идёт.
    if !args.warmup.is_zero() {
        println!("Прогрев {:.1} с…", args.warmup.as_secs_f64());
        let deadline = Instant::now() + args.warmup;
        let mut idx = 0usize;
        while Instant::now() < deadline {
            let s = &samples[idx % samples.len()];
            idx += 1;
            let body = mask_body(&args, &format!("warmup-{idx}"), &s.text);
            let _ = run_step(&client, &args, body).await;
        }
    }

    // Проба контракта: один запрос, чтобы не гонять нагрузку впустую на 401/400.
    {
        let s = &samples[0];
        let body = mask_body(&args, "probe-0", &s.text);
        let probe = run_step(&client, &args, body).await;
        match probe.kind {
            OutcomeKind::Ok => {
                if parse_result(&args, probe.body.as_ref().unwrap()).is_none() {
                    anyhow::bail!(
                        "сервис ответил 200, но тело не соответствует режиму {}: {}",
                        args.mode.as_str(),
                        String::from_utf8_lossy(probe.body.as_ref().unwrap())
                            .chars()
                            .take(200)
                            .collect::<String>()
                    );
                }
            }
            OutcomeKind::HttpError(s) => anyhow::bail!(
                "проба контракта вернула HTTP {s}. Режим {} не поддерживается сервисом, \
                 либо неверные --system-id/--system-key",
                args.mode.as_str()
            ),
            OutcomeKind::Transport => {
                anyhow::bail!("сервис недоступен по адресу {}", args.url)
            }
            OutcomeKind::Timeout => anyhow::bail!("проба контракта не уложилась в таймаут"),
            _ => {}
        }
    }

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<JobReport>();
    let stop = Arc::new(AtomicBool::new(false));
    let inflight = Arc::new(AtomicU64::new(0));
    let lag_events = Arc::new(AtomicU64::new(0));

    // Сборщик: агрегирует отчёты и следит за серией невалидных ответов.
    let collector = {
        let stop = stop.clone();
        let stop_after = args.stop_after;
        tokio::spawn(async move {
            let mut stats = Stats::default();
            while let Some(job) = rx.recv().await {
                let cat = stats.per_category.entry(job.category.clone()).or_default();

                stats.mask.record(&job.mask, job.tokens);
                if job.mask.kind == OutcomeKind::Ok {
                    cat.mask_ok += 1;
                    if job.changed {
                        cat.changed += 1;
                    }
                } else {
                    cat.mask_failed += 1;
                }

                if let Some(d) = &job.demask {
                    stats.demask.record(d, 0);
                    if d.kind == OutcomeKind::Ok {
                        cat.demask_ok += 1;
                        if job.exact {
                            cat.exact += 1;
                        }
                    } else {
                        cat.demask_failed += 1;
                    }
                }

                // Условие остановки Приложения B: 5 невалидных подряд; 429 нейтрален.
                for kind in [Some(job.mask.kind), job.demask.as_ref().map(|d| d.kind)]
                    .into_iter()
                    .flatten()
                {
                    if is_invalid(kind) {
                        stats.consecutive_invalid += 1;
                        stats.max_consecutive_invalid =
                            stats.max_consecutive_invalid.max(stats.consecutive_invalid);
                        if stats.consecutive_invalid >= stop_after && !stats.aborted {
                            stats.aborted = true;
                            stop.store(true, Ordering::Relaxed);
                        }
                    } else if kind == OutcomeKind::Ok {
                        stats.consecutive_invalid = 0;
                    }
                }
            }
            stats
        })
    };

    // Прогресс раз в секунду.
    let progress = if args.quiet {
        None
    } else {
        let inflight = inflight.clone();
        let stop = stop.clone();
        Some(tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(1));
            ticker.tick().await;
            let mut sec = 0u64;
            while !stop.load(Ordering::Relaxed) {
                ticker.tick().await;
                sec += 1;
                eprint!("\r  {sec} с, в полёте {}   ", inflight.load(Ordering::Relaxed));
            }
        }))
    };

    println!(
        "Нагрузка: {:.0} RPS, {:.0} с, режим {}…",
        args.rps,
        args.duration.as_secs_f64(),
        args.mode.as_str()
    );

    // Открытая модель: тикаем каждую миллисекунду и выпускаем накопившиеся задания.
    // Одно задание = пара mask→demask, то есть два HTTP-запроса.
    let jobs_per_sec = if args.mask_only { args.rps } else { args.rps / 2.0 };
    let jobs_per_tick = jobs_per_sec / 1000.0;

    let started = Instant::now();
    let mut ticker = tokio::time::interval(Duration::from_millis(1));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Burst);
    let mut credit = 0.0f64;
    let mut idx = 0u64;
    let mut handles = Vec::new();

    while started.elapsed() < args.duration && !stop.load(Ordering::Relaxed) {
        ticker.tick().await;
        credit += jobs_per_tick;
        while credit >= 1.0 {
            credit -= 1.0;
            if inflight.load(Ordering::Relaxed) >= args.max_inflight {
                lag_events.fetch_add(1, Ordering::Relaxed);
                credit = 0.0;
                break;
            }
            let sample = &samples[(idx as usize) % samples.len()];
            let payload_id = format!("{}-{}", sample.id, idx);
            idx += 1;

            let client = client.clone();
            let args = args.clone();
            let tx = tx.clone();
            let inflight = inflight.clone();
            let text = sample.text.clone();
            let category = sample.category.clone();
            let tokens = sample.tokens;

            inflight.fetch_add(1, Ordering::Relaxed);
            handles.push(tokio::spawn(async move {
                let mask_out = run_step(&client, &args, mask_body(&args, &payload_id, &text)).await;

                let mut changed = false;
                let mut demask_out = None;
                let mut exact = false;

                if mask_out.kind == OutcomeKind::Ok {
                    match parse_result(&args, mask_out.body.as_ref().unwrap()) {
                        Some((masked, session)) => {
                            changed = masked != *text;
                            if !args.mask_only {
                                let body = demask_body(&args, &payload_id, &masked, &session);
                                let out = run_step(&client, &args, body).await;
                                if out.kind == OutcomeKind::Ok {
                                    if let Some((restored, _)) =
                                        parse_result(&args, out.body.as_ref().unwrap())
                                    {
                                        exact = restored == *text;
                                    }
                                }
                                demask_out = Some(out);
                            }
                        }
                        None => {
                            // 200 с телом не по контракту — невалидный ответ.
                            let mut broken = mask_out;
                            broken.kind = OutcomeKind::BadBody;
                            let _ = tx.send(JobReport {
                                category,
                                tokens,
                                mask: broken,
                                changed: false,
                                demask: None,
                                exact: false,
                            });
                            inflight.fetch_sub(1, Ordering::Relaxed);
                            return;
                        }
                    }
                }

                let _ = tx.send(JobReport {
                    category,
                    tokens,
                    mask: mask_out,
                    changed,
                    demask: demask_out,
                    exact,
                });
                inflight.fetch_sub(1, Ordering::Relaxed);
            }));
        }
    }

    // Даём долететь тому, что уже в воздухе.
    for h in handles {
        let _ = h.await;
    }
    let elapsed = started.elapsed();
    drop(tx);
    stop.store(true, Ordering::Relaxed);
    if let Some(p) = progress {
        let _ = p.await;
        eprint!("\r{}\r", " ".repeat(40));
    }
    let stats = collector.await?;

    // Отчёт.
    let requests_total = stats.mask.sent + stats.demask.sent;
    let mask_rep = step_report(&stats.mask);
    let demask_rep = step_report(&stats.demask);
    let changed: u64 = stats.per_category.values().map(|c| c.changed).sum();
    let mask_ok: u64 = stats.per_category.values().map(|c| c.mask_ok).sum();
    let exact: u64 = stats.per_category.values().map(|c| c.exact).sum();
    let demask_ok: u64 = stats.per_category.values().map(|c| c.demask_ok).sum();

    let report = Report {
        mode: args.mode.as_str().to_string(),
        url: args.url.clone(),
        dataset: args.dataset.display().to_string(),
        target_rps: args.rps,
        duration_s: elapsed.as_secs_f64(),
        requests_total,
        achieved_rps: requests_total as f64 / elapsed.as_secs_f64(),
        tokens_per_second: stats.mask.tokens as f64 / elapsed.as_secs_f64(),
        scheduler_lag_events: lag_events.load(Ordering::Relaxed),
        aborted_after_consecutive_invalid: stats.aborted,
        max_consecutive_invalid: stats.max_consecutive_invalid,
        mask: mask_rep,
        demask: demask_rep,
        masking_rate: if mask_ok == 0 { 0.0 } else { changed as f64 / mask_ok as f64 },
        exact_restore_rate: if demask_ok == 0 { 0.0 } else { exact as f64 / demask_ok as f64 },
        per_category: stats
            .per_category
            .iter()
            .map(|(k, c)| {
                (
                    k.clone(),
                    CategoryReport {
                        mask_ok: c.mask_ok,
                        mask_failed: c.mask_failed,
                        masking_rate: if c.mask_ok == 0 {
                            0.0
                        } else {
                            c.changed as f64 / c.mask_ok as f64
                        },
                        demask_ok: c.demask_ok,
                        demask_failed: c.demask_failed,
                        exact_restore_rate: if c.demask_ok == 0 {
                            0.0
                        } else {
                            c.exact as f64 / c.demask_ok as f64
                        },
                    },
                )
            })
            .collect(),
    };

    print_report(&report);

    if let Some(path) = &args.json {
        std::fs::write(path, serde_json::to_vec_pretty(&report)?)?;
        println!("JSON-отчёт: {}", path.display());
    }

    // Код возврата: ненулевой, если SLA не выдержан.
    let sla_ok = !report.aborted_after_consecutive_invalid
        && report.mask.ok_rate >= 0.99
        && report.mask.p99_ms <= 1000.0;
    if !sla_ok {
        std::process::exit(1);
    }
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let Some(args) = parse_args()? else {
        return Ok(());
    };
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(run(args))
}
