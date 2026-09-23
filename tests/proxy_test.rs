//! Интеграционные тесты прокси-режима: маскирование запроса, демаскирование ответа,
//! гибкая настройка через конфиг (json_paths, bypass, block, upstream).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use pd_guard::adapter::circuit_breaker::CircuitBreaker;
use pd_guard::adapter::llm_client::{HttpLlmClient, UpstreamConfig};
use pd_guard::adapter::vault_memory::MemoryVault;
use pd_guard::config::loader;
use pd_guard::domain::traits::{
    CombinationRule, Detector, LlmClient, Masker, MaskKind, RelevanceFilter, Resolver, Validator,
    Vault,
};
use pd_guard::service::combination::DefaultCombinationRule;
use pd_guard::service::detect::address::AddressDetector;
use pd_guard::service::detect::card::{CardHolderDetector, CardNumberDetector, CvvDetector, PinDetector};
use pd_guard::service::detect::citizenship::CitizenshipDetector;
use pd_guard::service::detect::dates::{DateDetector, NumeralDateDetector};
use pd_guard::service::detect::email::EmailDetector;
use pd_guard::service::detect::fio::FioDetector;
use pd_guard::service::detect::inn::InnDetector;
use pd_guard::service::detect::passport::{DivisionCodeDetector, PassportDetector};
use pd_guard::service::detect::phone::PhoneDetector;
use pd_guard::service::detect::snils::SnilsDetector;
use pd_guard::service::guard_service::GuardService;
use pd_guard::service::mask::{HashMasker, PartialMasker, PlaceholderMasker, RedactMasker, SyntheticMasker, TokenMasker};
use pd_guard::service::pipeline::PipelineCtx;
use pd_guard::service::policy_resolver::PolicyResolver;
use pd_guard::service::relevance::{BankAllowlistFilter, NegativeNumberContext, OrgContextFilter, PublicPersonFilter};
use pd_guard::service::resolve::DefaultResolver;

fn install_crypto() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn base64_encode_32() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes)
}

fn sha256_hex(s: &str) -> String {
    pd_guard::infra::crypto::sha256_hex(s.as_bytes())
}

/// Строит полный стек сервиса с прокси-клиентом к заданному upstream URL.
fn build_proxy_stack(upstream_url: &str) -> (Arc<GuardService>, Arc<PolicyResolver>, Arc<pd_guard::config::compiled::CompiledConfig>) {
    let cfg_yaml = format!(
        r#"
version: 1
server:
  listen: "0.0.0.0:8080"
  admin_listen: "127.0.0.1:9090"
  max_body_bytes: 2000000
  request_timeout_ms: 2000
security:
  master_key: "env:PDG_MASTER_KEY"
  auth_header: "X-System-Key"
  system_id_header: "X-System-Id"
  default_system_id: "crm-assistant"
vault:
  mode: memory
  ttl_seconds: 900
ner:
  engine: disabled
resources:
  first_names: "config/resources/first_names.txt"
  public_persons: "config/resources/public_persons.txt"
  bank_offices: "config/resources/bank_offices.txt"
  bank_phones: "config/resources/bank_phones.txt"
  countries: "config/resources/countries.txt"
  cities: "config/resources/cities.txt"
  issuing_authorities: "config/resources/issuing_authorities.txt"
pd_types:
  FIO:            {{ label: "ФИО",       priority: 50,  threshold: 0.7 }}
  PASSPORT:       {{ label: "ПАСПОРТ",   priority: 90,  threshold: 0.6 }}
  EMAIL:          {{ label: "EMAIL",     priority: 80,  threshold: 0.6 }}
  PHONE:          {{ label: "ТЕЛЕФОН",   priority: 80,  threshold: 0.6 }}
  INN:            {{ label: "ИНН",       priority: 95,  threshold: 0.6 }}
  CARD_NUMBER:    {{ label: "КАРТА",     priority: 100, threshold: 0.7 }}
  CVV:            {{ label: "CVV",       priority: 40,  threshold: 0.6 }}
  PIN:            {{ label: "ПИН",       priority: 40,  threshold: 0.6 }}
  CARD_HOLDER:    {{ label: "ДЕРЖАТЕЛЬ", priority: 52,  threshold: 0.6 }}
  SNILS:          {{ label: "СНИЛС",     priority: 90,  threshold: 0.6 }}
  DRIVER_LICENSE: {{ label: "ВУ",        priority: 85,  threshold: 0.6 }}
  ADDRESS:        {{ label: "АДРЕС",     priority: 60,  threshold: 0.6 }}
  ADDR_CITY:      {{ label: "ГОРОД",     priority: 45,  threshold: 0.6 }}
  ADDR_STREET:    {{ label: "УЛИЦА",     priority: 45,  threshold: 0.6 }}
  ADDR_HOUSE:     {{ label: "ДОМ",       priority: 45,  threshold: 0.6 }}
  ADDR_FLAT:      {{ label: "КВ",        priority: 45,  threshold: 0.6 }}
  DATE:           {{ label: "ДАТА",      priority: 10,  threshold: 0.6 }}
  ORG_INN:        {{ label: "ИНН_ОРГ",   priority: 95,  threshold: 0.6 }}
  UNCLASSIFIED_ID: {{ label: "ID",       priority: 5,   threshold: 0.6 }}
profiles:
  strict:
    types:
      FIO:             {{ mask: placeholder }}
      PASSPORT:        {{ mask: placeholder }}
      EMAIL:           {{ mask: placeholder }}
      PHONE:           {{ mask: placeholder }}
      INN:             {{ mask: placeholder }}
      CARD_NUMBER:     {{ mask: partial, keep_last: 4 }}
      CVV:             {{ mask: redact }}
      PIN:             {{ mask: redact }}
      CARD_HOLDER:     {{ mask: placeholder }}
      SNILS:           {{ mask: placeholder }}
      DRIVER_LICENSE:  {{ mask: placeholder }}
      ADDRESS:         {{ mask: placeholder, mode: components }}
    ner: {{ enabled: false }}
    filters: [public_persons, bank_allowlist, org_context, negative_number_context]
    combination:
      rules:
        PIN: {{ requires_any: [CARD_NUMBER], scope: document }}
      min_distinct_types: 1
      always_mask: [CARD_NUMBER, PASSPORT, INN]
    ambiguous_ids: mask
    demask: true
defaults:
  profile: strict
  placeholder: {{ format: "[{{label}}_{{n}}]" }}
  action: mask
systems:
  crm-assistant:
    enabled: true
    key_sha256: "env:PDG_KEY_CRM_SHA256"
    profile: strict
    demask: true
upstreams:
  llm-main:
    url: "{upstream_url}"
    auth_header: "Authorization"
    auth_value: "Bearer test-token"
    timeout_ms: 2000
    pass_headers: ["content-type", "accept"]
routes:
  - id: chat
    match: {{ method: POST, path: "/v1/chat/completions" }}
    upstream: llm-main
    request:
      json_paths: ["$.messages[*].content"]
    response:
      demask: true
      json_paths: ["$.choices[*].message.content"]
    stream: forbid
  - id: models
    match: {{ method: GET, path: "/v1/models" }}
    upstream: llm-main
    action: bypass
  - id: files
    match: {{ method: POST, path_prefix: "/v1/files" }}
    action: block
"#
    );

    std::env::set_var("PDG_MASTER_KEY", base64_encode_32());
    std::env::set_var("PDG_KEY_CRM_SHA256", sha256_hex("test-key"));

    let cfg = loader::load_from_str(&cfg_yaml, std::path::Path::new(".")).unwrap();
    let cfg = Arc::new(cfg);

    let master_key = pd_guard::infra::crypto::MasterKey::from_base64(&cfg.master_key_b64).unwrap();
    let vault: Arc<dyn Vault> = Arc::new(MemoryVault::new(Duration::from_secs(900), 1000));

    let mut registry = pd_guard::service::detect::DetectorRegistry::default();
    registry.register(Arc::new(CardNumberDetector::new()));
    registry.register(Arc::new(CvvDetector::new()));
    registry.register(Arc::new(PinDetector::new()));
    registry.register(Arc::new(CardHolderDetector::new()));
    registry.register(Arc::new(InnDetector::new()));
    registry.register(Arc::new(PassportDetector::new()));
    registry.register(Arc::new(DivisionCodeDetector::new()));
    registry.register(Arc::new(PhoneDetector::new()));
    registry.register(Arc::new(EmailDetector::new()));
    registry.register(Arc::new(SnilsDetector::new()));
    registry.register(Arc::new(DateDetector::new()));
    registry.register(Arc::new(NumeralDateDetector::new()));
    registry.register(Arc::new(AddressDetector::new()));
    registry.register(Arc::new(CitizenshipDetector::new(cfg.countries.clone())));
    registry.register(Arc::new(FioDetector::new(cfg.first_names.clone())));
    registry.register(Arc::new(pd_guard::service::detect::documents::DriverLicenseDetector::new()));
    registry.register(Arc::new(pd_guard::service::detect::documents::BirthPlaceDetector::new(cfg.cities.clone(), cfg.countries.clone())));
    registry.register(Arc::new(pd_guard::service::detect::documents::PassportIssuerDetector::new(cfg.issuing_authorities.clone())));
    registry.register(Arc::new(pd_guard::service::detect::structured::StructuredFieldDetector::new()));

    let detectors: Vec<Arc<dyn Detector>> = registry.detectors.clone();
    let validators: Vec<Arc<dyn Validator>> = vec![];
    let context_scorers: Vec<Arc<dyn pd_guard::domain::traits::ContextScorer>> = vec![];
    let filters: Vec<Arc<dyn RelevanceFilter>> = vec![
        Arc::new(PublicPersonFilter { persons: cfg.public_persons.clone() }),
        Arc::new(BankAllowlistFilter::new(cfg.bank_offices.clone(), cfg.bank_phones.clone())),
        Arc::new(OrgContextFilter),
        Arc::new(NegativeNumberContext),
    ];
    let resolver: Arc<dyn Resolver> = Arc::new(DefaultResolver);
    let combination: Arc<dyn CombinationRule> = Arc::new(DefaultCombinationRule);

    let placeholder: Arc<dyn Masker> = Arc::new(PlaceholderMasker { format: cfg.placeholder_format.clone(), labels: cfg.labels.clone() });
    let redact: Arc<dyn Masker> = Arc::new(RedactMasker);
    let partial: Arc<dyn Masker> = Arc::new(PartialMasker { keep_last: 4 });
    let token: Arc<dyn Masker> = Arc::new(TokenMasker { secret: master_key.expose().to_vec() });
    let hash: Arc<dyn Masker> = Arc::new(HashMasker);
    let synthetic: Arc<dyn Masker> = Arc::new(SyntheticMasker {
        secret: master_key.expose().to_vec(),
        first_names: cfg.first_names.clone(),
        surnames: vec!["Иванов".into(), "Петров".into()],
    });
    let mut maskers_by_kind: std::collections::HashMap<MaskKind, Arc<dyn Masker>> = std::collections::HashMap::new();
    maskers_by_kind.insert(MaskKind::Placeholder, placeholder.clone());
    maskers_by_kind.insert(MaskKind::Redact, redact.clone());
    maskers_by_kind.insert(MaskKind::Partial, partial.clone());
    maskers_by_kind.insert(MaskKind::Token, token.clone());
    maskers_by_kind.insert(MaskKind::Hash, hash.clone());
    maskers_by_kind.insert(MaskKind::Synthetic, synthetic.clone());

    let pipeline = Arc::new(PipelineCtx {
        detectors,
        validators,
        context_scorers,
        ner: None,
        filters,
        resolver,
        combination,
        maskers_by_kind,
        default_masker: placeholder,
        prefilter_regex_set: cfg.prefilter_regex_set.clone(),
    });

    // LLM-клиент к mock upstream.
    let mut upstreams = HashMap::new();
    upstreams.insert(
        "llm-main".to_string(),
        UpstreamConfig {
            url: upstream_url.to_string(),
            auth_header: "Authorization".into(),
            auth_value: "Bearer test-token".into(),
            timeout_ms: 2000,
            pass_headers: vec!["content-type".into(), "accept".into()],
        },
    );
    let mut cbs = HashMap::new();
    cbs.insert("llm-main".to_string(), Arc::new(CircuitBreaker::new(0.5, 20, 10)));
    let llm: Option<Arc<dyn LlmClient>> = Some(Arc::new(HttpLlmClient::new(upstreams, cbs)));

    let service = Arc::new(GuardService {
        pipeline,
        vault,
        llm,
        master_key,
        vault_mode: "memory".into(),
        ttl: Duration::from_secs(900),
        delete_after_demask: false,
        heavy_text_threshold_bytes: 65536,
    });

    let resolver = Arc::new(PolicyResolver::new(cfg.clone()));
    (service, resolver, cfg)
}

/// Запускает mock upstream, который эхо-возвращает тело с добавленным ответом.
async fn spawn_mock_upstream() -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{addr}");
    let handle = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let io = hyper_util::rt::TokioIo::new(stream);
            tokio::spawn(async move {
                let service = hyper::service::service_fn(|req: Request<hyper::body::Incoming>| async move {
                    let _body = req.into_body().collect().await.unwrap().to_bytes();
                    let resp_body = serde_json::json!({
                        "choices": [{
                            "message": {
                                "content": "Здравствуйте, Иванов Иван Иванович! Ваш телефон +7 912 345-67-89"
                            }
                        }]
                    });
                    Ok::<_, std::convert::Infallible>(
                        Response::builder()
                            .status(200)
                            .header("content-type", "application/json")
                            .body(Full::new(Bytes::from(serde_json::to_vec(&resp_body).unwrap())))
                            .unwrap(),
                    )
                });
                let conn = hyper::server::conn::http1::Builder::new().serve_connection(io, service);
                let _ = conn.await;
            });
        }
    });
    (url, handle)
}

/// Строит полный Router и запускает реальный HTTP-сервер на случайном порту.
async fn spawn_server(upstream_url: &str) -> (String, tokio::task::JoinHandle<()>) {
    let (service, resolver, cfg) = build_proxy_stack(upstream_url);
    let process = pd_guard::controller::process_handler::ProcessHandler {
        cfg: cfg.clone(),
        service: service.clone(),
        resolver: resolver.clone(),
        token_counter: Arc::new(pd_guard::service::tokens::ApproxTokenCounter::default()),
        inflight: pd_guard::controller::middleware::InflightGuard::new(4096),
        rate_limiter: Arc::new(pd_guard::infra::rate_limit::RateLimiter::new()),
    };
    let proxy = pd_guard::controller::proxy_handler::ProxyHandler {
        cfg: cfg.clone(),
        service: service.clone(),
        resolver: resolver.clone(),
        rate_limiter: Arc::new(pd_guard::infra::rate_limit::RateLimiter::new()),
    };
    let vault_health: Arc<dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send>> + Send + Sync> = {
        let vault = service.vault.clone();
        Arc::new(move || {
            let vault = vault.clone();
            Box::pin(async move { vault.health().await })
        })
    };
    let admin = pd_guard::controller::admin_handler::AdminHandler {
        cfg: cfg.clone(),
        vault_health,
        reload: Arc::new(move || Ok(())),
    };
    let router = Arc::new(pd_guard::controller::router::Router { process, proxy, admin });

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{addr}");
    let handle = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let io = hyper_util::rt::TokioIo::new(stream);
            let router = router.clone();
            tokio::spawn(async move {
                let service = hyper::service::service_fn(move |req| {
                    let router = router.clone();
                    async move {
                        let resp = router.route(req).await;
                        let (parts, body) = resp.into_parts();
                        let full = http_body_util::Full::new(body);
                        Ok::<_, std::convert::Infallible>(http::Response::from_parts(parts, full))
                    }
                });
                let conn = hyper::server::conn::http1::Builder::new().keep_alive(true).serve_connection(io, service);
                let _ = conn.await;
            });
        }
    });
    (url, handle)
}

/// Отправляет HTTP-запрос через реальный клиент.
async fn http_request(
    base: &str,
    method: &str,
    path: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .build();
    let client: hyper_util::client::legacy::Client<_, Full<Bytes>> =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new()).build(https);

    let mut builder = Request::builder()
        .method(method)
        .uri(format!("{base}{path}"))
        .header("X-System-Id", "crm-assistant")
        .header("X-System-Key", "test-key");
    let req = match body {
        Some(v) => {
            builder = builder.header("content-type", "application/json");
            builder.body(Full::new(Bytes::from(serde_json::to_vec(&v).unwrap()))).unwrap()
        }
        None => builder.body(Full::new(Bytes::new())).unwrap(),
    };
    let resp = client.request(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

/// Запрос без заголовков аутентификации — так обращается проверяющая система.
async fn http_request_anon(
    base: &str,
    path: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .build();
    let client: hyper_util::client::legacy::Client<_, Full<Bytes>> =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new()).build(https);
    let req = Request::builder()
        .method("POST")
        .uri(format!("{base}{path}"))
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(serde_json::to_vec(&body).unwrap())))
        .unwrap();
    let resp = client.request(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

/// Приложение A: первый запрос с новым payload_id маскирует, второй с тем же id
/// возвращает исходную строку.
#[tokio::test]
async fn tz_contract_masks_then_restores() {
    install_crypto();
    let (upstream, _u) = spawn_mock_upstream().await;
    let (base, _h) = spawn_server(&upstream).await;

    let original = "Клиент Иванов Иван Иванович, паспорт 4509 123456";
    let (status, masked) = http_request_anon(
        &base,
        "/process",
        serde_json::json!({"payload": original, "payload_id": "pair-1"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let masked_text = masked["result"].as_str().unwrap().to_string();
    assert_ne!(masked_text, original, "прямой шаг обязан что-то замаскировать");
    assert!(!masked_text.contains("Иванов"), "ФИО осталось в маске");
    assert!(!masked_text.contains("4509"), "паспорт остался в маске");

    let (status, restored) = http_request_anon(
        &base,
        "/process",
        serde_json::json!({"payload": masked_text, "payload_id": "pair-1"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(restored["result"].as_str().unwrap(), original);
}

/// Ретрай прямого шага не должен ломать корреляцию: эндпоинт идемпотентен.
#[tokio::test]
async fn tz_contract_is_idempotent_on_retry() {
    install_crypto();
    let (upstream, _u) = spawn_mock_upstream().await;
    let (base, _h) = spawn_server(&upstream).await;

    let original = "Телефон +7 912 345-67-89";
    let body = serde_json::json!({"payload": original, "payload_id": "pair-retry"});
    let (_, first) = http_request_anon(&base, "/process", body.clone()).await;
    let (_, second) = http_request_anon(&base, "/process", body).await;
    assert_eq!(first["result"], second["result"]);

    // После двух одинаковых прямых шагов обратный всё ещё работает.
    let masked = first["result"].as_str().unwrap().to_string();
    let (_, restored) = http_request_anon(
        &base,
        "/process",
        serde_json::json!({"payload": masked, "payload_id": "pair-retry"}),
    )
    .await;
    assert_eq!(restored["result"].as_str().unwrap(), original);
}

/// Текст без ПД: оба шага отвечают 200 и той же строкой.
/// Раньше обратный шаг отдавал 404, потому что сессия не создавалась.
#[tokio::test]
async fn tz_contract_handles_text_without_pd() {
    install_crypto();
    let (upstream, _u) = spawn_mock_upstream().await;
    let (base, _h) = spawn_server(&upstream).await;

    let original = "Какая ставка по накопительному счёту?";
    let body = serde_json::json!({"payload": original, "payload_id": "pair-clean"});
    let (status, masked) = http_request_anon(&base, "/process", body.clone()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(masked["result"].as_str().unwrap(), original);

    let (status, restored) = http_request_anon(&base, "/process", body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(restored["result"].as_str().unwrap(), original);
}

/// Анонимный доступ разрешён только при отсутствии заголовков.
/// Неверный ключ — по-прежнему 401.
#[tokio::test]
async fn tz_contract_rejects_wrong_key() {
    install_crypto();
    let (upstream, _u) = spawn_mock_upstream().await;
    let (base, _h) = spawn_server(&upstream).await;

    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .build();
    let client: hyper_util::client::legacy::Client<_, Full<Bytes>> =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new()).build(https);
    let req = Request::builder()
        .method("POST")
        .uri(format!("{base}/process"))
        .header("content-type", "application/json")
        .header("X-System-Id", "crm-assistant")
        .header("X-System-Key", "wrong-key")
        .body(Full::new(Bytes::from(
            serde_json::to_vec(&serde_json::json!({"payload": "тест", "payload_id": "x"})).unwrap(),
        )))
        .unwrap();
    let resp = client.request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn proxy_masks_request_and_demasks_response() {
    install_crypto();
    let (upstream_url, _uh) = spawn_mock_upstream().await;
    let (base, _sh) = spawn_server(&upstream_url).await;

    let body = serde_json::json!({
        "model": "gpt-4",
        "messages": [
            {"role": "user", "content": "Клиент Иванов Иван Иванович, телефон +7 912 345-67-89"}
        ]
    });
    let (status, json) = http_request(&base, "POST", "/proxy/v1/chat/completions", Some(body)).await;
    assert_eq!(status, StatusCode::OK);

    // Ответ демаскирован: оригинальные ПД восстановлены.
    let content = json["choices"][0]["message"]["content"].as_str().unwrap();
    assert!(content.contains("Иванов Иван Иванович"), "response should be demasked: {content}");
    assert!(content.contains("+7 912 345-67-89"), "response should be demasked: {content}");
}

#[tokio::test]
async fn proxy_bypass_route_passes_through() {
    install_crypto();
    let (upstream_url, _uh) = spawn_mock_upstream().await;
    let (base, _sh) = spawn_server(&upstream_url).await;

    let (status, _json) = http_request(&base, "GET", "/proxy/v1/models", None).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn proxy_block_route_forbidden() {
    install_crypto();
    let (upstream_url, _uh) = spawn_mock_upstream().await;
    let (base, _sh) = spawn_server(&upstream_url).await;

    let (status, _json) = http_request(&base, "POST", "/proxy/v1/files/upload", None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn proxy_unauthorized_rejected() {
    install_crypto();
    let (upstream_url, _uh) = spawn_mock_upstream().await;
    let (base, _sh) = spawn_server(&upstream_url).await;

    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .build();
    let client: hyper_util::client::legacy::Client<_, Full<Bytes>> =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new()).build(https);
    let req = Request::builder()
        .method("POST")
        .uri(format!("{base}/proxy/v1/chat/completions"))
        .header("X-System-Id", "crm-assistant")
        .header("X-System-Key", "wrong-key")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = client.request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn proxy_route_not_found() {
    install_crypto();
    let (upstream_url, _uh) = spawn_mock_upstream().await;
    let (base, _sh) = spawn_server(&upstream_url).await;

    let (status, _json) = http_request(&base, "POST", "/proxy/v1/nonexistent", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn batch_endpoint_masks_multiple_texts() {
    install_crypto();
    let (upstream_url, _uh) = spawn_mock_upstream().await;
    let (base, _sh) = spawn_server(&upstream_url).await;

    let body = serde_json::json!({
        "operation": "mask",
        "texts": [
            "Клиент Иванов Иван Иванович",
            "Телефон +7 912 345-67-89",
            "обычный текст без ПД"
        ]
    });
    let (status, json) = http_request(&base, "POST", "/process/batch", Some(body)).await;
    assert_eq!(status, StatusCode::OK);

    let results = json["results"].as_array().unwrap();
    assert_eq!(results.len(), 3);
    assert!(!results[0]["text"].as_str().unwrap().contains("Иванов Иван"));
    assert!(!results[1]["text"].as_str().unwrap().contains("912"));
    assert_eq!(results[2]["text"].as_str().unwrap(), "обычный текст без ПД");
}