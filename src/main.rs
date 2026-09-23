//! Точка входа: сборка зависимостей (DI вручную), запуск.

use std::path::PathBuf;
use std::sync::Arc;

// PERF-08: глобальный аллокатор mimalloc для релизной сборки.
#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use pd_guard::adapter::circuit_breaker::CircuitBreaker;
use pd_guard::adapter::llm_client::{HttpLlmClient, UpstreamConfig};
use pd_guard::adapter::ner_http::HttpNerEngine;
use pd_guard::adapter::vault_memory::MemoryVault;
use pd_guard::config::loader;
use pd_guard::controller::admin_handler::AdminHandler;
use pd_guard::controller::process_handler::ProcessHandler;
use pd_guard::controller::proxy_handler::ProxyHandler;
use pd_guard::controller::router::Router;
use pd_guard::controller::server;
use pd_guard::domain::traits::{
    CombinationRule, ContextScorer, Detector, Masker, MaskKind, NerEngine, RelevanceFilter,
    Resolver, TokenCounter, Validator, Vault,
};
use pd_guard::service::combination::DefaultCombinationRule;
use pd_guard::service::detect::address::AddressDetector;
use pd_guard::service::detect::card::{CardHolderDetector, CardNumberDetector, CvvDetector, PinDetector};
use pd_guard::service::detect::citizenship::CitizenshipDetector;
use pd_guard::service::detect::dates::{DateDetector, NumeralDateDetector};
use pd_guard::service::detect::documents::{BirthPlaceDetector, DriverLicenseDetector, PassportIssuerDetector};
use pd_guard::service::detect::email::EmailDetector;
use pd_guard::service::detect::fio::FioDetector;
use pd_guard::service::detect::inn::InnDetector;
use pd_guard::service::detect::passport::{DivisionCodeDetector, PassportDetector};
use pd_guard::service::detect::phone::PhoneDetector;
use pd_guard::service::detect::snils::SnilsDetector;
use pd_guard::service::guard_service::GuardService;
use pd_guard::service::mask::{HashMasker, PartialMasker, PlaceholderMasker, RedactMasker, SyntheticMasker, TokenMasker};
use pd_guard::service::policy_resolver::PolicyResolver;
use pd_guard::service::relevance::{
    BankAllowlistFilter, NegativeNumberContext, OrgContextFilter, PublicPersonFilter,
};
use pd_guard::service::resolve::DefaultResolver;
use pd_guard::service::tokens::ApproxTokenCounter;
use pd_guard::service::pipeline::PipelineCtx;

fn main() -> anyhow::Result<()> {
    // Устанавливаем CryptoProvider для rustls (HTTPS к upstream).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let config_path = std::env::var("PDG_CONFIG").unwrap_or_else(|_| "config/config.yaml".into());
    let config_path = PathBuf::from(config_path);

    // OPS-02: --check-config — валидация конфига без запуска сервиса (для CI).
    if std::env::args().any(|a| a == "--check-config") {
        match loader::load_from_file(&config_path) {
            Ok(cfg) => {
                println!("config OK (version {})", cfg.version);
                return Ok(());
            }
            Err(e) => {
                eprintln!("config INVALID: {e}");
                std::process::exit(1);
            }
        }
    }

    let cfg = loader::load_from_file(&config_path)?;
    let cfg = Arc::new(cfg);

    // Логирование.
    pd_guard::infra::logging::init(&cfg.raw.logging.level, &cfg.raw.logging.format);

    // Мастер-ключ.
    let master_key = pd_guard::infra::crypto::MasterKey::from_base64(&cfg.master_key_b64)?;

    // Vault.
    let ttl = std::time::Duration::from_secs(cfg.raw.vault.ttl_seconds);
    let vault: Arc<dyn Vault> = match cfg.raw.vault.mode.as_str() {
        "memory" => Arc::new(MemoryVault::new(ttl, cfg.raw.vault.max_entries)),
        "stateless" => Arc::new(MemoryVault::new(ttl, cfg.raw.vault.max_entries)),
        "redis" => {
            #[cfg(feature = "redis")]
            {
                let url = cfg.raw.vault.redis_url.clone();
                Arc::new(pd_guard::adapter::vault_redis::RedisVault::new(&url)?)
            }
            #[cfg(not(feature = "redis"))]
            {
                anyhow::bail!("redis vault requires feature 'redis'");
            }
        }
        other => anyhow::bail!("unknown vault mode: {other}"),
    };

    // Детекторы.
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
    registry.register(Arc::new(DriverLicenseDetector::new()));
    registry.register(Arc::new(BirthPlaceDetector::new(cfg.cities.clone(), cfg.countries.clone())));
    registry.register(Arc::new(PassportIssuerDetector::new(cfg.issuing_authorities.clone())));
    registry.register(Arc::new(pd_guard::service::detect::structured::StructuredFieldDetector::new()));

    // Конфиг-детекторы.
    for (t, tc) in &cfg.raw.pd_types {
        if let Some(d) = &tc.detector {
            let det = pd_guard::service::detect::ConfigRegexDetector::new(
                t.clone(),
                d,
                cfg.detector_regexes.get(t).cloned().unwrap(),
            );
            registry.register(Arc::new(det));
        }
    }

    let detectors: Vec<Arc<dyn Detector>> = registry.detectors.clone();

    // Валидаторы.
    let validators: Vec<Arc<dyn Validator>> = vec![
        Arc::new(pd_guard::service::detect::validators::LuhnValidator),
        Arc::new(pd_guard::service::detect::validators::InnValidator),
        Arc::new(pd_guard::service::detect::validators::SnilsValidator),
        Arc::new(pd_guard::service::detect::validators::DateValidator),
        Arc::new(pd_guard::service::detect::validators::PassportSeriesValidator),
    ];

    // Контекстные скореры.
    let context_scorers: Vec<Arc<dyn ContextScorer>> = Vec::new();

    // NER.
    let ner: Option<Arc<dyn NerEngine>> = match cfg.raw.ner.engine.as_str() {
        "disabled" => None,
        "http" => {
            let cb = Arc::new(CircuitBreaker::new(
                cfg.raw.ner.circuit_breaker.failure_ratio,
                cfg.raw.ner.circuit_breaker.window,
                cfg.raw.ner.circuit_breaker.open_seconds,
            ));
            Some(Arc::new(HttpNerEngine::new(
                cfg.raw.ner.http.url.clone(),
                cfg.raw.ner.http.timeout_ms,
                Some(cb),
            )))
        }
        "onnx" => {
            #[cfg(feature = "ner-onnx")]
            {
                Some(Arc::new(pd_guard::adapter::ner_onnx::OnnxNerEngine::new(
                    &cfg.raw.ner.onnx.model_path,
                    &cfg.raw.ner.onnx.tokenizer_path,
                )?))
            }
            #[cfg(not(feature = "ner-onnx"))]
            {
                anyhow::bail!("onnx NER requires feature 'ner-onnx'");
            }
        }
        other => anyhow::bail!("unknown ner engine: {other}"),
    };

    // Фильтры.
    let filters: Vec<Arc<dyn RelevanceFilter>> = vec![
        Arc::new(PublicPersonFilter {
            persons: cfg.public_persons.clone(),
        }),
        Arc::new(BankAllowlistFilter::new(
            cfg.bank_offices.clone(),
            cfg.bank_phones.clone(),
        )),
        Arc::new(OrgContextFilter),
        Arc::new(NegativeNumberContext),
    ];

    // Resolver, combination.
    let resolver: Arc<dyn Resolver> = Arc::new(DefaultResolver);
    let combination: Arc<dyn CombinationRule> = Arc::new(DefaultCombinationRule);

    // Маскеры по виду.
    let mut maskers_by_kind: std::collections::HashMap<MaskKind, Arc<dyn Masker>> = std::collections::HashMap::new();
    let placeholder = Arc::new(PlaceholderMasker {
        format: cfg.placeholder_format.clone(),
        labels: cfg.labels.clone(),
    });
    let redact: Arc<dyn Masker> = Arc::new(RedactMasker);
    let partial: Arc<dyn Masker> = Arc::new(PartialMasker { keep_last: 4 });
    let token: Arc<dyn Masker> = Arc::new(TokenMasker {
        secret: master_key_bytes(&master_key),
    });
    let hash: Arc<dyn Masker> = Arc::new(HashMasker);
    let synthetic: Arc<dyn Masker> = Arc::new(SyntheticMasker {
        secret: master_key_bytes(&master_key),
        first_names: cfg.first_names.clone(),
        surnames: vec![
            "Иванов".into(), "Петров".into(), "Сидоров".into(), "Смирнов".into(),
            "Кузнецов".into(), "Попов".into(), "Васильев".into(), "Соколов".into(),
            "Михайлов".into(), "Новиков".into(), "Федоров".into(), "Морозов".into(),
        ],
    });

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
        ner,
        filters,
        resolver,
        combination,
        maskers_by_kind,
        default_masker: placeholder,
        prefilter_regex_set: cfg.prefilter_regex_set.clone(),
    });

    // LlmClient.
    let mut upstreams = std::collections::HashMap::new();
    let mut cbs = std::collections::HashMap::new();
    for (id, uc) in &cfg.upstreams {
        upstreams.insert(
            id.clone(),
            UpstreamConfig {
                url: uc.url.clone(),
                auth_header: uc.auth_header.clone(),
                auth_value: loader::resolve_secret(&uc.auth_value)?,
                timeout_ms: uc.timeout_ms,
                pass_headers: uc.pass_headers.clone(),
            },
        );
        cbs.insert(
            id.clone(),
            Arc::new(CircuitBreaker::new(0.5, 20, 10)),
        );
    }
    let llm: Option<Arc<dyn pd_guard::domain::traits::LlmClient>> = if upstreams.is_empty() {
        None
    } else {
        Some(Arc::new(HttpLlmClient::new(upstreams, cbs)))
    };

    let service = Arc::new(GuardService {
        pipeline,
        vault,
        llm,
        master_key,
        vault_mode: cfg.raw.vault.mode.clone(),
        ttl,
        delete_after_demask: cfg.raw.vault.delete_after_demask,
        heavy_text_threshold_bytes: cfg.raw.server.heavy_text_threshold_bytes,
    });

    let resolver = Arc::new(PolicyResolver::new(cfg.clone()));
    let token_counter: Arc<dyn TokenCounter> = Arc::new(ApproxTokenCounter::default());

    let process = ProcessHandler {
        cfg: cfg.clone(),
        service: service.clone(),
        resolver: resolver.clone(),
        token_counter,
        inflight: pd_guard::controller::middleware::InflightGuard::new(cfg.raw.server.max_inflight),
        rate_limiter: Arc::new(pd_guard::infra::rate_limit::RateLimiter::new()),
    };
    let proxy = ProxyHandler {
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
    let admin = AdminHandler {
        cfg: cfg.clone(),
        vault_health,
        reload: {
            let resolver = resolver.clone();
            let config_path = config_path.clone();
            Arc::new(move || -> Result<(), String> {
                match loader::load_from_file(&config_path) {
                    Ok(new_cfg) => {
                        resolver.swap(Arc::new(new_cfg));
                        tracing::info!("config reloaded");
                        Ok(())
                    }
                    Err(e) => {
                        pd_guard::infra::metrics::inc_config_reload_failures();
                        tracing::error!(error = %e, "config reload failed");
                        Err(e.to_string())
                    }
                }
            })
        },
    };

    let reload_for_watch = admin.reload.clone();
    let router = Arc::new(Router { process, proxy, admin });

    // Запуск.
    // Recorder ставим до старта runtime: макросы metrics::* пишут в него сразу.
    pd_guard::infra::metrics::install()?;

    let rt = tokio::runtime::Runtime::new()?;
    let result = rt.block_on(async {
        pd_guard::infra::metrics::spawn_upkeep();

        // Служебный порт: метрики и перезагрузка конфига, отдельно от публичного.
        {
            let admin_listen = cfg.raw.server.admin_listen.clone();
            let router = router.clone();
            tokio::spawn(async move {
                if let Err(e) = server::serve_kind(&admin_listen, router, true).await {
                    tracing::error!(error = %e, "admin listener stopped");
                }
            });
        }
        // OPS-01: горячая перезагрузка конфига по изменению файла.
        // Watcher живёт на отдельном потоке: он блокируется на recv(), а внутри
        // tokio-задачи это намертво занимало бы воркер рантайма.
        let reload = reload_for_watch;
        let config_path = config_path.clone();
        std::thread::Builder::new()
            .name("config-watcher".into())
            .spawn(move || watch_config(&config_path, reload))
            .ok();
        server::run(&cfg.raw.server.listen, router).await
    });

    // Без явного завершения процесс висит после SIGTERM: фоновые задачи
    // (watcher конфига, upkeep метрик, moka) не дают runtime закрыться.
    // Даём долететь запросам, которые уже в обработке.
    rt.shutdown_timeout(std::time::Duration::from_secs(2));
    tracing::info!("stopped");
    result
}

/// OPS-01: наблюдает за файлом конфига через notify и перезагружает при изменении.
/// Блокирующий цикл наблюдения за файлом конфига. Запускается на своём потоке.
fn watch_config(
    config_path: &std::path::Path,
    reload: Arc<dyn Fn() -> Result<(), String> + Send + Sync>,
) {
    use notify::{RecommendedWatcher, RecursiveMode, Watcher};
    let (tx, rx) = std::sync::mpsc::channel();
    let mut watcher: RecommendedWatcher = match notify::recommended_watcher(tx) {
        Ok(w) => w,
        Err(e) => {
            tracing::error!(error = %e, "failed to create config watcher");
            return;
        }
    };
    let watch_path = config_path.to_path_buf();
    if let Err(e) = watcher.watch(&watch_path, RecursiveMode::NonRecursive) {
        tracing::error!(error = %e, path = %watch_path.display(), "failed to watch config");
        return;
    }
    tracing::info!(path = %watch_path.display(), "watching config for changes");
    loop {
        match rx.recv() {
            Ok(Ok(notify::Event { kind, .. })) => {
                let is_modify = matches!(
                    kind,
                    notify::EventKind::Modify(_) | notify::EventKind::Create(_)
                );
                if is_modify {
                    // Небольшая задержка, чтобы файл успел записаться.
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    match reload() {
                        Ok(()) => {
                            pd_guard::infra::metrics::set_config_version(1);
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "config reload on file change failed");
                        }
                    }
                }
            }
            Ok(Err(e)) => {
                tracing::error!(error = %e, "config watcher event error");
            }
            Err(e) => {
                // Отправитель уничтожен — сервис завершается, поток тоже.
                tracing::debug!(error = %e, "config watcher stopped");
                return;
            }
        }
    }
}

fn master_key_bytes(master: &pd_guard::infra::crypto::MasterKey) -> Vec<u8> {
    master.expose().to_vec()
}