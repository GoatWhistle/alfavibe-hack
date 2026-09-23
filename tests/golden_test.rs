//! QA-01: золотой набор и метрики качества по типам (precision/recall/F1).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use pd_guard::adapter::vault_memory::MemoryVault;
use pd_guard::config::loader;
use pd_guard::domain::traits::{
    CombinationRule, Detector, Masker, MaskKind, RelevanceFilter, Resolver, Validator, Vault,
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
use pd_guard::service::mask::{HashMasker, PartialMasker, PlaceholderMasker, RedactMasker, TokenMasker};
use pd_guard::service::pipeline::PipelineCtx;
use pd_guard::service::policy_resolver::PolicyResolver;
use pd_guard::service::relevance::{BankAllowlistFilter, NegativeNumberContext, OrgContextFilter, PublicPersonFilter};
use pd_guard::service::resolve::DefaultResolver;

fn base64_encode_32() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes)
}

fn sha256_hex(s: &str) -> String {
    pd_guard::infra::crypto::sha256_hex(s.as_bytes())
}

fn build_service() -> (Arc<GuardService>, Arc<pd_guard::config::compiled::CompiledConfig>) {
    let cfg_yaml = r#"
version: 1
server:
  listen: "0.0.0.0:8080"
  admin_listen: "127.0.0.1:9090"
security:
  master_key: "env:PDG_MASTER_KEY"
  auth_header: "X-System-Key"
  system_id_header: "X-System-Id"
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
  FIO:            { label: "ФИО",       priority: 50,  threshold: 0.7 }
  BIRTH_DATE:     { label: "ДАТА_РОЖД", priority: 70,  threshold: 0.6 }
  PASSPORT:       { label: "ПАСПОРТ",   priority: 90,  threshold: 0.6 }
  EMAIL:          { label: "EMAIL",     priority: 80,  threshold: 0.6 }
  PHONE:          { label: "ТЕЛЕФОН",   priority: 80,  threshold: 0.6 }
  INN:            { label: "ИНН",       priority: 95,  threshold: 0.6 }
  CARD_NUMBER:    { label: "КАРТА",     priority: 100, threshold: 0.7 }
  CVV:            { label: "CVV",       priority: 40,  threshold: 0.6 }
  PIN:            { label: "ПИН",       priority: 40,  threshold: 0.6 }
  CARD_HOLDER:    { label: "ДЕРЖАТЕЛЬ", priority: 52,  threshold: 0.6 }
  SNILS:          { label: "СНИЛС",     priority: 90,  threshold: 0.6 }
  DRIVER_LICENSE: { label: "ВУ",        priority: 85,  threshold: 0.6 }
  ADDRESS:        { label: "АДРЕС",     priority: 60,  threshold: 0.6 }
  ADDR_CITY:      { label: "ГОРОД",     priority: 45,  threshold: 0.6 }
  ADDR_STREET:    { label: "УЛИЦА",     priority: 45,  threshold: 0.6 }
  ADDR_HOUSE:     { label: "ДОМ",       priority: 45,  threshold: 0.6 }
  ADDR_FLAT:      { label: "КВ",        priority: 45,  threshold: 0.6 }
  DATE:           { label: "ДАТА",      priority: 10,  threshold: 0.6 }
  ORG_INN:        { label: "ИНН_ОРГ",   priority: 95,  threshold: 0.6 }
  UNCLASSIFIED_ID: { label: "ID",       priority: 5,   threshold: 0.6 }
profiles:
  strict:
    types:
      FIO:             { mask: placeholder }
      BIRTH_DATE:      { mask: placeholder }
      PASSPORT:        { mask: placeholder }
      EMAIL:           { mask: placeholder }
      PHONE:           { mask: placeholder }
      INN:             { mask: placeholder }
      CARD_NUMBER:     { mask: partial, keep_last: 4 }
      CVV:             { mask: redact }
      PIN:             { mask: redact }
      CARD_HOLDER:     { mask: placeholder }
      SNILS:           { mask: placeholder }
      DRIVER_LICENSE:  { mask: placeholder }
      ADDRESS:         { mask: placeholder, mode: components }
    ner: { enabled: false }
    filters: [public_persons, bank_allowlist, org_context, negative_number_context]
    combination:
      rules:
        PIN: { requires_any: [CARD_NUMBER], scope: document }
      min_distinct_types: 1
      always_mask: [CARD_NUMBER, PASSPORT, INN]
    ambiguous_ids: mask
    demask: true
defaults:
  profile: strict
  placeholder: { format: "[{label}_{n}]" }
  action: mask
systems:
  crm-assistant:
    enabled: true
    key_sha256: "env:PDG_KEY_CRM_SHA256"
    profile: strict
    demask: true
upstreams: {}
routes: []
"#;

    std::env::set_var("PDG_MASTER_KEY", base64_encode_32());
    std::env::set_var("PDG_KEY_CRM_SHA256", sha256_hex("test-key"));
    std::env::set_var("PDG_KEY_PAY_SHA256", sha256_hex("test-key"));
    std::env::set_var("PDG_KEY_ANALYTICS_SHA256", sha256_hex("test-key"));
    std::env::set_var("PDG_ADMIN_TOKEN_SHA256", sha256_hex("test-admin"));
    std::env::set_var("PDG_LLM_TOKEN", "unused");
    std::env::set_var("PDG_REDIS_URL", "redis://127.0.0.1:6379");

    // Проверяем ровно тот конфиг, с которым сервис едет в прод: своя копия
    // правил внутри теста незаметно расходится с боевой.
    let _ = cfg_yaml;
    let cfg = loader::load_from_file(std::path::Path::new("config/config.yaml")).unwrap();
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
    let mut maskers_by_kind: std::collections::HashMap<MaskKind, Arc<dyn Masker>> = std::collections::HashMap::new();
    maskers_by_kind.insert(MaskKind::Placeholder, placeholder.clone());
    maskers_by_kind.insert(MaskKind::Redact, redact.clone());
    maskers_by_kind.insert(MaskKind::Partial, partial.clone());
    maskers_by_kind.insert(MaskKind::Token, token.clone());
    maskers_by_kind.insert(MaskKind::Hash, hash.clone());

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

    let service = Arc::new(GuardService {
        pipeline,
        vault,
        llm: None,
        master_key,
        vault_mode: "memory".into(),
        ttl: Duration::from_secs(900),
        delete_after_demask: false,
        heavy_text_threshold_bytes: 65536,
    });

    (service, cfg)
}

#[derive(serde::Deserialize)]
struct GoldenSample {
    text: String,
    entities: Vec<GoldenEntity>,
}

#[derive(serde::Deserialize)]
struct GoldenEntity {
    r#type: String,
    start: usize,
    end: usize,
}

#[tokio::test]
async fn golden_set_quality() {
    let (service, cfg) = build_service();
    let resolver = PolicyResolver::new(cfg.clone());
    let policy = resolver.resolve("crm-assistant", None).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);

    let content = std::fs::read_to_string("tests/golden/golden.jsonl").unwrap();
    let mut per_type: HashMap<String, (usize, usize, usize)> = HashMap::new(); // tp, fp, fn

    for line in content
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
    {
        let sample: GoldenSample = serde_json::from_str(line).unwrap();
        let result = service.mask(&policy, "crm-assistant", &sample.text, None, deadline, false).await.unwrap();

        // Детектированные сущности.
        let mut detected: Vec<(String, usize, usize)> = result
            .entities
            .iter()
            .map(|e| (e.pd_type.clone(), e.start, e.end))
            .collect();
        detected.sort_by_key(|e| (e.0.clone(), e.1));

        // Ожидаемые.
        let mut expected: Vec<(String, usize, usize)> = sample
            .entities
            .iter()
            .map(|e| (e.r#type.clone(), e.start, e.end))
            .collect();
        expected.sort_by_key(|e| (e.0.clone(), e.1));

        // Сопоставление по (type, start, end).
        let mut used = vec![false; expected.len()];
        for d in &detected {
            let mut matched = false;
            for (i, e) in expected.iter().enumerate() {
                if !used[i] && e.0 == d.0 && e.1 == d.1 && e.2 == d.2 {
                    used[i] = true;
                    matched = true;
                    break;
                }
            }
            let entry = per_type.entry(d.0.clone()).or_insert((0, 0, 0));
            if matched {
                entry.0 += 1; // tp
            } else {
                entry.1 += 1; // fp
            }
        }
        for (i, e) in expected.iter().enumerate() {
            if !used[i] {
                let entry = per_type.entry(e.0.clone()).or_insert((0, 0, 0));
                entry.2 += 1; // fn
            }
        }
    }

    // Отчёт по типам.
    let mut total_tp = 0usize;
    let mut total_fp = 0usize;
    let mut total_fn = 0usize;
    println!("=== Golden set quality report ===");
    let mut types: Vec<&String> = per_type.keys().collect();
    types.sort();
    for t in &types {
        let (tp, fp, fn_) = per_type[*t];
        total_tp += tp;
        total_fp += fp;
        total_fn += fn_;
        let precision = if tp + fp > 0 { tp as f64 / (tp + fp) as f64 } else { 1.0 };
        let recall = if tp + fn_ > 0 { tp as f64 / (tp + fn_) as f64 } else { 1.0 };
        let f1 = if precision + recall > 0.0 { 2.0 * precision * recall / (precision + recall) } else { 0.0 };
        println!("{t}: precision={precision:.3} recall={recall:.3} f1={f1:.3} (tp={tp} fp={fp} fn={fn_})");
    }
    let precision = if total_tp + total_fp > 0 { total_tp as f64 / (total_tp + total_fp) as f64 } else { 1.0 };
    let recall = if total_tp + total_fn > 0 { total_tp as f64 / (total_tp + total_fn) as f64 } else { 1.0 };
    let f1 = if precision + recall > 0.0 { 2.0 * precision * recall / (precision + recall) } else { 0.0 };
    println!("OVERALL: precision={precision:.3} recall={recall:.3} f1={f1:.3}");

    // Порог: F1 >= 0.95 по каждому типу и суммарно.
    for t in &types {
        let (tp, fp, fn_) = per_type[*t];
        let p = if tp + fp > 0 { tp as f64 / (tp + fp) as f64 } else { 1.0 };
        let r = if tp + fn_ > 0 { tp as f64 / (tp + fn_) as f64 } else { 1.0 };
        let f = if p + r > 0.0 { 2.0 * p * r / (p + r) } else { 0.0 };
        assert!(f >= 0.95, "type {t} F1 {f:.3} below threshold 0.95");
    }
    assert!(f1 >= 0.95, "overall F1 {f1:.3} below threshold 0.95");
}