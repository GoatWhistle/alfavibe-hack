//! Интеграционные тесты: mask/demask roundtrip, auth, политики.

use std::sync::Arc;
use std::time::{Duration, Instant};

use pd_guard::adapter::vault_memory::MemoryVault;
use pd_guard::config::loader;
use pd_guard::domain::traits::{CombinationRule, Detector, Masker, MaskKind, RelevanceFilter, Resolver, Validator, Vault};
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
use pd_guard::service::relevance::{BankAllowlistFilter, NegativeNumberContext, OrgContextFilter, PublicPersonFilter};
use pd_guard::service::resolve::DefaultResolver;

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

    let cfg = loader::load_from_str(cfg_yaml, std::path::Path::new(".")).unwrap();
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

fn base64_encode_32() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes)
}

fn sha256_hex(s: &str) -> String {
    pd_guard::infra::crypto::sha256_hex(s.as_bytes())
}

#[tokio::test]
async fn mask_demask_roundtrip() {
    let (service, cfg) = build_service();
    let resolver = pd_guard::service::policy_resolver::PolicyResolver::new(cfg.clone());
    let policy = resolver.resolve("crm-assistant", None).unwrap();
    let deadline = Instant::now() + Duration::from_secs(1);

    let text = "Клиент Иванов Иван Иванович, паспорт 4509 123456, телефон +7 912 345-67-89, email ivanov@mail.ru, карта 4532 0151 1283 0366";
    let mask_result = service.mask(&policy, "crm-assistant", text, None, deadline, false).await.unwrap();

    // Маскированный текст не содержит исходных значений.
    assert!(!mask_result.text.contains("Иванов Иван"));
    assert!(!mask_result.text.contains("4509 123456"));
    assert!(!mask_result.text.contains("4532 0151 1283 0366"));

    // Демаскирование возвращает оригинал.
    let demask_result = service
        .demask(&policy, "crm-assistant", &mask_result.text, &mask_result.session_id, None, deadline)
        .await
        .unwrap();
    assert_eq!(demask_result.text, text);
    assert_eq!(demask_result.restored, 5);
}

#[tokio::test]
async fn mask_does_not_leak_pd() {
    let (service, cfg) = build_service();
    let resolver = pd_guard::service::policy_resolver::PolicyResolver::new(cfg.clone());
    let policy = resolver.resolve("crm-assistant", None).unwrap();
    let deadline = Instant::now() + Duration::from_secs(1);

    let text = "Клиент Иванов Иван, телефон +7 912 345-67-89";
    let mask_result = service.mask(&policy, "crm-assistant", text, None, deadline, false).await.unwrap();
    assert!(!mask_result.text.contains("Иванов"));
    assert!(!mask_result.text.contains("912"));
}

#[tokio::test]
async fn pin_requires_card() {
    let (service, cfg) = build_service();
    let resolver = pd_guard::service::policy_resolver::PolicyResolver::new(cfg.clone());
    let policy = resolver.resolve("crm-assistant", None).unwrap();
    let deadline = Instant::now() + Duration::from_secs(1);

    // PIN без карты — не маскируется.
    let text = "Пин-код 1234";
    let mask_result = service.mask(&policy, "crm-assistant", text, None, deadline, false).await.unwrap();
    assert!(mask_result.text.contains("1234"));

    // PIN с картой — маскируется.
    let text2 = "Карта 4532 0151 1283 0366, пин-код 1234";
    let mask_result2 = service.mask(&policy, "crm-assistant", text2, None, deadline, false).await.unwrap();
    assert!(!mask_result2.text.contains("1234"));
}

#[tokio::test]
async fn public_person_not_masked() {
    let (service, cfg) = build_service();
    let resolver = pd_guard::service::policy_resolver::PolicyResolver::new(cfg.clone());
    let policy = resolver.resolve("crm-assistant", None).unwrap();
    let deadline = Instant::now() + Duration::from_secs(1);

    // Пушкин-поэт не маскируется.
    let text = "Александр Сергеевич Пушкин — великий поэт";
    let mask_result = service.mask(&policy, "crm-assistant", text, None, deadline, false).await.unwrap();
    assert!(mask_result.text.contains("Пушкин"));
}

#[tokio::test]
async fn multiple_entities_same_type_get_distinct_placeholders() {
    let (service, cfg) = build_service();
    let resolver = pd_guard::service::policy_resolver::PolicyResolver::new(cfg.clone());
    let policy = resolver.resolve("crm-assistant", None).unwrap();
    let deadline = Instant::now() + Duration::from_secs(1);

    // Два разных человека — разные плейсхолдеры.
    let text = "Клиенты Иванов Иван и Петров Петр";
    let mask_result = service.mask(&policy, "crm-assistant", text, None, deadline, false).await.unwrap();
    assert!(mask_result.text.contains("[ФИО_1]"));
    assert!(mask_result.text.contains("[ФИО_2]"));

    // Один и тот же человек дважды — один плейсхолдер.
    let text2 = "Иванов Иван и снова Иванов Иван";
    let mask_result2 = service.mask(&policy, "crm-assistant", text2, None, deadline, false).await.unwrap();
    let count = mask_result2.text.matches("[ФИО_1]").count();
    assert_eq!(count, 2, "same person twice should get same placeholder");
}

#[tokio::test]
async fn address_detected() {
    let (service, cfg) = build_service();
    let resolver = pd_guard::service::policy_resolver::PolicyResolver::new(cfg.clone());
    let policy = resolver.resolve("crm-assistant", None).unwrap();
    let deadline = Instant::now() + Duration::from_secs(1);

    let text = "Проживает по адресу: г. Москва, ул. Тверская, д. 12, кв. 34";
    let mask_result = service.mask(&policy, "crm-assistant", text, None, deadline, false).await.unwrap();
    // Адрес должен быть замаскирован (не содержать "Тверская").
    assert!(!mask_result.text.contains("Тверская"), "street should be masked: {}", mask_result.text);
}

#[tokio::test]
async fn driver_license_detected() {
    let (service, cfg) = build_service();
    let resolver = pd_guard::service::policy_resolver::PolicyResolver::new(cfg.clone());
    let policy = resolver.resolve("crm-assistant", None).unwrap();
    let deadline = Instant::now() + Duration::from_secs(1);

    let text = "Водительское удостоверение 77 12 345678";
    let mask_result = service.mask(&policy, "crm-assistant", text, None, deadline, false).await.unwrap();
    assert!(!mask_result.text.contains("345678"), "driver license should be masked");
}

#[tokio::test]
async fn word_boundary_context_does_not_false_negative() {
    // DET-04: «тип», «принцип», «хаос» не должны ломать детекцию ИНН/ФИО.
    let (service, cfg) = build_service();
    let resolver = pd_guard::service::policy_resolver::PolicyResolver::new(cfg.clone());
    let policy = resolver.resolve("crm-assistant", None).unwrap();
    let deadline = Instant::now() + Duration::from_secs(1);

    // ИНН физлица рядом со словом «тип» не должен классифицироваться как ИНН организации.
    let text = "Тип операции, ИНН 500100732259";
    let mask_result = service.mask(&policy, "crm-assistant", text, None, deadline, false).await.unwrap();
    assert!(!mask_result.text.contains("500100732259"), "INN should be masked: {}", mask_result.text);

    // «хаос» не должен срабатывать как «ао» (ИНН организации).
    let text2 = "Хаос в данных, ИНН 500100732259";
    let mask_result2 = service.mask(&policy, "crm-assistant", text2, None, deadline, false).await.unwrap();
    assert!(!mask_result2.text.contains("500100732259"), "INN should be masked: {}", mask_result2.text);
}

#[tokio::test]
async fn structured_field_detected() {
    // DET-03: имя поля как сильный контекстный сигнал.
    let (service, cfg) = build_service();
    let resolver = pd_guard::service::policy_resolver::PolicyResolver::new(cfg.clone());
    let policy = resolver.resolve("crm-assistant", None).unwrap();
    let deadline = Instant::now() + Duration::from_secs(1);

    let text = r#"{"passport": "4509 123456", "phone": "+7 912 345-67-89"}"#;
    let result = service.mask(&policy, "crm-assistant", text, None, deadline, false).await.unwrap();
    assert!(!result.text.contains("4509 123456"), "passport should be masked: {}", result.text);
    assert!(!result.text.contains("912 345-67-89"), "phone should be masked: {}", result.text);
}

#[tokio::test]
async fn dry_run_returns_entities_without_masking() {
    // FEAT-05: dry_run возвращает перечень того, что было бы замаскировано,
    // без изменения текста и без записи маппинга.
    let (service, cfg) = build_service();
    let resolver = pd_guard::service::policy_resolver::PolicyResolver::new(cfg.clone());
    let policy = resolver.resolve("crm-assistant", None).unwrap();
    let deadline = Instant::now() + Duration::from_secs(1);

    let text = "Клиент Иванов Иван Иванович, телефон +7 912 345-67-89";
    let result = service.mask(&policy, "crm-assistant", text, None, deadline, true).await.unwrap();

    // Текст не изменён.
    assert_eq!(result.text, text);
    // Маппинг пуст (не записывается).
    assert!(result.mapping.entries.is_empty());
    // Сущности найдены.
    assert!(!result.entities.is_empty());
    let types: Vec<&str> = result.entities.iter().map(|e| e.pd_type.as_str()).collect();
    assert!(types.contains(&"FIO"));
    assert!(types.contains(&"PHONE"));
}

#[tokio::test]
async fn stateless_demask_roundtrip() {
    // FEAT-02: stateless-демаскирование через mask_context (без vault).
    let (service, cfg) = build_service();
    let resolver = pd_guard::service::policy_resolver::PolicyResolver::new(cfg.clone());
    let policy = resolver.resolve("crm-assistant", None).unwrap();
    let deadline = Instant::now() + Duration::from_secs(1);

    // Пересобираем сервис в stateless-режиме.
    let mut service = service;
    Arc::get_mut(&mut service).unwrap().vault_mode = "stateless".into();

    let text = "Клиент Иванов Иван Иванович, телефон +7 912 345-67-89";
    let mask_result = service.mask(&policy, "crm-assistant", text, None, deadline, false).await.unwrap();
    assert!(mask_result.mask_context.is_some(), "stateless mode should return mask_context");

    // Демаскирование на «другой реплике» — только по mask_context.
    let demask_result = service
        .demask(&policy, "crm-assistant", &mask_result.text, &mask_result.session_id, mask_result.mask_context.as_deref(), deadline)
        .await
        .unwrap();
    assert_eq!(demask_result.text, text);
}

proptest::proptest! {
    #[test]
    fn demask_mask_roundtrip_prop(
        name in proptest::string::string_regex("Иванов Иван Иванович|Петров Петр Петрович|Сидорова Анна Сергеевна").unwrap(),
        phone in proptest::string::string_regex("\\+7 9[0-9]{2} [0-9]{3}-[0-9]{2}-[0-9]{2}").unwrap(),
        email in proptest::string::string_regex("[a-z]+@[a-z]+\\.[a-z]{2,3}").unwrap(),
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (service, cfg) = build_service();
            let resolver = pd_guard::service::policy_resolver::PolicyResolver::new(cfg.clone());
            let policy = resolver.resolve("crm-assistant", None).unwrap();
            let deadline = Instant::now() + Duration::from_secs(1);
            let text = format!("Клиент {name}, телефон {phone}, email {email}");
            let mask_result = service.mask(&policy, "crm-assistant", &text, None, deadline, false).await.unwrap();
            let demask_result = service.demask(&policy, "crm-assistant", &mask_result.text, &mask_result.session_id, None, deadline).await.unwrap();
            assert_eq!(demask_result.text, text);
        });
    }
}