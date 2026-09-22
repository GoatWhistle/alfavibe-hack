use pd_guard::config::loader;

#[test]
fn payments_bot_policy() {
    std::env::set_var("PDG_MASTER_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
    std::env::set_var("PDG_KEY_CRM_SHA256", "abc");
    std::env::set_var("PDG_KEY_PAY_SHA256", "abc");
    std::env::set_var("PDG_KEY_ANALYTICS_SHA256", "abc");
    std::env::set_var("PDG_ADMIN_TOKEN_SHA256", "abc");
    std::env::set_var("PDG_LLM_TOKEN", "abc");
    let cfg = loader::load_from_file(std::path::Path::new("config/config.yaml")).unwrap();
    let cfg = std::sync::Arc::new(cfg);
    let resolver = pd_guard::service::policy_resolver::PolicyResolver::new(cfg.clone());
    let p = resolver.resolve("payments-bot", None).unwrap();
    println!("payments-bot demask: {}", p.demask);
    println!("sys_demask: {:?}", cfg.system_demask.get("payments-bot"));
    println!("cards_only profile demask: {:?}", cfg.profiles.get("cards_only").map(|p| p.demask));
    assert!(p.demask, "payments-bot demask should be true");
}
