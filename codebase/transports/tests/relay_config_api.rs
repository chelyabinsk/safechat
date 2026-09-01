use safechat_transports::relay_client::RelayClientConfig;

#[test]
fn relay_configuration_builder_keeps_secure_defaults_and_explicit_opt_ins() {
    let config = RelayClientConfig::new("https://relay.example", "client", "secret");
    assert_eq!(config.base_url, "https://relay.example");
    assert!(!config.allow_insecure_http);
    assert!(config.ca_certificate_pem.is_none());

    let config = config
        .with_ca_certificate(b"certificate".to_vec())
        .with_insecure_http(true);
    assert_eq!(
        config.ca_certificate_pem.as_deref(),
        Some(b"certificate".as_slice())
    );
    assert!(config.allow_insecure_http);
}
