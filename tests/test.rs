use ss_uri::Method;
use ss_uri::SSConfig;
use url::Host;
fn main() {
    let config =
        SSConfig::parse("ss://YWVzLTEyOC1nY206dGVzdA@192.168.100.1:8888#Foo%20Bar").unwrap();

    assert_eq!(config.method, Method::Aes128Gcm);
    assert_eq!(config.password, "test");
    assert_eq!(config.host, Host::parse("192.168.100.1").unwrap());
    assert_eq!(config.port, 8888);
    assert_eq!(config.tag, Some("Foo Bar".to_string()));

    assert_eq!(
        config.to_sip002(),
        "ss://YWVzLTEyOC1nY206dGVzdA@192.168.100.1:8888#Foo%20Bar"
    )
}
