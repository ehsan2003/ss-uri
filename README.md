a shadowsocks uri parser inspired by https://github.com/Jigsaw-Code/outline-shadowsocksconfig

this crate uses the same algorithm and passes the same tests of what outline uses so it is compatible with what outline expects

example usage :

```rust
use ss_uri::SSConfig;
use url::Host;
use ss_uri::Method;
let config = SSConfig::parse("ss://YWVzLTEyOC1nY206dGVzdA@192.168.100.1:8888#Foo%20Bar").unwrap();

assert_eq!(config.method, Method::Aes128Gcm);
assert_eq!(config.password,"test");
assert_eq!(config.host, Host::parse("192.168.100.1").unwrap());
assert_eq!(config.port, 8888);
assert_eq!(config.tag, Some("Foo Bar".to_string()));

assert_eq!(config.to_sip002(),"ss://YWVzLTEyOC1nY206dGVzdA@192.168.100.1:8888#Foo%20Bar")
```

a cli tool generating ss-local config based on this parser : https://github.com/ehsan2003/ss-uri-cli
