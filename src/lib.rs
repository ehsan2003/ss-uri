use core::fmt;
use percent_encoding::{percent_decode_str, NON_ALPHANUMERIC};
use std::collections::HashMap;
pub use url;
use url::{Host, Url};
mod method;
mod sip008;

pub use method::{Method, MethodParseError};
pub use sip008::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SSConfig {
    pub host: Host,
    pub port: u16,
    pub method: Method,
    pub password: String,
    pub tag: Option<String>,
    pub extra: Option<HashMap<String, String>>,
}
#[derive(Debug, PartialEq, Clone, Copy, Hash)]
pub enum SSParseError {
    InvalidUrl,
    InvalidProtocol,
    InvalidHost,
    InvalidPort,
    InvalidMethod,
    InvalidPassword,
}
impl fmt::Display for SSParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl std::error::Error for SSParseError {}

impl SSConfig {
    /// converts SSConfig to legacy base64 shadowsocks uri
    /// ```
    /// use ss_uri::SSConfig;
    /// use ss_uri::Method;
    /// use url::Host;
    /// let config = SSConfig {
    ///     host: Host::parse("192.168.100.1").unwrap(),
    ///     port: 8888,
    ///     method: Method::BfCfb,
    ///     password: "test".to_string(),
    ///     tag: Some("Foo Bar".to_string()),
    ///     extra: None,
    /// };
    /// assert_eq!(
    ///     config.to_legacy_base64_encoded(),
    ///     "ss://YmYtY2ZiOnRlc3RAMTkyLjE2OC4xMDAuMTo4ODg4#Foo%20Bar"
    /// );
    /// ```
    pub fn to_legacy_base64_encoded(&self) -> String {
        let SSConfig {
            host,
            port,
            method,
            password,
            tag,
            ..
        } = self;
        let hash = Self::get_hash(tag);
        let encoded = base64::encode(format!("{}:{password}@{host}:{port}", method));
        let encoded = encoded.trim_end_matches('=');

        format!("ss://{encoded}{hash}")
    }
    /// converts SSConfig to shadowsocks sip002 format
    /// ```
    /// use ss_uri::SSConfig;
    /// use ss_uri::Method;
    /// use url::Host;
    /// let config = SSConfig {
    ///     host: Host::parse("192.168.100.1").unwrap(),
    ///     port: 8888,
    ///     method: Method::Aes128Gcm,
    ///     password: "test".to_string(),
    ///     tag: Some("Foo Bar".to_string()),
    ///     extra: None,
    /// };
    /// assert_eq!(
    ///     config.to_sip002(),
    ///     "ss://YWVzLTEyOC1nY206dGVzdA@192.168.100.1:8888/#Foo%20Bar"
    /// );
    /// ```
    pub fn to_sip002(&self) -> String {
        let SSConfig {
            host,
            port,
            method,
            password,
            tag,
            extra,
        } = self;

        let user_info = Self::encode_user_info(method, password);
        let query = match extra {
            Some(q) => Self::encode_query(q),
            None => "".to_string(),
        };

        let hash = Self::get_hash(tag);

        let host = Self::get_uri_formatted_host(host);
        format!("ss://{user_info}@{host}:{port}/{query}{hash}")
    }
    /// this is the method you should usually use for parsing shadowsocks uris
    /// parses an string into shadowsocks uri it supports both [sip002](https://shadowsocks.org/en/wiki/SIP002-URI-Scheme.html) and legacy mode if both were invalid returns sip002's error
    /// sip002 example:
    /// ```
    ///     use ss_uri::SSConfig;
    ///     use url::Host;
    ///     use ss_uri::Method;
    ///     let config = SSConfig::parse("ss://YWVzLTEyOC1nY206dGVzdA@192.168.100.1:8888#Foo%20Bar").unwrap();
    ///     assert_eq!(config.method, Method::Aes128Gcm);
    ///     assert_eq!(config.password,"test");
    ///     assert_eq!(config.host, Host::parse("192.168.100.1").unwrap());
    ///     assert_eq!(config.port, 8888);
    ///     assert_eq!(config.tag, Some("Foo Bar".to_string()));
    ///
    /// ```
    /// legacy uri example:
    /// ```
    /// use ss_uri::SSConfig;
    /// use url::Host;
    /// use ss_uri::Method;
    /// let input = "ss://YmYtY2ZiOnRlc3RAMTkyLjE2OC4xMDAuMTo4ODg4#Foo Bar";
    /// let config = SSConfig::parse_legacy_base64(input).unwrap();
    ///
    /// assert_eq!(config.method, Method::BfCfb);
    /// assert_eq!(config.password, "test");
    /// assert_eq!(config.host, Host::parse("192.168.100.1").unwrap());
    /// assert_eq!(config.port, 8888);
    /// assert_eq!(config.tag, Some("Foo Bar".to_string()));
    /// assert_eq!(config.extra, None);
    /// ```
    pub fn parse(s: &str) -> Result<Self, SSParseError> {
        let result = Self::parse_sip002(s);
        if result.is_ok() {
            return result;
        }
        let legacy_result = Self::parse_legacy_base64(s);
        if legacy_result.is_ok() {
            return legacy_result;
        }
        result
    }

    pub fn parse_sip002(s: &str) -> Result<Self, SSParseError> {
        let s = &Self::remove_unsafe_padding(s);

        let url = url::Url::parse(s).map_err(|_| SSParseError::InvalidUrl)?;
        Self::validate_protocol(&url)?;

        let host = Self::extract_host(&url)?;
        let port = Self::extract_port(&url)?;
        let query = Self::extract_query(&url);
        let (method, password) = Self::extract_method_and_password(url.username())?;
        let tag = Self::extract_hash(url.fragment());

        Ok(SSConfig {
            host,
            port,
            method,
            password,
            tag,
            extra: if query.is_empty() { None } else { Some(query) },
        })
    }
    pub fn parse_legacy_base64(s: &str) -> Result<Self, SSParseError> {
        let url = Url::parse(s).map_err(|_| SSParseError::InvalidUrl)?;
        Self::validate_protocol(&url)?;

        let encoded = url.host_str().ok_or(SSParseError::InvalidUrl)?;
        let decoded = base64::decode(encoded).map_err(|_| SSParseError::InvalidUrl)?;
        let decoded_str = String::from_utf8(decoded).map_err(|_| SSParseError::InvalidUrl)?;
        let decoded_str = decoded_str.trim_end_matches('=');

        let colon_index = decoded_str.find(':').ok_or(SSParseError::InvalidUrl)?;
        let (method, remaining) = decoded_str.split_at(colon_index);
        let method: Method = method.parse().map_err(|_| SSParseError::InvalidMethod)?;
        let remaining = remaining.trim_start_matches(':');

        let at_index = remaining.rfind('@').ok_or(SSParseError::InvalidUrl)?;
        let (password, remaining) = remaining.split_at(at_index);
        let remaining = remaining.trim_start_matches('@');

        let (host, port) =
            remaining.split_at(remaining.rfind(':').ok_or(SSParseError::InvalidUrl)?);
        let port = port.trim_start_matches(':');
        eprintln!("{:?}", port);
        let port = port.parse().map_err(|_| SSParseError::InvalidPort)?;

        Ok(Self {
            host: Host::parse(host).map_err(|_| SSParseError::InvalidHost)?,
            port,
            method,
            password: password.to_string(),
            tag: Self::extract_hash(url.fragment()),
            extra: None,
        })
    }
    fn validate_protocol(url: &Url) -> Result<(), SSParseError> {
        if !url.scheme().starts_with("ss") {
            return Err(SSParseError::InvalidProtocol);
        }
        Ok(())
    }
    fn extract_host(url: &url::Url) -> Result<Host, SSParseError> {
        let host = url
            .host()
            .ok_or(SSParseError::InvalidHost)?
            .to_owned()
            .to_string();
        let host = url::Host::parse(&host).map_err(|_| SSParseError::InvalidUrl)?;
        Ok(host)
    }

    fn extract_port(url: &url::Url) -> Result<u16, SSParseError> {
        let port = url
            .port_or_known_default()
            .ok_or(SSParseError::InvalidPort)?;
        Ok(port)
    }

    fn extract_hash(fragment: Option<&str>) -> Option<String> {
        fragment.map(|f| percent_decode_str(f).decode_utf8_lossy().to_string())
    }

    fn extract_query(url: &url::Url) -> HashMap<String, String> {
        url.query_pairs()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect::<HashMap<String, String>>()
    }

    fn extract_method_and_password(input: &str) -> Result<(Method, String), SSParseError> {
        let encoded_part = base64::decode(input).map_err(|_| SSParseError::InvalidPassword)?;
        let encoded_part =
            String::from_utf8(encoded_part).map_err(|_| SSParseError::InvalidPassword)?;
        let encoded_part = encoded_part.split(':').collect::<Vec<&str>>();
        let method = encoded_part
            .get(0)
            .ok_or(SSParseError::InvalidMethod)?
            .to_string();
        let method = method.parse().map_err(|_| SSParseError::InvalidMethod)?;
        let password = encoded_part
            .get(1)
            .ok_or(SSParseError::InvalidPassword)?
            .to_string();
        Ok((method, password))
    }

    fn remove_unsafe_padding(s: &str) -> String {
        let s = if s.contains("=@") {
            let a = s
                .split("=@")
                .map(|e| e.trim_matches('='))
                .collect::<Vec<&str>>()
                .join("@");
            a
        } else {
            s.into()
        };
        s
    }

    fn encode_user_info(method: &Method, password: &str) -> String {
        let user_info = base64::encode(format!("{}:{}", method, password));
        let user_info = user_info.trim_end_matches('=');
        user_info.into()
    }
    fn get_hash(tag: &Option<String>) -> String {
        match tag {
            Some(t) if !t.is_empty() => format!(
                "#{}",
                percent_encoding::percent_encode(t.as_ref(), NON_ALPHANUMERIC)
            ),
            _ => "".into(),
        }
    }
    fn encode_query(extra: &HashMap<String, String>) -> String {
        let mut uri_encoded = url::form_urlencoded::Serializer::new(String::new());
        extra.iter().for_each(|(k, v)| {
            uri_encoded.append_pair(k, v);
        });
        uri_encoded.finish()
    }
    fn get_uri_formatted_host(host: &Host) -> String {
        match host {
            Host::Domain(i) => i.to_string(),
            Host::Ipv4(i) => i.to_string(),
            Host::Ipv6(i) => format!("[{}]", i),
        }
    }
}

#[cfg(test)]
mod tests {
    mod generic {
        use super::super::*;
        #[test]
        fn should_parse_a_valid_sip002() {
            let config =
                SSConfig::parse("ss://YWVzLTEyOC1nY206dGVzdA@192.168.100.1:8888#Foo%20Bar")
                    .unwrap();

            assert_eq!((config.method), ("aes-128-gcm").try_into().unwrap());
            assert_eq!((config.password), ("test"));
            assert_eq!((config.host), Host::parse("192.168.100.1").unwrap());
            assert_eq!((config.port), (8888));
            assert_eq!((config.tag), Some("Foo Bar".into()));
        }
        #[test]
        fn should_parse_a_valid_legacy_shadowsocks_uri() {
            let input = "ss://YmYtY2ZiOnRlc3RAMTkyLjE2OC4xMDAuMTo4ODg4#Foo Bar";
            let config = SSConfig::parse(input).unwrap();

            assert_eq!(config.method, Method::BfCfb);
            assert_eq!(config.password, "test");
            assert_eq!(config.host, Host::parse("192.168.100.1").unwrap());
            assert_eq!(config.port, 8888);
            assert_eq!(config.tag, Some("Foo Bar".to_string()));
            assert_eq!(config.extra, None);
        }
    }

    mod sip002 {
        use crate::method::Method;

        use super::super::*;
        #[test]
        fn can_serialize_a_sip002_uri() {
            let config = SSConfig {
                host: Host::parse("192.168.100.1").unwrap(),
                port: 8888,
                method: Method::Aes128Gcm,
                password: "test".to_string(),
                tag: Some("Foo Bar".to_string()),
                extra: None,
            };
            assert_eq!(
                config.to_sip002(),
                "ss://YWVzLTEyOC1nY206dGVzdA@192.168.100.1:8888/#Foo%20Bar"
            );
        }

        #[test]
        fn can_serialize_a_sip002_uri_with_a_non_latin_password() {
            let config = SSConfig {
                host: Host::parse("192.168.100.1").unwrap(),
                port: "8888".parse().unwrap(),
                method: "aes-128-gcm".parse().unwrap(),
                password: "小洞不补大洞吃苦".into(),
                tag: Some("Foo Bar".into()),
                extra: None,
            };
            assert_eq!(
            config.to_sip002(),
            "ss://YWVzLTEyOC1nY2065bCP5rSe5LiN6KGl5aSn5rSe5ZCD6Ium@192.168.100.1:8888/#Foo%20Bar"
        )
        }
        #[test]
        fn can_serialize_a_sip002_uri_with_ipv6_host() {
            let config = SSConfig {
                host: Host::parse("[2001:0:ce49:7601:e866:efff:62c3:fffe]").unwrap(),
                port: "8888".parse().unwrap(),
                method: "aes-128-gcm".parse().unwrap(),
                password: "test".into(),
                tag: Some("Foo Bar".into()),
                extra: None,
            };

            assert_eq!(
            config.to_sip002(),
            "ss://YWVzLTEyOC1nY206dGVzdA@[2001:0:ce49:7601:e866:efff:62c3:fffe]:8888/#Foo%20Bar"
        );
        }
        #[test]
        fn can_serialize_a_legacy_base64_uri() {
            let config = SSConfig {
                host: Host::parse("192.168.100.1").unwrap(),
                port: 8888,
                method: Method::BfCfb,
                password: "test".to_string(),
                tag: Some("Foo Bar".to_string()),
                extra: None,
            };
            assert_eq!(
                config.to_legacy_base64_encoded(),
                "ss://YmYtY2ZiOnRlc3RAMTkyLjE2OC4xMDAuMTo4ODg4#Foo%20Bar"
            );
        }
        #[test]
        fn can_serialize_a_legacy_base64_uri_with_a_non_latin_password() {
            let config = SSConfig {
                host: Host::parse("192.168.100.1").unwrap(),
                port: "8888".parse().unwrap(),
                method: "bf-cfb".parse().unwrap(),
                password: "小洞不补大洞吃苦".into(),
                tag: Some("Foo Bar".into()),
                extra: None,
            };
            assert_eq!(
            config.to_legacy_base64_encoded(),
            "ss://YmYtY2ZiOuWwj+a0nuS4jeihpeWkp+a0nuWQg+iLpkAxOTIuMTY4LjEwMC4xOjg4ODg#Foo%20Bar"
        )
        }

        #[test]
        fn can_parse_a_valid_sip002_uri_with_ipv4_host() {
            let input = "ss://YWVzLTEyOC1nY206dGVzdA@192.168.100.1:8888#Foo%20Bar";
            let config = SSConfig::parse_sip002(input).unwrap();

            assert_eq!((config.method), ("aes-128-gcm").try_into().unwrap());
            assert_eq!((config.password), ("test"));
            assert_eq!((config.host), Host::parse("192.168.100.1").unwrap());
            assert_eq!((config.port), (8888));
            assert_eq!((config.tag), Some("Foo Bar".into()));
        }
        #[test]
        fn can_parse_a_sip002_uri_with_non_uri_safe_base64_padding() {
            let input = "ss://YWVzLTEyOC1nY206dGVzdA==@192.168.100.1:8888#Foo%20Bar";
            let config = SSConfig::parse_sip002(input).unwrap();

            assert_eq!((config.method), ("aes-128-gcm").try_into().unwrap());
            assert_eq!((config.password), ("test"));
            assert_eq!((config.host), Host::parse("192.168.100.1").unwrap());
            assert_eq!((config.port), (8888));
            assert_eq!((config.tag), Some("Foo Bar".into()));
        }
        #[test]
        fn can_parse_a_valid_sip002_uri_with_ipv6_host() {
            let input = "ss://YWVzLTEyOC1nY206dGVzdA@[2001:0:ce49:7601:e866:efff:62c3:fffe]:8888";
            let config = SSConfig::parse_sip002(input).unwrap();

            assert_eq!((config.method), ("aes-128-gcm").try_into().unwrap());
            assert_eq!((config.password), ("test"));
            assert_eq!(
                (config.host),
                Host::parse("[2001:0:ce49:7601:e866:efff:62c3:fffe]").unwrap()
            );
            assert_eq!((config.port), (8888));
        }
        #[test]
        fn can_parse_a_valid_sip002_uri_with_a_compressed_ipv6_host() {
            let input = "ss://YWVzLTEyOC1nY206dGVzdA@[2001::fffe]:8888";
            let config = SSConfig::parse_sip002(input).unwrap();

            assert_eq!((config.method), ("aes-128-gcm").try_into().unwrap());
            assert_eq!((config.password), ("test"));
            assert_eq!(
                (config.host),
                Host::parse("[2001:0:0:0:0:0:0:fffe]").unwrap()
            );
            assert_eq!((config.port), (8888));
        }
        #[test]
        fn can_parse_a_valid_sip002_uri_with_a_non_latin_password() {
            let input = "ss://YWVzLTEyOC1nY2065bCP5rSe5LiN6KGl5aSn5rSe5ZCD6Ium@192.168.100.1:8888";
            let config = SSConfig::parse_sip002(input).unwrap();

            assert_eq!((config.method), ("aes-128-gcm").try_into().unwrap());
            assert_eq!((config.password), ("小洞不补大洞吃苦"));
            assert_eq!((config.host), Host::parse("192.168.100.1").unwrap());
            assert_eq!((config.port), (8888));
        }
        #[test]
        fn can_parse_a_valid_sip002_uri_with_an_arbitrary_query_param() {
            let input = "ss://cmM0LW1kNTpwYXNzd2Q@192.168.100.1:8888/?foo=1";
            let config = SSConfig::parse_sip002(input).unwrap();

            assert_eq!((config.extra.unwrap().get("foo").unwrap()), ("1"));
        }

        #[test]
        fn can_parse_a_valid_sip002_uri_with_a_plugin_param() {
            let input =
                "ss://cmM0LW1kNTpwYXNzd2Q@192.168.100.1:8888/?plugin=obfs-local%3Bobfs%3Dhttp";
            let config = SSConfig::parse_sip002(input).unwrap();

            assert_eq!((config.method), ("rc4-md5").try_into().unwrap());
            assert_eq!((config.password), ("passwd"));
            assert_eq!((config.host), Host::parse("192.168.100.1").unwrap());
            assert_eq!((config.port), (8888));
            assert_eq!(
                (config.extra.unwrap().get("plugin").unwrap()),
                ("obfs-local;obfs=http")
            );
        }
        #[test]
        fn can_parse_a_valid_sip002_uri_with_the_default_http_port_and_no_plugin_parameters() {
            let input = "ss://cmM0LW1kNTpwYXNzd2Q@192.168.100.1:80";
            let config = SSConfig::parse_sip002(input).unwrap();

            assert_eq!((config.method), ("rc4-md5").try_into().unwrap());
            assert_eq!((config.password), ("passwd"));
            assert_eq!((config.host), Host::parse("192.168.100.1").unwrap());
            assert_eq!((config.port), (80));
        }
        #[test]
        fn can_parse_a_valid_sip002_uri_with_the_default_http_port_and_parameters() {
            let input = "ss://cmM0LW1kNTpwYXNzd2Q@192.168.100.1:80/?foo=1&bar=";
            let config = SSConfig::parse_sip002(input).unwrap();

            assert_eq!((config.method), ("rc4-md5").try_into().unwrap());
            assert_eq!((config.password), ("passwd"));
            assert_eq!((config.host), Host::parse("192.168.100.1").unwrap());
            assert_eq!((config.port), (80));
        }
    }
    mod legacy {
        use super::super::*;
        #[test]
        fn can_parse_a_legacy_uri_with_the_at_symbol_and_other_symbols_in_the_password() {
            let input =
            "ss://YmYtY2ZiOnRlc3QvIUAjOi5fLV4nIiRAJUAxOTIuMTY4LjEwMC4xOjg4ODg#server_by_tim@shadowsocks.org";
            let config = SSConfig::parse_legacy_base64(input).unwrap();

            assert_eq!((config.password), (r###"test/!@#:._-^'"$@%"###));
        }

        #[test]
        fn can_parse_a_valid_legacy_base64_uri_with_ipv4_host() {
            let input = "ss://YmYtY2ZiOnRlc3RAMTkyLjE2OC4xMDAuMTo4ODg4#Foo Bar";
            let config = SSConfig::parse_legacy_base64(input).unwrap();

            assert_eq!(config.method, Method::BfCfb);
            assert_eq!(config.password, "test");
            assert_eq!(config.host, Host::parse("192.168.100.1").unwrap());
            assert_eq!(config.port, 8888);
            assert_eq!(config.tag, Some("Foo Bar".to_string()));
            assert_eq!(config.extra, None);
        }

        #[test]
        fn can_parse_a_valid_legacy_base64_uri_with_ipv6_host() {
            let input =
                "ss://YmYtY2ZiOnRlc3RAWzIwMDE6MDpjZTQ5Ojc2MDE6ZTg2NjplZmZmOjYyYzM6ZmZmZV06ODg4OA";
            let config = SSConfig::parse_legacy_base64(input).unwrap();

            assert_eq!(
                (config.host),
                Host::parse("[2001:0:ce49:7601:e866:efff:62c3:fffe]").unwrap()
            );
            assert_eq!((config.port), (8888));
            assert_eq!((config.method), ("bf-cfb").try_into().unwrap());
            assert_eq!((config.password), ("test"));
            assert_eq!((config.tag), None);
        }

        #[test]
        fn can_parse_a_valid_legacy_base64_uri_default_http_port() {
            let input = "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNzdzByZEAxOTIuMTY4LjEwMC4xOjgw";
            let config = SSConfig::parse_legacy_base64(input).unwrap();

            assert_eq!((config.host), Host::parse("192.168.100.1").unwrap());
            assert_eq!((config.port), (80));
            assert_eq!(
                (config.method),
                ("chacha20-ietf-poly1305").try_into().unwrap()
            );
            assert_eq!((config.password), ("passw0rd"));
        }

        #[test]
        fn can_parse_a_valid_legacy_base64_uri_with_a_non_latin_password() {
            let input =
            "ss://YmYtY2ZiOuWwj+a0nuS4jeihpeWkp+a0nuWQg+iLpkAxOTIuMTY4LjEwMC4xOjg4ODg#Foo%20Bar";
            let config = SSConfig::parse_legacy_base64(input).unwrap();

            assert_eq!((config.method), ("bf-cfb").try_into().unwrap());
            assert_eq!((config.password), ("小洞不补大洞吃苦"));
            assert_eq!((config.host), Host::parse("192.168.100.1").unwrap());
            assert_eq!((config.port), (8888));
            assert_eq!((config.tag), Some("Foo Bar".into()));
        }
    }
}
