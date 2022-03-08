use std::collections::HashMap;

use url::Url;

pub struct SIP008Config {
    pub location: String,
    pub cert_finger_print: Option<String>,
    pub http_method: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub enum SIP008ParseError {
    InvalidUrl,
    InvalidProtocol,
    InvalidPort,
    InvalidHost,
}

impl SIP008Config {
    pub fn parse(input: &str) -> Result<Self, SIP008ParseError> {
        let url = Url::parse(input).map_err(|_| SIP008ParseError::InvalidUrl)?;
        Self::validate_protocol(&url)?;
        let params = url::form_urlencoded::parse(url.fragment().unwrap_or("").as_ref())
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect::<HashMap<String, String>>();
        Ok(Self {
            location: format!(
                "https://{}:{}{}",
                url.host_str().ok_or(SIP008ParseError::InvalidUrl)?,
                url.port_or_known_default().unwrap_or(443),
                url.path()
            ),
            cert_finger_print: params.get("certFp").cloned(),
            http_method: params.get("httpMethod").cloned(),
        })
    }
    pub(crate) fn validate_protocol(url: &Url) -> Result<(), SIP008ParseError> {
        if !url.scheme().starts_with("ssconf") {
            return Err(SIP008ParseError::InvalidProtocol);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use percent_encoding::{percent_encode, NON_ALPHANUMERIC};
    use url::Url;

    #[test]
    fn can_parse_a_valid_ssconf_uri_with_domain_name_and_extras() {
        let input =
            "ssconf://my.domain.com/secret/long/path#certFp=AA:BB:CC:DD:EE:FF&httpMethod=POST";
        let online_config = SIP008Config::parse(input).unwrap();
        let url = Url::parse(&online_config.location).unwrap();
        assert_eq!(
            url,
            Url::parse("https://my.domain.com/secret/long/path").unwrap()
        );
        assert_eq!(
            online_config.cert_finger_print,
            Some("AA:BB:CC:DD:EE:FF".to_string())
        );
        assert_eq!(online_config.http_method, Some("POST".to_string()));
    }
    #[test]
    fn can_parse_a_valid_ssconf_uri_with_domain_name_and_custom_port() {
        let input = "ssconf://my.domain.com:9090/secret/long/path#certFp=AA:BB:CC:DD:EE:FF";
        let online_config = SIP008Config::parse(input).unwrap();
        let url = Url::parse(&online_config.location).unwrap();
        assert_eq!(
            url,
            Url::parse("https://my.domain.com:9090/secret/long/path").unwrap()
        );
        assert_eq!(
            online_config.cert_finger_print,
            Some("AA:BB:CC:DD:EE:FF".to_string())
        );
    }
    #[test]
    fn can_parse_a_valid_ssconf_uri_with_hostname_and_no_path() {
        let input = "ssconf://my.domain.com";
        let online_config = SIP008Config::parse(input).unwrap();
        let url = Url::parse(&online_config.location).unwrap();
        assert_eq!(url, Url::parse("https://my.domain.com").unwrap());
        assert_eq!(online_config.cert_finger_print, None);
    }

    #[test]
    fn can_parse_a_valid_ssconf_uri_with_ipv4_address() {
        let input = "ssconf://1.2.3.4/secret/long/path#certFp=AA:BB:CC:DD:EE:FF&other=param";
        let online_config = SIP008Config::parse(input).unwrap();
        let url = Url::parse(&online_config.location).unwrap();
        assert_eq!(url, Url::parse("https://1.2.3.4/secret/long/path").unwrap());
        assert_eq!(
            online_config.cert_finger_print,
            Some("AA:BB:CC:DD:EE:FF".to_string())
        );
    }

    #[test]
    fn can_parse_a_valid_ssconf_uri_with_ipv6_address_and_custom_port() {
        // encodeURI encodes the IPv6 address brackets.
        let input = "ssconf://[2001:0:ce49:7601:e866:efff:62c3:fffe]:8081/secret/long/path#certFp=AA:BB:CC:DD:EE:FF";
        let online_config = SIP008Config::parse(input).unwrap();
        let url = Url::parse(&online_config.location).unwrap();
        assert_eq!(
            url,
            Url::parse("https://[2001:0:ce49:7601:e866:efff:62c3:fffe]:8081/secret/long/path")
                .unwrap()
        );
        assert_eq!(
            online_config.cert_finger_print,
            Some("AA:BB:CC:DD:EE:FF".to_string())
        );
    }

    #[test]
    fn can_parse_a_valid_ssconf_uri_with_uri_encoded_tag() {
        let cert_fp = percent_encode("&=?:%".as_ref(), NON_ALPHANUMERIC).to_string();
        let input = format!("ssconf://1.2.3.4/secret#certFp={cert_fp}&httpMethod=GET");
        let online_config = SIP008Config::parse(&input).unwrap();
        let url = Url::parse(&online_config.location).unwrap();
        assert_eq!(url, Url::parse("https://1.2.3.4/secret").unwrap());
        assert_eq!(online_config.cert_finger_print, Some("&=?:%".to_string()));
        assert_eq!(online_config.http_method, Some("GET".to_string()));
    }
}
