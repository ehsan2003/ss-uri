use core::fmt;
use std::{self, str::FromStr};

// encryption method
#[derive(PartialEq, Eq, Hash, Clone, Copy)]
pub enum Method {
    Rc4Md5,
    Aes128Gcm,
    Aes192Gcm,
    Aes256Gcm,
    Aes128Cfb,
    Aes192Cfb,
    Aes256Cfb,
    Aes128Ctr,
    Aes192Ctr,
    Aes256Ctr,
    Camellia128Cfb,
    Camellia192Cfb,
    Camellia256Cfb,
    BfCfb,
    Chacha20IetfPoly1305,
    Salsa20,
    Chacha20,
    Chacha20Ietf,
    Xchacha20IetfPoly130,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MethodParseError {
    UnknownMethod,
}
impl fmt::Display for MethodParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl std::error::Error for MethodParseError {}

impl FromStr for Method {
    type Err = MethodParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Method::try_from(s)
    }
}
impl TryFrom<&str> for Method {
    type Error = MethodParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "rc4-md5" => Ok(Method::Rc4Md5),
            "aes-128-gcm" => Ok(Method::Aes128Gcm),
            "aes-192-gcm" => Ok(Method::Aes192Gcm),
            "aes-256-gcm" => Ok(Method::Aes256Gcm),
            "aes-128-cfb" => Ok(Method::Aes128Cfb),
            "aes-192-cfb" => Ok(Method::Aes192Cfb),
            "aes-256-cfb" => Ok(Method::Aes256Cfb),
            "aes-128-ctr" => Ok(Method::Aes128Ctr),
            "aes-192-ctr" => Ok(Method::Aes192Ctr),
            "aes-256-ctr" => Ok(Method::Aes256Ctr),
            "camellia-128-cfb" => Ok(Method::Camellia128Cfb),
            "camellia-192-cfb" => Ok(Method::Camellia192Cfb),
            "camellia-256-cfb" => Ok(Method::Camellia256Cfb),
            "bf-cfb" => Ok(Method::BfCfb),
            "chacha20-ietf-poly1305" => Ok(Method::Chacha20IetfPoly1305),
            "salsa20" => Ok(Method::Salsa20),
            "chacha20" => Ok(Method::Chacha20),
            "chacha20-ietf" => Ok(Method::Chacha20Ietf),
            "xchacha20-ietf-poly1305" => Ok(Method::Xchacha20IetfPoly130),
            _ => Err(MethodParseError::UnknownMethod),
        }
    }
}

impl From<Method> for String {
    fn from(val: Method) -> Self {
        val.as_str().into()
    }
}

impl Method {
    pub fn as_str(&self) -> &'static str {
        match self {
            Method::Rc4Md5 => "rc4-md5",
            Method::Aes128Gcm => "aes-128-gcm",
            Method::Aes192Gcm => "aes-192-gcm",
            Method::Aes256Gcm => "aes-256-gcm",
            Method::Aes128Cfb => "aes-128-cfb",
            Method::Aes192Cfb => "aes-192-cfb",
            Method::Aes256Cfb => "aes-256-cfb",
            Method::Aes128Ctr => "aes-128-ctr",
            Method::Aes192Ctr => "aes-192-ctr",
            Method::Aes256Ctr => "aes-256-ctr",
            Method::Camellia128Cfb => "camellia-128-cfb",
            Method::Camellia192Cfb => "camellia-192-cfb",
            Method::Camellia256Cfb => "camellia-256-cfb",
            Method::BfCfb => "bf-cfb",
            Method::Chacha20IetfPoly1305 => "chacha20-ietf-poly1305",
            Method::Salsa20 => "salsa20",
            Method::Chacha20 => "chacha20",
            Method::Chacha20Ietf => "chacha20-ietf",
            Method::Xchacha20IetfPoly130 => "xchacha20-ietf-poly1305",
        }
    }
}

impl std::fmt::Debug for Method {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::fmt::Display for Method {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl TryFrom<String> for Method {
    type Error = MethodParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        TryFrom::<&str>::try_from(&value)
    }
}
