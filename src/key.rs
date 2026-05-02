use anyhow::{Error, Result, anyhow};

#[derive(Debug)]
pub enum PublicKey {
    NistP256(p256::PublicKey),
}

#[derive(Debug, Clone)]
pub enum KexAlgorithm {
    EcdhSha2NistP256,
    Unsupported(String),
}

impl From<&str> for KexAlgorithm {
    fn from(value: &str) -> Self {
        match value {
            "ecdh-sha2-nistp256" => KexAlgorithm::EcdhSha2NistP256,
            _ => KexAlgorithm::Unsupported(value.to_string()),
        }
    }
}

#[derive(Debug)]
pub enum SignatureAlgorithm {
    EcdsaSha2NistP256,
}
