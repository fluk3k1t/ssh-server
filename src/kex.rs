use anyhow::{Result, anyhow};
use p256::EncodedPoint;
use tokio_util::bytes::Bytes;

use crate::{Algorithm, EphemeralPublicKey, Parse, SshNameList, SshString};

#[derive(Debug, Clone)]
pub enum KexAlgorithm {
    EcdhSha2NistP256,
    Unsupported(String),
}

impl From<&String> for KexAlgorithm {
    fn from(value: &String) -> Self {
        match value.as_str() {
            "ecdh-sha2-nistp256" => KexAlgorithm::EcdhSha2NistP256,
            _ => KexAlgorithm::Unsupported(value.to_string()),
        }
    }
}

impl Into<String> for &KexAlgorithm {
    fn into(self) -> String {
        match self {
            KexAlgorithm::EcdhSha2NistP256 => "ecdh-sha2-nistp256".to_string(),
            KexAlgorithm::Unsupported(unsuported) => unsuported.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum SignatureAlgorithm {
    EcdsaSha2NistP256,
    Unsupported(String),
}

impl From<&String> for SignatureAlgorithm {
    fn from(value: &String) -> Self {
        match value.as_str() {
            "ecdsa-sha2-nistp256" => SignatureAlgorithm::EcdsaSha2NistP256,
            _ => SignatureAlgorithm::Unsupported(value.to_string()),
        }
    }
}

impl Into<String> for &SignatureAlgorithm {
    fn into(self) -> String {
        match self {
            SignatureAlgorithm::EcdsaSha2NistP256 => "ecdsa-sha2-nistp256",
            SignatureAlgorithm::Unsupported(unsupported) => unsupported,
        }
        .to_string()
    }
}

#[derive(Debug, Clone)]
pub enum CipherAlgorithm {
    Aes128Ctr,
    Unsupported(String),
}

impl From<&String> for CipherAlgorithm {
    fn from(value: &String) -> Self {
        match value.as_str() {
            "aes128-ctr" => CipherAlgorithm::Aes128Ctr,
            _ => CipherAlgorithm::Unsupported(value.clone()),
        }
    }
}

impl Into<String> for &CipherAlgorithm {
    fn into(self) -> String {
        match self {
            CipherAlgorithm::Aes128Ctr => "aes128-ctr",
            CipherAlgorithm::Unsupported(unsupported) => unsupported,
        }
        .to_string()
    }
}

#[derive(Debug, Clone)]
pub enum MacAlgorithm {
    HmacSha2256,
    Unsupported(String),
}

impl From<&String> for MacAlgorithm {
    fn from(value: &String) -> Self {
        match value.as_str() {
            "hmac-sha2-256" => MacAlgorithm::HmacSha2256,
            _ => MacAlgorithm::Unsupported(value.to_string()),
        }
    }
}

impl Into<String> for &MacAlgorithm {
    fn into(self) -> String {
        match self {
            MacAlgorithm::HmacSha2256 => "hmac-sha2-256",
            MacAlgorithm::Unsupported(unsupported) => unsupported,
        }
        .to_string()
    }
}

#[derive(Debug)]
pub struct Kex {
    pub client_ephemeral_public_key: EphemeralPublicKey,
}

impl Kex {
    pub fn parse(src: &Bytes, agreed_algorithm: &Algorithm) -> Result<Self> {
        let mut src = src.clone();

        let (client_public_key, _) = SshString::parse(&mut src)?;

        match &agreed_algorithm.encryption_algorithms_client_to_server[0] {
            CipherAlgorithm::Aes128Ctr => {
                let encoded_point = EncodedPoint::from_bytes(client_public_key.as_bytes())?;
                let client_ephemeral_public_key =
                    p256::PublicKey::from_sec1_bytes(encoded_point.as_bytes())?;

                Ok(Kex {
                    client_ephemeral_public_key: EphemeralPublicKey::EcdaNistP256(
                        client_ephemeral_public_key,
                    ),
                })
            }
            CipherAlgorithm::Unsupported(unsupported) => {
                Err(anyhow!("unsupported algorithm: {:?}", unsupported))
            }
        }
    }
}
