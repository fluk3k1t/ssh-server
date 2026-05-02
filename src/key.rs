use anyhow::{Error, Result, anyhow};

#[derive(Debug)]
pub enum PublicKey {
    NistP256(p256::PublicKey),
}
