use std::io::Bytes;

use anyhow::{Error, Result, anyhow};
use p256::{
    ecdsa::{
        self,
        signature::{Keypair, Signer},
    },
    elliptic_curve::{rand_core::OsRng, sec1::ToEncodedPoint},
};
use tokio_util::bytes::{BufMut, BytesMut};

use crate::{EncodeToBytesMut, SshBytesMut, SshMpint, SshString};

use p256::ecdsa::signature::SignerMut;

#[derive(Debug, Clone)]
pub enum EphemeralPublicKey {
    EcdaNistP256(p256::PublicKey),
}

impl EncodeToBytesMut for EphemeralPublicKey {
    fn encode_to_bytes_mut(&self, dst: &mut impl BufMut) {
        let encoded_key = match self {
            EphemeralPublicKey::EcdaNistP256(public_key) => {
                public_key.to_encoded_point(false).as_bytes().to_vec()
            }
        };

        SshString::new(encoded_key).encode_to_bytes_mut(dst);
    }
}

#[derive(Debug)]
pub enum SigningKey {
    EcdsaSha2NistP256(p256::ecdsa::SigningKey),
}

impl Into<String> for &SigningKey {
    fn into(self) -> String {
        match self {
            SigningKey::EcdsaSha2NistP256(_) => "ecdsa-sha2-nistp256",
        }
        .to_string()
    }
}

impl SigningKey {
    pub fn ecdsa() -> (Self, VerifyingKey) {
        let signing_key = ecdsa::SigningKey::random(&mut OsRng);
        let verifying_key = *signing_key.verifying_key();
        (
            SigningKey::EcdsaSha2NistP256(signing_key),
            VerifyingKey::EcdsaSha2NistP256(verifying_key),
        )
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        match self {
            SigningKey::EcdsaSha2NistP256(signing_key) => {
                Signature::EcdsaSha2NistP256(signing_key.sign(msg))
            }
        }
    }
}

impl EncodeToBytesMut for SigningKey {
    fn encode_to_bytes_mut(&self, dst: &mut impl BufMut) {
        SshString::from_str(self).encode_to_bytes_mut(dst);
        SshString::from_str("nistp256").encode_to_bytes_mut(dst);

        let verifing_key_blob = match self {
            SigningKey::EcdsaSha2NistP256(signing_key) => signing_key
                .verifying_key()
                .to_encoded_point(false)
                .to_bytes()
                .to_vec(),
        };

        SshString::new(verifing_key_blob).encode_to_bytes_mut(dst);
    }
}

#[derive(Debug, Clone)]
pub enum VerifyingKey {
    EcdsaSha2NistP256(p256::ecdsa::VerifyingKey),
}

impl Into<String> for &VerifyingKey {
    fn into(self) -> String {
        match self {
            VerifyingKey::EcdsaSha2NistP256(_) => "ecdsa-sha2-nistp256",
        }
        .to_string()
    }
}
use std::fmt::Debug;

impl EncodeToBytesMut for VerifyingKey {
    fn encode_to_bytes_mut(&self, dst: &mut impl BufMut) {
        let mut blob = BytesMut::new();

        SshString::from_str(self).encode_to_bytes_mut(&mut blob);
        SshString::from_str("nistp256").encode_to_bytes_mut(&mut blob);

        let verifing_key_blob = match self {
            VerifyingKey::EcdsaSha2NistP256(verifying_key) => {
                verifying_key.to_encoded_point(false).as_bytes().to_vec()
            }
        };

        SshString::new(verifing_key_blob).encode_to_bytes_mut(&mut blob);

        SshString::new(blob.clone()).encode_to_bytes_mut(dst);

        // let mut test = BytesMut::new();

        // SshString::new(blob).encode_to_bytes_mut(&mut test);

        // println!("{:?}", &test);
    }
}

#[derive(Debug)]
pub enum Signature {
    EcdsaSha2NistP256(ecdsa::Signature),
}

impl Into<String> for &Signature {
    fn into(self) -> String {
        match self {
            Signature::EcdsaSha2NistP256(_) => "ecdsa-sha2-nistp256",
        }
        .to_string()
    }
}

impl EncodeToBytesMut for Signature {
    fn encode_to_bytes_mut(&self, dst: &mut impl BufMut) {
        let (r, s) = match self {
            Signature::EcdsaSha2NistP256(signature) => (
                signature.r().to_bytes().to_vec(),
                signature.s().to_bytes().to_vec(),
            ),
        };

        let identifier: String = self.into();
        let mut str = BytesMut::new();

        SshString::from_str(identifier).encode_to_bytes_mut(&mut str);

        let mut blob = BytesMut::new();
        SshMpint::new(r).encode_to_bytes_mut(&mut blob);
        SshMpint::new(s).encode_to_bytes_mut(&mut blob);

        SshString::new(blob).encode_to_bytes_mut(&mut str);

        SshString::new(str).encode_to_bytes_mut(dst);
    }
}

pub enum SharedSecretKey {
    EcdaNistP256(p256::ecdh::SharedSecret),
}

impl EncodeToBytesMut for SharedSecretKey {
    fn encode_to_bytes_mut(&self, dst: &mut impl BufMut) {
        let raw_secret_bytes = match self {
            SharedSecretKey::EcdaNistP256(shared_secret) => {
                shared_secret.raw_secret_bytes().to_vec()
            }
        };

        SshMpint::new(raw_secret_bytes).encode_to_bytes_mut(dst);
    }
}
