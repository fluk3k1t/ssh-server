use std::io;

use bytes::Buf;
use p256::{EncodedPoint, NistP256, elliptic_curve::PublicKey};

use crate::{MessageNumber, Parse, Payload, SpString};

#[derive(Debug)]
pub struct EcdhKex {
    pub client_public_key: PublicKey<NistP256>,
}

impl Parse for EcdhKex {
    fn parse(src: &mut Payload) -> io::Result<Self> {
        let msg = src.inner[0];

        if msg != MessageNumber::SSH_MSG_KEX_ECDH_INIT as u8 {
            return Err(io::Error::other(""));
        }

        let _msg = src.inner.get_u8();

        let client_public_key = SpString::parse(src)?;
        let client_public_key = EncodedPoint::from_bytes(&client_public_key).unwrap();
        let client_public_key = PublicKey::from_sec1_bytes(&client_public_key.as_bytes())
            .map_err(|e| io::Error::other(e))?;

        Ok(EcdhKex { client_public_key })
    }
}
