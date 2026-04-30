use std::io;

use bytes::{Buf, BytesMut};
use p256::{EncodedPoint, NistP256, elliptic_curve::PublicKey};

use crate::{MessageNumber, Parse, Payload, SshString};

#[derive(Debug)]
pub struct EcdhKex {
    pub client_public_key: PublicKey<NistP256>,
}

impl Parse for EcdhKex {
    fn parse(mut src: BytesMut) -> io::Result<Self> {
        // let msg = src[0];

        // if msg != MessageNumber::SSH_MSG_KEX_ECDH_INIT as u8 {
        //     return Err(io::Error::other(""));
        // }

        // let _msg = src.get_u8();

        let client_public_key = SshString::parse(&mut src);
        let client_public_key = EncodedPoint::from_bytes(&client_public_key.as_bytes()).unwrap();
        let client_public_key = PublicKey::from_sec1_bytes(&client_public_key.as_bytes())
            .map_err(|e| io::Error::other(e))?;

        Ok(EcdhKex { client_public_key })
    }
}
