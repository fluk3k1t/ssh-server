use anyhow::Result;
use anyhow::anyhow;
use tokio_util::bytes::BufMut;
use tokio_util::bytes::Bytes;
use tokio_util::bytes::{Buf, BytesMut};

use crate::{BinaryPacket, PublicKey};

#[derive(Debug)]
pub struct RawMessage {
    pub message_number: MessageNumber,
    pub paylaod: Bytes,
}

#[derive(Debug, Clone)]
pub enum MessageNumber {
    SSH_MSG_SERVICE_REQUEST = 5,
    SSH_MSG_SERVICE_ACCEPT = 6,

    SSH_MSG_KEXINIT = 20,
    SSH_MSG_NEWKEYS = 21,

    SSH_MSG_KEX_ECDH_INIT = 30,
    SSH_MSG_KEX_ECDH_REPLY = 31,
}

impl TryFrom<u8> for MessageNumber {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            5 => Ok(Self::SSH_MSG_SERVICE_REQUEST),
            6 => Ok(Self::SSH_MSG_SERVICE_ACCEPT),
            20 => Ok(Self::SSH_MSG_KEXINIT),
            21 => Ok(Self::SSH_MSG_NEWKEYS),
            30 => Ok(Self::SSH_MSG_KEX_ECDH_INIT),
            31 => Ok(Self::SSH_MSG_KEX_ECDH_REPLY),
            _ => Err(anyhow!("invalid message number")),
        }
    }
}

impl RawMessage {
    pub fn parse(packet: &BinaryPacket) -> Result<RawMessage> {
        let mut packet = packet.clone();

        let message_number = packet.try_get_u8()?;
        let message_number: MessageNumber = message_number.try_into()?;

        Ok(RawMessage {
            message_number,
            paylaod: packet.clone(),
        })
    }
}

pub trait BytesExt {
    fn try_split_to(&mut self, n: usize) -> Result<Bytes>;
}

impl BytesExt for Bytes {
    fn try_split_to(&mut self, n: usize) -> Result<Bytes> {
        if self.len() < n {
            return Err(anyhow!(""));
        }

        Ok(self.split_to(n))
    }
}

pub trait EncodeToBytesMut {
    fn encode_to_bytes_mut(&self, dst: &mut BytesMut);

    fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();

        self.encode_to_bytes_mut(&mut buf);

        buf.freeze()
    }
}
