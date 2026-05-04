use anyhow::Result;
use anyhow::anyhow;
use tokio_util::bytes::BufMut;
use tokio_util::bytes::Bytes;
use tokio_util::bytes::{Buf, BytesMut};

use crate::BinaryPacket;
use crate::SshBytesMut;
use crate::SshNameList;
use crate::SshString;

#[derive(Debug)]
pub struct RawMessage {
    pub message_number: MessageNumber,
    pub paylaod: Bytes,
}

impl RawMessage {
    pub fn to_bytes(&self) -> Bytes {
        let mut bytes = BytesMut::new();

        bytes.put_u8(self.message_number.clone() as u8);
        bytes.extend(self.paylaod.clone());

        bytes.freeze()
    }
}

#[derive(Debug, Clone)]
pub enum MessageNumber {
    SSH_MSG_SERVICE_REQUEST = 5,
    SSH_MSG_SERVICE_ACCEPT = 6,

    SSH_MSG_KEXINIT = 20,
    SSH_MSG_NEWKEYS = 21,

    SSH_MSG_KEX_ECDH_INIT = 30,
    SSH_MSG_KEX_ECDH_REPLY = 31,

    SSH_MSG_USERAUTH_REQUEST = 50,
    SSH_MSG_USERAUTH_FAILURE = 51,
    SSH_MSG_USERAUTH_SUCCESS = 52,
    SSH_MSG_USERAUTH_BANNER = 53,
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
            50 => Ok(Self::SSH_MSG_USERAUTH_REQUEST),
            51 => Ok(Self::SSH_MSG_USERAUTH_FAILURE),
            52 => Ok(Self::SSH_MSG_USERAUTH_SUCCESS),
            53 => Ok(Self::SSH_MSG_USERAUTH_BANNER),
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

#[derive(Debug, Clone)]
pub struct RawMessageBuilder {
    message_number: MessageNumber,
    paylaod: BytesMut,
}

impl RawMessageBuilder {
    pub fn new(message_number: MessageNumber) -> Self {
        RawMessageBuilder {
            message_number,
            paylaod: BytesMut::new(),
        }
    }

    pub fn put(mut self, src: impl EncodeToBytesMut) -> Self {
        src.encode_to_bytes_mut(&mut self.paylaod);
        self
    }

    pub fn put_ssh_string(mut self, str: impl Into<Bytes>) -> Self {
        SshString::new(str).encode_to_bytes_mut(&mut self.paylaod);
        self
    }

    pub fn put_name_list(mut self, lists: Vec<impl Into<String>>) -> Self {
        SshNameList::new(lists).encode_to_bytes_mut(&mut self.paylaod);
        self
    }

    pub fn put_bool(mut self, value: bool) -> Self {
        self.paylaod.put_u8(value as u8);
        self
    }

    pub fn build(self) -> RawMessage {
        RawMessage {
            message_number: self.message_number,
            paylaod: self.paylaod.freeze(),
        }
    }
}

pub trait BytesExt {
    fn try_split_to(&mut self, n: usize) -> Result<Bytes>;
}

impl BytesExt for Bytes {
    fn try_split_to(&mut self, n: usize) -> Result<Bytes> {
        if self.len() < n {
            return Err(anyhow!("failed to try 'split_to'"));
        }

        Ok(self.split_to(n))
    }
}

pub trait EncodeToBytesMut {
    fn encode_to_bytes_mut(&self, dst: &mut impl BufMut);

    fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();

        self.encode_to_bytes_mut(&mut buf);

        buf.freeze()
    }
}
