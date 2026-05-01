use std::{
    collections::VecDeque,
    io::{self, Error},
};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use p256::ecdsa::{Signature, VerifyingKey};

use crate::Payload;

pub trait Parse: Sized {
    // BytesMutのclone前提は筋が悪いが、&mut BytesMutにしてparseで内部カーソルが進んでデータが変わるのは意識から外れがちなので一旦
    fn parse(src: BytesMut) -> io::Result<Self>;
}

pub trait Encode: Sized {
    fn encode(&self) -> BytesMut;
}

#[derive(Debug, Clone)]
pub enum MessageNumber {
    SSH_MSG_SERVICE_REQUEST = 5,

    SSH_MSG_KEXINIT = 20,
    SSH_MSG_NEWKEYS = 21,

    SSH_MSG_KEX_ECDH_INIT = 30,
    SSH_MSG_KEX_ECDH_REPLY = 31,
}

#[derive(Debug, Clone)]
pub enum Msg {
    ProtoVerEx(BytesMut),
}

impl Msg {
    // pub fn parse(mut src: BytesMut) -> io::Result<Self> {
    //     let message_number = src.get_u8();

    //     match message_number {}
    // }
}

#[derive(Debug, Clone)]
pub struct NameList {
    inner: Vec<String>,
}

impl From<Vec<String>> for NameList {
    fn from(value: Vec<String>) -> Self {
        NameList::new(value)
    }
}

impl NameList {
    pub fn new(inner: Vec<String>) -> Self {
        NameList { inner }
    }
}

impl Encode for NameList {
    fn encode(&self) -> BytesMut {
        let name_list_bytes = self.inner.join(",");
        let name_list_bytes = Vec::from_iter(name_list_bytes.into_bytes());

        let lenght: [u8; 4] = (name_list_bytes.len() as u32).to_be_bytes();

        let mut bytes = BytesMut::new();

        bytes.extend_from_slice(&lenght);
        bytes.extend_from_slice(&name_list_bytes);

        bytes
    }
}

pub fn parse_name_list(src: &mut BytesMut) -> io::Result<NameList> {
    let length = src.get_u32();
    let name_list = String::from_utf8_lossy(&src.split_to(length as usize))
        .split(",")
        .map(String::from)
        .collect::<Vec<_>>();

    Ok(NameList::from(name_list))
}

pub trait EncodeToBytesMut {
    fn encode(&self, dst: &mut BytesMut);
}

#[derive(Debug, Clone)]
pub struct Message {
    message_number: MessageNumber,
    pub buffer: BytesMut,
}

impl Message {
    pub fn new(message_number: MessageNumber) -> Message {
        let mut buffer = BytesMut::new();
        buffer.put_u8(message_number.clone() as u8);

        Message {
            message_number,
            buffer,
        }
    }

    pub fn ssh_string(self, str: impl Into<Bytes>) -> Message {
        self.extend(SshString::new(str.into()))
    }

    pub fn extend(mut self, item: impl EncodeToBytesMut) -> Message {
        item.encode(&mut self.buffer);
        self
    }
}

#[derive(Debug, Clone)]
pub struct ByteStream {
    pub buffer: BytesMut,
}

impl ByteStream {
    pub fn new() -> ByteStream {
        ByteStream {
            buffer: BytesMut::new(),
        }
    }

    pub fn ssh_string(self, str: impl Into<Bytes>) -> ByteStream {
        self.extend(SshString::new(str.into()))
    }

    pub fn ssh_mpint(self, src: impl Into<Bytes>) -> ByteStream {
        self.extend(SshMpInt::new(src.into()))
    }

    pub fn extend(mut self, item: impl EncodeToBytesMut) -> ByteStream {
        item.encode(&mut self.buffer);
        self
    }

    pub fn put(mut self, item: impl Buf) -> ByteStream {
        self.buffer.put(item);
        self
    }
}

#[derive(Debug, Clone)]
pub struct SshString {
    src: Bytes,
}

impl SshString {
    pub fn new(src: impl Into<Bytes>) -> SshString {
        SshString { src: src.into() }
    }

    pub fn parse(src: &mut BytesMut) -> Self {
        let length = src.get_u32();
        let str = src.split_to(length as usize);

        SshString {
            src: str.clone().into(),
        }
    }

    pub fn as_bytes(&self) -> Bytes {
        self.src.clone()
    }

    pub fn as_str(&self) -> String {
        String::from_utf8_lossy(&self.src).to_string()
    }
}

impl EncodeToBytesMut for SshString {
    fn encode(&self, dst: &mut BytesMut) {
        dst.put_u32(self.src.len() as u32);
        dst.extend(&self.src);
    }
}

use ssh_encoding::Writer;
pub(crate) fn encode_mpint(s: &[u8], w: &mut BytesMut) -> Result<(), ssh_encoding::Error> {
    use ssh_encoding::Encode;
    // Skip initial 0s.
    let mut i = 0;
    while i < s.len() && s[i] == 0 {
        i += 1
    }
    // If the first non-zero is >= 128, write its length (u32, BE), followed by 0.
    if s[i] & 0x80 != 0 {
        // ((s.len() - i + 1) as u32).encode(w)?;
        w.put_u32(((s.len() - i + 1) as u32));
        // 0u8.encode(w)?;
        w.put_u8(0);
    } else {
        // ((s.len() - i) as u32).encode(w)?;
        w.put_u32(((s.len() - i) as u32));
    }
    w.extend_from_slice(&s[i..]);

    Ok(())
}

#[derive(Debug, Clone)]
pub struct SshMpInt {
    src: Bytes,
}

impl SshMpInt {
    pub fn new(src: impl Into<Bytes>) -> SshMpInt {
        SshMpInt { src: src.into() }
    }
}

impl EncodeToBytesMut for SshMpInt {
    fn encode(&self, dst: &mut BytesMut) {
        encode_mpint(&self.src, dst).unwrap();
    }
}

#[derive(Debug, Clone)]
pub struct SshPublicKey {
    identifier: String,
    key: VerifyingKey,
}

impl SshPublicKey {
    pub fn new(identifier: impl Into<String>, key: VerifyingKey) -> Self {
        SshPublicKey {
            identifier: identifier.into(),
            key,
        }
    }

    pub fn encoded(&self) -> BytesMut {
        let mut bytes = BytesMut::new();
        self.encode(&mut bytes);

        bytes
    }
}

impl EncodeToBytesMut for SshPublicKey {
    fn encode(&self, dst: &mut BytesMut) {
        let mut blob = BytesMut::new();

        SshString::new(format!("ecdsa-sha2-{}", self.identifier.clone())).encode(&mut blob);
        SshString::new(self.identifier.clone()).encode(&mut blob);
        SshString::new(self.key.to_encoded_point(false).as_bytes().to_vec()).encode(&mut blob);
        SshString::new(blob).encode(dst);
    }
}

#[derive(Debug)]
pub struct SshSignature {
    sig: Signature,
    identifier: String,
}

impl SshSignature {
    pub fn new(sig: Signature, identifier: impl Into<String>) -> Self {
        SshSignature {
            sig,
            identifier: identifier.into(),
        }
    }
}

impl EncodeToBytesMut for SshSignature {
    fn encode(&self, dst: &mut BytesMut) {
        let mut str = BytesMut::new();

        SshString::new(format!("ecdsa-sha2-{}", self.identifier)).encode(&mut str);

        let mut blob = BytesMut::new();
        SshMpInt::new(self.sig.r().to_bytes().to_vec()).encode(&mut blob);
        SshMpInt::new(self.sig.s().to_bytes().to_vec()).encode(&mut blob);
        SshString::new(blob).encode(&mut str);

        SshString::new(str).encode(dst);
    }
}
