use std::{collections::VecDeque, io};

use bytes::{Buf, BufMut, BytesMut};

use crate::Payload;

pub trait Parse: Sized {
    fn parse(src: &mut Payload) -> io::Result<Self>;
}

pub trait Encode: Sized {
    fn encode(&self) -> BytesMut;
}

#[derive(Debug)]
pub enum MessageNumber {
    SSH_MSG_KEXINIT = 20,
    SSH_MSG_KEX_ECDH_INIT = 30,
    SSH_MSG_KEX_ECDH_REPLY = 31,
}

#[derive(Debug)]
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

pub type SpString = BytesMut;
impl Parse for SpString {
    fn parse(src: &mut Payload) -> io::Result<Self> {
        let length = src.inner.get_u32();
        let str = src.inner.split_to(length as usize);

        Ok(str)
    }
}

impl Encode for SpString {
    fn encode(&self) -> BytesMut {
        let length = self.len();

        let mut bytes = BytesMut::new();
        // bytes.put_u32(length as u32);
        bytes.put_u32(length as u32);

        bytes.put(&self.to_vec()[..]);

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
