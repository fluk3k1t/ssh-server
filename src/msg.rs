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

#[derive(Debug)]
pub struct AlgorithmNegotiation {
    pub cookie: [u8; 16],
    pub kex_algorithms: NameList,
    pub server_host_key_algorithms: NameList,
    pub encryption_algorithms_client_to_server: NameList,
    pub encryption_algorithms_server_to_client: NameList,
    pub mac_algorithms_client_to_server: NameList,
    pub mac_algorithms_server_to_client: NameList,
    pub compression_algorithms_client_to_server: NameList,
    pub compression_algorithms_server_to_client: NameList,
    pub languages_client_to_server: NameList,
    pub languages_server_to_client: NameList,
    pub first_kex_packet_follows: bool,
}

impl Parse for AlgorithmNegotiation {
    fn parse(src: &mut Payload) -> io::Result<Self> {
        let payload = &mut src.inner;

        let msg = payload[0];

        if msg != MessageNumber::SSH_MSG_KEXINIT as u8 {
            return Err(io::Error::other(format!(
                "expected {:?} but ",
                MessageNumber::SSH_MSG_KEXINIT
            )));
        }

        let _msg = payload.get_u8();

        let cookie: [u8; 16] = *payload
            .split_to(16)
            .first_chunk::<16>()
            .expect("unreachable");

        let kex_algorithms = parse_name_list(payload)?;
        let server_host_key_algorithms = parse_name_list(payload)?;
        let encryption_algorithms_client_to_server = parse_name_list(payload)?;
        let encryption_algorithms_server_to_client = parse_name_list(payload)?;
        let mac_algorithms_client_to_server = parse_name_list(payload)?;
        let mac_algorithms_server_to_client = parse_name_list(payload)?;
        let compression_algorithms_client_to_server = parse_name_list(payload)?;
        let compression_algorithms_server_to_client = parse_name_list(payload)?;
        let languages_client_to_server = parse_name_list(payload)?;
        let languages_server_to_client = parse_name_list(payload)?;

        let first_kex_packet_follows = payload.get_u8() != 0;
        let _reserved = payload.get_u32();

        Ok(AlgorithmNegotiation {
            cookie,
            kex_algorithms,
            server_host_key_algorithms,
            encryption_algorithms_client_to_server,
            encryption_algorithms_server_to_client,
            mac_algorithms_client_to_server,
            mac_algorithms_server_to_client,
            compression_algorithms_client_to_server,
            compression_algorithms_server_to_client,
            languages_client_to_server,
            languages_server_to_client,
            first_kex_packet_follows,
        })
    }
}

impl Encode for AlgorithmNegotiation {
    fn encode(&self) -> BytesMut {
        let mut bytes = BytesMut::new();

        bytes.put_u8(MessageNumber::SSH_MSG_KEXINIT as u8);
        bytes.put(&self.cookie[..]);

        bytes.extend_from_slice(&self.kex_algorithms.encode());
        bytes.extend_from_slice(&self.server_host_key_algorithms.encode());
        bytes.extend_from_slice(&self.encryption_algorithms_client_to_server.encode());
        bytes.extend_from_slice(&self.encryption_algorithms_server_to_client.encode());
        bytes.extend_from_slice(&self.mac_algorithms_client_to_server.encode());
        bytes.extend_from_slice(&self.mac_algorithms_server_to_client.encode());
        bytes.extend_from_slice(&self.compression_algorithms_client_to_server.encode());
        bytes.extend_from_slice(&self.compression_algorithms_server_to_client.encode());
        bytes.extend_from_slice(&self.languages_client_to_server.encode());
        bytes.extend_from_slice(&self.languages_server_to_client.encode());

        bytes.put_u8(if self.first_kex_packet_follows { 1 } else { 0 });
        bytes.put_bytes(b'0', 4);

        bytes
    }
}

fn parse_name_list(src: &mut BytesMut) -> io::Result<NameList> {
    let length = src.get_u32();
    let name_list = String::from_utf8_lossy(&src.split_to(length as usize))
        .split(",")
        .map(String::from)
        .collect::<Vec<_>>();

    Ok(NameList::from(name_list))
}
