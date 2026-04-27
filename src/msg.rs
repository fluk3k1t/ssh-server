use std::io;

use bytes::{Buf, BytesMut};

use crate::Payload;

pub trait Parse: Sized {
    fn parse(src: &mut Payload) -> io::Result<Self>;
}
#[derive(Debug)]
pub enum MessageNumber {
    SSH_MSG_KEXINIT = 20,
}

#[derive(Debug)]
pub struct AlgorithmNegotiation {
    pub cookie: [u8; 16],
    pub kex_algorithms: Vec<String>,
    pub server_host_key_algorithms: Vec<String>,
    pub encryption_algorithms_client_to_server: Vec<String>,
    pub encryption_algorithms_server_to_client: Vec<String>,
    pub mac_algorithms_client_to_server: Vec<String>,
    pub mac_algorithms_server_to_client: Vec<String>,
    pub compression_algorithms_client_to_server: Vec<String>,
    pub compression_algorithms_server_to_client: Vec<String>,
    pub languages_client_to_server: Vec<String>,
    pub languages_server_to_client: Vec<String>,
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

fn parse_name_list(src: &mut BytesMut) -> io::Result<Vec<String>> {
    let length = src.get_u32();
    let name_list = String::from_utf8_lossy(&src.split_to(length as usize))
        .split(",")
        .map(String::from)
        .collect::<Vec<_>>();

    Ok(name_list)
}
