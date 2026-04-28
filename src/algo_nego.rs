use std::io;

use bytes::{Buf, BufMut, BytesMut};
use tokio_util::codec::Encoder;

use crate::{
    BinaryPacketEncoder, Encode, MessageNumber, NameList, Parse, Payload, parse_name_list,
};

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

impl Encoder<AlgorithmNegotiation> for BinaryPacketEncoder {
    type Error = io::Error;

    fn encode(
        &mut self,
        item: AlgorithmNegotiation,
        dst: &mut BytesMut,
    ) -> Result<(), Self::Error> {
        let packet = item.encode();
        let padding: u8 = 4;

        dst.put_u32(packet.len() as u32 + padding as u32 + 1);
        dst.put_u8(padding);
        dst.extend_from_slice(&packet);
        dst.put_bytes(0, padding as usize);

        Ok(())
    }
}
