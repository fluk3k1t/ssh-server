use anyhow::Result;
use tokio_util::bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::{
    BytesExt, CipherAlgorithm, EncodeToBytesMut, KexAlgorithm, MacAlgorithm, MessageNumber, Parse,
    SignatureAlgorithm, SshNameList, SshString,
};

#[derive(Debug, Clone)]
pub struct Algorithm {
    pub cookie: [u8; 16],
    pub kex_algorithms: Algorithms<KexAlgorithm>,
    pub server_host_key_algorithms: Algorithms<SignatureAlgorithm>,
    pub encryption_algorithms_client_to_server: Algorithms<CipherAlgorithm>,
    pub encryption_algorithms_server_to_client: Algorithms<CipherAlgorithm>,
    pub mac_algorithms_client_to_server: Algorithms<MacAlgorithm>,
    pub mac_algorithms_server_to_client: Algorithms<MacAlgorithm>,
    pub compression_algorithms_client_to_server: SshNameList,
    pub compression_algorithms_server_to_client: SshNameList,
    pub languages_client_to_server: SshNameList,
    pub languages_server_to_client: SshNameList,
    pub first_kex_packet_follows: bool,
}

impl Algorithm {}

impl Default for Algorithm {
    fn default() -> Self {
        Algorithm {
            cookie: [0; 16],
            kex_algorithms: vec![KexAlgorithm::EcdhSha2NistP256],
            server_host_key_algorithms: vec![SignatureAlgorithm::EcdsaSha2NistP256],
            encryption_algorithms_client_to_server: vec![CipherAlgorithm::Aes128Ctr],
            encryption_algorithms_server_to_client: vec![CipherAlgorithm::Aes128Ctr],
            mac_algorithms_client_to_server: vec![MacAlgorithm::HmacSha2256],
            mac_algorithms_server_to_client: vec![MacAlgorithm::HmacSha2256],
            compression_algorithms_client_to_server: SshNameList::new(vec!["none"]),
            compression_algorithms_server_to_client: SshNameList::new(vec!["none"]),
            languages_client_to_server: SshNameList::new(vec!["none"]),
            languages_server_to_client: SshNameList::new(vec!["none"]),
            first_kex_packet_follows: false,
        }
    }
}

pub type Algorithms<T> = Vec<T>;

impl<T> EncodeToBytesMut for Algorithms<T>
where
    for<'a> &'a T: Into<String>,
{
    fn encode_to_bytes_mut(&self, dst: &mut BytesMut) {
        SshNameList::new(self.into_iter().map(|k| k.into()).collect::<Vec<String>>())
            .encode_to_bytes_mut(dst);
    }
}

impl<T> Parse for Algorithms<T>
where
    for<'a> &'a String: Into<T>,
{
    type Item = Bytes;

    fn parse(src: &Self::Item) -> Result<(Self, usize)>
    where
        Self: Sized,
    {
        let mut src = src.clone();

        let (parsed, n) = SshNameList::parse(&mut src)?;

        Ok((parsed.name_list.iter().map(|n| n.into()).collect(), n))
    }
}

impl Parse for Algorithm {
    type Item = Bytes;

    fn parse(src: &Self::Item) -> Result<(Self, usize)>
    where
        Self: Sized,
    {
        let mut src = src.clone();
        let start_pos = src.remaining();

        let cookie = *src
            .try_split_to(16)?
            .first_chunk::<16>()
            .expect("unreachable");

        let kex_algorithms = Algorithms::<KexAlgorithm>::parse_mut(&mut src)?;
        let server_host_key_algorithms = Algorithms::<SignatureAlgorithm>::parse_mut(&mut src)?;
        let encryption_algorithms_client_to_server =
            Algorithms::<CipherAlgorithm>::parse_mut(&mut src)?;
        let encryption_algorithms_server_to_client =
            Algorithms::<CipherAlgorithm>::parse_mut(&mut src)?;
        let mac_algorithms_client_to_server = Algorithms::<MacAlgorithm>::parse_mut(&mut src)?;
        let mac_algorithms_server_to_client = Algorithms::<MacAlgorithm>::parse_mut(&mut src)?;
        let compression_algorithms_client_to_server = SshNameList::parse_mut(&mut src)?;
        let compression_algorithms_server_to_client = SshNameList::parse_mut(&mut src)?;
        let languages_client_to_server = SshNameList::parse_mut(&mut src)?;
        let languages_server_to_client = SshNameList::parse_mut(&mut src)?;

        let first_kex_packet_follows = src.try_get_u8()? != 0;
        let _reserved = src.try_get_u32();

        Ok((
            Algorithm {
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
            },
            start_pos - src.remaining(),
        ))
    }
}

impl EncodeToBytesMut for Algorithm {
    fn encode_to_bytes_mut(&self, dst: &mut BytesMut) {
        dst.put_u8(MessageNumber::SSH_MSG_KEXINIT as u8);
        dst.put(&self.cookie[..]);

        self.kex_algorithms.encode_to_bytes_mut(dst);
        self.server_host_key_algorithms.encode_to_bytes_mut(dst);
        self.encryption_algorithms_client_to_server
            .encode_to_bytes_mut(dst);
        self.encryption_algorithms_server_to_client
            .encode_to_bytes_mut(dst);
        self.mac_algorithms_client_to_server
            .encode_to_bytes_mut(dst);
        self.mac_algorithms_server_to_client
            .encode_to_bytes_mut(dst);
        self.compression_algorithms_client_to_server
            .encode_to_bytes_mut(dst);
        self.compression_algorithms_server_to_client
            .encode_to_bytes_mut(dst);
        self.languages_client_to_server.encode_to_bytes_mut(dst);
        self.languages_server_to_client.encode_to_bytes_mut(dst);

        dst.put_u8(if self.first_kex_packet_follows { 1 } else { 0 });
        dst.put_bytes(b'0', 4);
    }
}
