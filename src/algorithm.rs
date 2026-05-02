use anyhow::Result;
use tokio_util::bytes::{Buf, Bytes};

use crate::{BytesExt, KexAlgorithm, Parse, SshNameList, SshString};

#[derive(Debug, Clone)]
pub struct Algorithm {
    pub cookie: [u8; 16],
    pub kex_algorithms: Vec<KexAlgorithm>,
    pub server_host_key_algorithms: SshNameList,
    pub encryption_algorithms_client_to_server: SshNameList,
    pub encryption_algorithms_server_to_client: SshNameList,
    pub mac_algorithms_client_to_server: SshNameList,
    pub mac_algorithms_server_to_client: SshNameList,
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
            server_host_key_algorithms: SshNameList::new(vec!["none"]),
            encryption_algorithms_client_to_server: SshNameList::new(vec!["none"]),
            encryption_algorithms_server_to_client: SshNameList::new(vec!["none"]),
            mac_algorithms_client_to_server: SshNameList::new(vec!["none"]),
            mac_algorithms_server_to_client: SshNameList::new(vec!["none"]),
            compression_algorithms_client_to_server: SshNameList::new(vec!["none"]),
            compression_algorithms_server_to_client: SshNameList::new(vec!["none"]),
            languages_client_to_server: SshNameList::new(vec!["none"]),
            languages_server_to_client: SshNameList::new(vec!["none"]),
            first_kex_packet_follows: false,
        }
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

        let kex_algorithms = SshNameList::parse_mut(&mut src)?;
        let server_host_key_algorithms = SshNameList::parse_mut(&mut src)?;
        let encryption_algorithms_client_to_server = SshNameList::parse_mut(&mut src)?;
        let encryption_algorithms_server_to_client = SshNameList::parse_mut(&mut src)?;
        let mac_algorithms_client_to_server = SshNameList::parse_mut(&mut src)?;
        let mac_algorithms_server_to_client = SshNameList::parse_mut(&mut src)?;
        let compression_algorithms_client_to_server = SshNameList::parse_mut(&mut src)?;
        let compression_algorithms_server_to_client = SshNameList::parse_mut(&mut src)?;
        let languages_client_to_server = SshNameList::parse_mut(&mut src)?;
        let languages_server_to_client = SshNameList::parse_mut(&mut src)?;

        let first_kex_packet_follows = src.try_get_u8()? != 0;
        let _reserved = src.try_get_u32();

        let kex_algorithms = kex_algorithms
            .name_list
            .into_iter()
            .map(|s| KexAlgorithm::from(s.as_str()))
            .collect::<Vec<_>>();

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
