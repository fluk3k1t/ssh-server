use anyhow::{Context, Result, anyhow};
use futures::SinkExt;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_stream::StreamExt;
use tokio_util::{
    bytes::{Bytes, BytesMut},
    codec::Framed,
};
use tracing::info;

use crate::{
    Algorithm, BinaryPacketProtocol, EncodeToBytesMut, Identification, Kex, KexAlgorithm,
    MessageNumber, Parse, RawMessage, SignatureAlgorithm, SshNameList,
};

#[derive(Debug)]
pub struct SshServer {
    server_identification: Identification,
    client_identification: Option<Identification>,
    client_kexinit_payload: Option<Bytes>,
    algorithm: Algorithm,
    codec: Framed<TcpStream, BinaryPacketProtocol>,
    state: SshServerState,
}

#[derive(Debug)]
pub enum SshServerState {
    WaitForProtoVerEx,
    WaitForKexInit,
}

#[derive(Debug)]
pub struct SshServerBuilder {
    kex_algorithm: KexAlgorithm,
    server_host_key_algorithm: SignatureAlgorithm,
}

impl Default for SshServerBuilder {
    fn default() -> Self {
        SshServerBuilder {
            kex_algorithm: KexAlgorithm::EcdhSha2NistP256,
            server_host_key_algorithm: SignatureAlgorithm::EcdsaSha2NistP256,
        }
    }
}

impl SshServerBuilder {
    pub fn build(self, stream: TcpStream) -> SshServer {
        let protoversion = "2.0"; // RFC4253 version 2.0
        let softwareversion = "0.0"; // manually increment
        let identification = Identification::new(protoversion, softwareversion);

        SshServer {
            server_identification: identification,
            client_identification: None,
            client_kexinit_payload: None,
            algorithm: Algorithm::default(),
            codec: Framed::new(stream, BinaryPacketProtocol::new()),
            state: SshServerState::WaitForProtoVerEx,
        }
    }
}

impl SshServer {
    pub async fn run(&mut self) -> Result<()> {
        loop {
            if let SshServerState::WaitForProtoVerEx = self.state {
                info!("waiting for protocol version exchange");

                self.protocol_version_exchange().await?;
                self.checked_transition()?;

                continue;
            }

            let packet = self
                .codec
                .next()
                .await
                .context("failed to read binary packet for some reasons")??;

            let raw_msg = RawMessage::parse(&packet)?;

            match raw_msg.message_number {
                MessageNumber::SSH_MSG_KEXINIT => {
                    // exchange hashの生成で使用
                    self.client_kexinit_payload = Some(raw_msg.paylaod.clone());

                    let (algo, _) = Algorithm::parse(&raw_msg.paylaod)?;

                    info!("client: kex_algorithm: {:?}", algo.kex_algorithms[0]);

                    info!(
                        "client: server_host_key_algorithm: {:?}",
                        algo.server_host_key_algorithms[0]
                    );

                    info!(
                        "client: encryption_algorithms_client_to_server: {:?}",
                        algo.encryption_algorithms_client_to_server[0]
                    );

                    info!(
                        "client: encryption_algorithms_server_to_client: {:?}",
                        algo.encryption_algorithms_server_to_client[0]
                    );

                    self.algorithm_negotiation(&algo).await?;
                }
                _ => todo!(),
            }
        }
    }

    pub fn checked_transition(&mut self) -> Result<()> {
        match &mut self.state {
            SshServerState::WaitForProtoVerEx => {
                if self.client_identification.is_some() {
                    self.state = SshServerState::WaitForKexInit;
                }

                Ok(())
            }
            SshServerState::WaitForKexInit => {
                todo!()
            }
        }
    }

    pub async fn algorithm_negotiation(&mut self, client_algorithm: &Algorithm) -> Result<()> {
        // println!("")

        let server_algorithm = self.algorithm.encode();

        self.codec.send(server_algorithm).await?;

        Ok(())
    }

    pub async fn protocol_version_exchange(&mut self) -> Result<()> {
        let mut buf = BytesMut::new();

        loop {
            self.codec.get_mut().read_buf(&mut buf).await?;
            if buf.windows(2).any(|w| w == b"\r\n") {
                break;
            }
        }

        let client_identification = String::from_utf8_lossy(&buf);

        let (protoversion, softwareversion) = {
            let mut splitted = client_identification.split("-");
            let _ = splitted.next();

            let protoversion = splitted
                .next()
                .map(String::from)
                .context("failed to parse protoversion")?;

            let softwareversion = splitted
                .next()
                .map(String::from)
                .context("failed to parse softwareversion")?;

            (protoversion, softwareversion)
        };

        let client_identification = Identification::new(protoversion, softwareversion);

        info!(
            "client: identification: {}",
            client_identification.as_crlf_excluded_str()
        );

        self.codec
            .get_mut()
            .write_all(
                format!("{}\r\n", self.server_identification.as_crlf_excluded_str()).as_bytes(),
            )
            .await?;

        self.client_identification = Some(client_identification);

        Ok(())
    }
}
