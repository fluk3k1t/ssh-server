use anyhow::{Context, Result, anyhow};
use futures::SinkExt;
use p256::{ecdh::EphemeralSecret, elliptic_curve::rand_core::OsRng};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_stream::StreamExt;
use tokio_util::{
    bytes::{Buf, BufMut, Bytes, BytesMut},
    codec::Framed,
};
use tracing::info;

use crate::{
    Algorithm, BinaryPacketProtocol, EncodeToBytesMut, EphemeralPublicKey, Identification, Kex,
    KexAlgorithm, MessageNumber, Parse, RawMessage, RawMessageBuilder, SharedSecretKey,
    SignatureAlgorithm, SigningKey, SshBytesMut, SshNameList, SshString, VerifyingKey,
};

#[derive(Debug)]
pub struct SshServer {
    server_identification: Identification,
    client_identification: Option<String>,
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
                    info!("recv: SSH_MSG_KEXINIT");

                    let mut client_kexinit_payload = BytesMut::new();
                    client_kexinit_payload.put_u8(raw_msg.message_number as u8);
                    client_kexinit_payload.extend(raw_msg.paylaod.clone());
                    self.client_kexinit_payload = Some(client_kexinit_payload.freeze());

                    let (client_algorithm, _) = Algorithm::parse(&raw_msg.paylaod)?;

                    info!(
                        "client: kex_algorithm: {:?}",
                        client_algorithm.kex_algorithms[0]
                    );

                    info!(
                        "client: server_host_key_algorithm: {:?}",
                        client_algorithm.server_host_key_algorithms[0]
                    );

                    info!(
                        "client: encryption_algorithms_client_to_server: {:?}",
                        client_algorithm.encryption_algorithms_client_to_server[0]
                    );

                    info!(
                        "client: encryption_algorithms_server_to_client: {:?}",
                        client_algorithm.encryption_algorithms_server_to_client[0]
                    );

                    self.algorithm_negotiation(&client_algorithm).await?;
                }
                MessageNumber::SSH_MSG_KEX_ECDH_INIT => {
                    info!("recv: SSH_MSG_KEX_ECDH_INIT");

                    let kex = Kex::parse(&raw_msg.paylaod, &self.algorithm)?;
                    self.kex_exchange(&kex).await?;
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

    pub async fn kex_exchange(&mut self, kex: &Kex) -> Result<()> {
        let (server_host_key, server_public_key) =
            match &self.algorithm.server_host_key_algorithms[0] {
                SignatureAlgorithm::EcdsaSha2NistP256 => Ok(SigningKey::ecdsa()),
                SignatureAlgorithm::Unsupported(unsupported) => {
                    Err(anyhow!("unsupported signature: {:?}", unsupported))
                }
            }?;

        let (shared_secret, server_emphemeral_key) = match &self.algorithm.kex_algorithms[0] {
            KexAlgorithm::EcdhSha2NistP256 => {
                let server_secret = EphemeralSecret::random(&mut OsRng);
                let server_emphemeral_key =
                    EphemeralPublicKey::EcdaNistP256(server_secret.public_key());
                let shared_secret = match kex.client_ephemeral_public_key {
                    EphemeralPublicKey::EcdaNistP256(client_ephemeral_public_key) => {
                        SharedSecretKey::EcdaNistP256(
                            server_secret.diffie_hellman(&client_ephemeral_public_key),
                        )
                    }
                };

                Ok((shared_secret, server_emphemeral_key))
            }
            KexAlgorithm::Unsupported(unsupported) => {
                Err(anyhow!("unsupported kex exchange: {:?}", unsupported))
            }
        }?;

        let V_C: String = self.client_identification.as_ref().unwrap().clone();
        let V_S: String = self.server_identification.to_crlf_excluded_str();
        let I_C = self.client_kexinit_payload.clone().context("unreachable")?;
        let I_S = self.algorithm.encode();
        let K_S: VerifyingKey = server_public_key;
        let Q_C: EphemeralPublicKey = kex.client_ephemeral_public_key.clone();
        let Q_S: EphemeralPublicKey = server_emphemeral_key.clone();
        let K: SharedSecretKey = shared_secret;

        let concatenation: BytesMut = BytesMut::new()
            .put_ssh_string(V_C)
            .put_ssh_string(V_S)
            .put_ssh_string(I_C)
            .put_ssh_string(I_S)
            .put_ssh_string(K_S.encode())
            .put(Q_C.clone())
            .put(Q_S.clone())
            .put(K);

        let H = Sha256::digest(concatenation);
        let sign = server_host_key.sign(&H);

        let edch_reply = RawMessageBuilder::new(MessageNumber::SSH_MSG_KEX_ECDH_REPLY)
            .put_ssh_string(K_S.encode())
            .put(Q_S)
            .put(sign)
            .build();

        self.codec.send(edch_reply.to_bytes()).await?;

        Ok(())
    }

    pub async fn algorithm_negotiation(&mut self, client_algorithm: &Algorithm) -> Result<()> {
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

        let client_identification = String::from_utf8_lossy(&buf).to_string();
        self.client_identification =
            Some(client_identification.trim_end_matches("\r\n").to_string());

        let mut client_identification = client_identification.split(" ");
        let client_identification = client_identification.next().unwrap().to_string();

        let (protoversion, softwareversion) = {
            let mut splitted = client_identification.splitn(3, "-");
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

        info!(
            "client: identification: {}",
            self.client_identification.clone().unwrap()
        );

        self.codec
            .get_mut()
            .write_all(
                format!("{}\r\n", self.server_identification.to_crlf_excluded_str()).as_bytes(),
            )
            .await?;

        Ok(())
    }
}
