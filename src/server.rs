use aes::{
    Aes128,
    cipher::{Array, KeyIvInit, StreamCipher, array::ArraySize},
};
use anyhow::{Context, Result, anyhow};
use futures::SinkExt;
use p256::{U32, ecdh::EphemeralSecret, elliptic_curve::rand_core::OsRng};
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
    Algorithm, BinaryPacketProtocol, Cipher, Codec, EncodeToBytesMut, EncryptedBinaryPacketCodec,
    EphemeralPublicKey, Identification, Kex, KexAlgorithm, MessageNumber, Parse, RawMessage,
    RawMessageBuilder, ServiceRequest, SharedSecretKey, SignatureAlgorithm, SigningKey,
    SshBytesMut, SshNameList, SshString, VerifyingKey,
};

pub type Aes128Ctr128BE = ctr::Ctr128BE<aes::Aes128>;
pub struct SshServer {
    server_identification: Identification,
    client_identification: Option<String>,
    client_kexinit_payload: Option<Bytes>,
    algorithm: Algorithm,
    codec: Framed<TcpStream, Codec>,
    cipher: Option<Aes128Ctr128BE>,
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
            codec: Framed::new(stream, Codec::Plain(BinaryPacketProtocol::new())),
            cipher: None,
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

            let mut packet: BytesMut = self
                .codec
                .next()
                .await
                .context("failed to read binary packet for some reasons")??
                .into();

            if let Some(cipher) = self.cipher.as_mut() {
                cipher.apply_keystream(&mut packet);
            }

            let raw_msg = RawMessage::parse(&packet.freeze())?;
            info!("recv: {:?}", raw_msg.message_number);

            match raw_msg.message_number {
                MessageNumber::SSH_MSG_KEXINIT => {
                    self.client_kexinit_payload = Some(raw_msg.to_bytes());

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
                    let kex = Kex::parse(&raw_msg.paylaod, &self.algorithm)?;
                    self.kex_exchange(&kex).await?;
                }
                MessageNumber::SSH_MSG_SERVICE_REQUEST => {
                    let (service_req, _) = ServiceRequest::parse(&raw_msg.paylaod)?;
                    self.service_request(service_req).await?;
                }
                _ => {
                    println!("{:?}", raw_msg);
                    todo!();
                }
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

    pub async fn service_request(&mut self, service_request: ServiceRequest) -> Result<()> {
        match service_request {
            ServiceRequest::UserAuth => {
                let accept_msg = RawMessageBuilder::new(MessageNumber::SSH_MSG_SERVICE_ACCEPT)
                    .put_ssh_string("ssh-userauth")
                    .build();

                self.codec.send(accept_msg.to_bytes()).await?;
            }
            ServiceRequest::Connection => todo!(),
        }

        Ok(())
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
            .put_ssh_mpint(K.encode());

        let H: Array<u8, U32> = Sha256::digest(concatenation);
        let sign = server_host_key.sign(&H);

        let edch_reply = RawMessageBuilder::new(MessageNumber::SSH_MSG_KEX_ECDH_REPLY)
            .put_ssh_string(K_S.encode())
            .put(Q_S)
            .put(sign)
            .build();

        self.codec.send(edch_reply.to_bytes()).await?;

        let mut new_keys = self.codec.next().await.unwrap()?;

        let new_keys = RawMessageBuilder::new(MessageNumber::SSH_MSG_NEWKEYS).build();
        self.codec.send(new_keys.to_bytes()).await?;

        let session_id = H.clone();

        let (c2s_cipher, c2s_hmac_key) = {
            let c2s_iv = SshServer::compute_shared_secret_hash(&K, H, 'A', session_id);
            let c2s_iv: [u8; 16] = c2s_iv[0..16].try_into().unwrap();

            let c2s_enc_key = SshServer::compute_shared_secret_hash(&K, H, 'C', session_id);
            let c2s_enc_key: [u8; 16] = c2s_enc_key[0..16].try_into().unwrap();

            let c2s_int_key = SshServer::compute_shared_secret_hash(&K, H, 'E', session_id);
            let cipher = Aes128Ctr128BE::new(&c2s_enc_key.into(), &c2s_iv.into());

            (cipher, c2s_int_key)
        };

        let (s2c_cipher, s2c_hmac_key) = {
            let s2c_iv = SshServer::compute_shared_secret_hash(&K, H, 'B', session_id);
            let s2c_iv: [u8; 16] = s2c_iv[0..16].try_into().unwrap();

            let s2c_enc_key = SshServer::compute_shared_secret_hash(&K, H, 'D', session_id);
            let s2c_enc_key: [u8; 16] = s2c_enc_key[0..16].try_into().unwrap();

            let s2c_int_key = SshServer::compute_shared_secret_hash(&K, H, 'F', session_id);
            let cipher = Aes128Ctr128BE::new(&s2c_enc_key.into(), &s2c_iv.into());

            (cipher, s2c_int_key)
        };

        self.codec
            .codec_mut()
            .upgrade(c2s_cipher, s2c_cipher, c2s_hmac_key, s2c_hmac_key);

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

    fn compute_shared_secret_hash(
        k: &SharedSecretKey,
        h: Array<u8, U32>,
        c: char,
        session_id: Array<u8, U32>,
    ) -> Array<u8, U32> {
        let shared = BytesMut::new()
            .put_ssh_mpint(k.encode())
            .put_bytes(Bytes::from_iter(h.clone()))
            .put_bytes(Bytes::from(String::from(c)))
            .put_bytes(Bytes::from_iter(session_id.clone()));

        Sha256::digest(shared)
    }
}
