use bytes::{Buf, BufMut, BytesMut};
use ed25519_dalek::Signer;
use ed25519_dalek::pkcs8::KeypairBytes;
// use ecdsa::VerifyingKey;
use bytes::Bytes;
use futures::{SinkExt, Stream, StreamExt};
use p256::ecdh::EphemeralSecret;
use p256::ecdsa::Signature;
use p256::ecdsa::signature::SignerMut;
use p256::elliptic_curve::PublicKey;
use p256::elliptic_curve::rand_core::OsRng;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::{DecodePublicKey, EncodePublicKey};
use p256::{EncodedPoint, NistP256, ecdsa};
use sha2::{Digest, Sha256};
// use ssh_key::PublicKey;
// use sec1::EncodedPoint;
use ssh_server::{
    AlgorithmNegotiation, BinaryPacketDecoder, ByteStream, Encode, EncodeToBytesMut, Message,
    MessageNumber, NameList, Parse, Payload, SpString, SshMpInt, SshPublicKey, SshString,
};
use ssh_server::{BinaryPacketEncoder, EcdhKex};
use std::io::{self, Error, Sink};
use tokio::io::AsyncWrite;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
// use tokio_stream::StreamExt;
use p256::ecdsa::{VerifyingKey, signature::Verifier};
use tokio_util::codec::{Framed, FramedRead, FramedWrite};

#[tokio::main]
async fn main() -> io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:2020").await?;

    loop {
        let (stream, _) = listener.accept().await?;
        let mut ssh_server = SshServer::new(stream);
        ssh_server.handle_connection().await?;
    }
}

pub struct SshServer {
    // binary_packet_reader: Framed<TcpStream, BinaryPacketDecoder>,
    stream: TcpStream,
    client_identification: Option<Identification>,
}

#[derive(Debug, Clone)]
pub struct Identification {
    softwareversion: String,
    protoversion: String,
}

impl Identification {
    pub fn new(protoversion: String, softwareversion: String) -> Self {
        Identification {
            softwareversion,
            protoversion,
        }
    }

    pub fn as_crlf_excluded_str(&self) -> String {
        format!("SSH-{}-{}", self.protoversion, self.softwareversion)
            .trim_end_matches("\r\n")
            .to_string()
    }
}

impl SshServer {
    pub fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            client_identification: None,
        }
    }

    pub async fn handle_connection(&mut self) -> io::Result<()> {
        let client_identification = self.excahnge_identification().await?;
        self.client_identification = Some(client_identification);

        self.key_exchange().await?;

        Ok(())
    }

    async fn key_exchange(&mut self) -> io::Result<()> {
        let (client_algorithm, i_c_raw, i_s_raw) = self.alghorithm_negotiation().await?;

        println!("{:?}", client_algorithm.server_host_key_algorithms);

        // TODO: self.algorithm_negotiationで応答したものを使用すべき
        let mut server_algo_nego = client_algorithm.clone();
        server_algo_nego.server_host_key_algorithms =
            // NameList::new(vec!["ecdsa-sha2-nistp256-cert-v01@openssh.com".to_string()]);
        // server_algo_nego.server_host_key_algorithms =
            NameList::new(vec!["ecdsa-sha2-nistp256".to_string()]);
        // println!("{:?}", client_algorithm.server_host_key_algorithms);

        let (mut read_half, write_half) = self.stream.split();
        let mut binary_packet_reader = FramedRead::new(read_half, BinaryPacketDecoder::default());

        let mut ecdh = binary_packet_reader
            .next()
            .await
            .ok_or(Error::other("failed to read binary packet"))??;

        let ecdh = EcdhKex::parse(&mut ecdh.payload)?;
        let server_signing_key = ecdsa::SigningKey::random(&mut OsRng);
        let server_secret = EphemeralSecret::random(&mut OsRng);
        let server_shared = server_secret.diffie_hellman(&ecdh.client_public_key);
        let server_tmp_public = server_secret.public_key();
        let verifying_key = server_signing_key.verifying_key();
        let q = verifying_key.to_encoded_point(false);
        let mut pubkey_blob = BytesMut::new();
        SshString::new("ecdsa-sha2-nistp256").encode(&mut pubkey_blob);
        SshString::new("nistp256").encode(&mut pubkey_blob);
        SshString::new(q.as_bytes().to_vec()).encode(&mut pubkey_blob);
        let k_s = SshString::new(pubkey_blob.clone());
        let v_c = self
            .client_identification
            .as_ref()
            .unwrap()
            .as_crlf_excluded_str();
        // );
        // let v_s = SshString::new("SSH-2.0-OpenSSH_10.0");
        // let i_c = SshString::new(i_c_raw);
        // let i_s = SshString::new(i_s_raw);
        // let q_c = SshString::new(ecdh.client_public_key.to_sec1_bytes());
        let q_s = SshString::new(server_tmp_public.to_encoded_point(false).to_bytes());

        let k = SshMpInt::new(server_shared.raw_secret_bytes().to_vec());

        // let exchange_concatation = ByteStream::new()
        //     .ssh_string(v_c.as_bytes())
        //     .ssh_string("SSH-2.0-OpenSSH_10.0")
        //     .ssh_string(i_c_raw)
        //     .ssh_string(i_s_raw)
        //     .ssh_string(pubkey_blob)
        //     .ssh_string(&ecdh.client_public_key.to_sec1_bytes()[..])
        //     .ssh_string(&server_tmp_public.to_sec1_bytes()[..])
        //     .ssh_mpint(&server_shared.raw_secret_bytes()[..]);
        let exchange_concatation = ByteStream::new()
            .ssh_string(
                self.client_identification
                    .as_ref()
                    .unwrap()
                    .as_crlf_excluded_str()
                    .as_bytes(),
            ) // V_C
            .ssh_string("SSH-2.0-OpenSSH_10.0") // V_S
            .ssh_string(i_c_raw) // I_C
            .ssh_string(i_s_raw) // I_S
            .ssh_string(pubkey_blob.clone()) // K_S
            .ssh_string(
                ecdh.client_public_key.to_encoded_point(false).as_bytes(), // .to_vec(),
            ) // Q_C
            .ssh_string(
                server_tmp_public.to_encoded_point(false).as_bytes(), // .to_vec(),
            ) // Q_S
            .ssh_mpint(&server_shared.raw_secret_bytes()[..]);
        // .ssh_mpint(server_shared.raw_secret_bytes()); // K

        let h = Sha256::digest(exchange_concatation.buffer);

        let sign: Signature = server_signing_key.sign(&h);

        let mut sign_blob = BytesMut::new();
        SshString::new("ecdsa-sha2-nistp256").encode(&mut sign_blob);

        let mut sign_blob_text = BytesMut::new();
        SshMpInt::new(sign.r().to_bytes().to_vec()).encode(&mut sign_blob_text);
        SshMpInt::new(sign.s().to_bytes().to_vec()).encode(&mut sign_blob_text);

        SshString::new(sign_blob_text.to_vec()).encode(&mut sign_blob);
        // SshString::new(sign.to_vec()).encode(&mut sign_blob);
        let sign_str = SshString::new(sign_blob);

        let test = SshString::new("hello");

        let msg = Message::new(MessageNumber::SSH_MSG_KEX_ECDH_REPLY)
            // .extend(q_s.clone())
            // .extend(q_s.clone())
            // .extend(q_s.clone());
            // .extend(test.clone())
            // .extend(test.clone())
            // .extend(test.clone());
            // .extend(k_s.clone())
            // .extend(k_s.clone())
            .extend(k_s)
            .extend(q_s)
            .extend(sign_str);

        let test = SshString::new("hello");
        let mut test_buf = BytesMut::new();
        test.encode(&mut test_buf);
        // println!("{:?}", test_buf);
        // dump::

        dump::<16>(&test_buf);

        dump::<16>(&msg.buffer);

        // msg.buffer

        let mut writer = FramedWrite::new(write_half, BinaryPacketEncoder::default());
        writer.send(msg.buffer).await?;

        // let

        Ok(())
    }

    async fn alghorithm_negotiation(
        &mut self,
    ) -> io::Result<(AlgorithmNegotiation, BytesMut, BytesMut)> {
        let (mut read_half, write_half) = self.stream.split();
        let mut binary_packet_reader = FramedRead::new(read_half, BinaryPacketDecoder::default());

        // let mut writer = FramedWrite::new(write_half, BinaryPacketEncoder::default());
        let mut writer = FramedWrite::new(write_half, BinaryPacketEncoder::default());

        let mut binary_packet = binary_packet_reader
            .next()
            .await
            .ok_or(Error::other("failed to read binary packet"))??;

        let saved2 = binary_packet.payload.inner.clone();

        let algo_nego = AlgorithmNegotiation::parse(&mut binary_packet.payload)?;

        // Selfに保存するなり何なり
        let mut server_algo_nego = algo_nego.clone();
        server_algo_nego.server_host_key_algorithms =
            NameList::new(vec!["ecdsa-sha2-nistp256".to_string()]);

        // println!("{:?}", server_algo_nego.server_host_key_algorithms);

        let server_algo_nego_encoded = server_algo_nego.encode();
        let saved = server_algo_nego_encoded.clone();

        writer.send(server_algo_nego_encoded.clone()).await?;

        Ok((algo_nego, saved2, saved))
    }

    async fn excahnge_identification(&mut self) -> io::Result<Identification> {
        let mut buf = BytesMut::new();

        loop {
            self.stream.read_buf(&mut buf).await?;
            if buf.windows(2).any(|w| w == b"\r\n") {
                break;
            }
        }

        // println!("{:?}", String::from_utf8_lossy(&buf));

        let identification = String::from_utf8_lossy(&buf);

        let (protoversion, softwareversion) = {
            let mut splitted = identification.split("-");
            let _ = splitted.next();

            let protoversion = splitted
                .next()
                .map(String::from)
                .ok_or(Error::other("failed to parse protoversion"))?;

            let softwareversion = splitted
                .next()
                .map(String::from)
                .ok_or(Error::other("failed to parse softwareversion"))?;

            (protoversion, softwareversion)
        };

        self.stream.write_all(b"SSH-2.0-OpenSSH_10.0\r\n").await?;

        Ok(Identification::new(protoversion, softwareversion))
    }

    async fn debug_read(&mut self) -> io::Result<String> {
        let mut buf = BytesMut::new();

        self.stream.read_buf(&mut buf).await?;

        Ok(String::from_utf8_lossy(&buf).to_string())
    }
}

fn dump<const N: usize>(src: &BytesMut) {
    for row in src.chunks(N) {
        println!("{:02x?}", row);
    }
}
