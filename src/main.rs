use bytes::{Buf, BufMut, BytesMut};
use ed25519_dalek::Signer;
use ed25519_dalek::pkcs8::KeypairBytes;
// use ecdsa::VerifyingKey;
use futures::{SinkExt, Stream, StreamExt};
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::PublicKey;
use p256::elliptic_curve::rand_core::OsRng;
use p256::pkcs8::{DecodePublicKey, EncodePublicKey};
use p256::{EncodedPoint, NistP256};
use sha2::{Digest, Sha256};
// use ssh_key::PublicKey;
// use sec1::EncodedPoint;
use ssh_server::{
    AlgorithmNegotiation, BinaryPacketDecoder, Encode, MessageNumber, NameList, Parse, Payload,
    SpString,
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

    pub fn encode(&self) -> String {
        format!("SSH-{}-{}", self.protoversion, self.softwareversion)
    }
}

use ssh_encoding::Writer;
pub(crate) fn encode_mpint(s: &[u8], w: &mut BytesMut) -> Result<(), ssh_encoding::Error> {
    use ssh_encoding::Encode;
    // Skip initial 0s.
    let mut i = 0;
    while i < s.len() && s[i] == 0 {
        i += 1
    }
    // If the first non-zero is >= 128, write its length (u32, BE), followed by 0.
    if s[i] & 0x80 != 0 {
        // ((s.len() - i + 1) as u32).encode(w)?;
        w.put_u32(((s.len() - i + 1) as u32));
        // 0u8.encode(w)?;
        w.put_u8(0);
    } else {
        // ((s.len() - i) as u32).encode(w)?;
        w.put_u32(((s.len() - i) as u32));
    }
    w.extend_from_slice(&s[i..]);

    Ok(())
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

        self.exchange_key().await?;

        Ok(())
    }

    async fn exchange_key(&mut self) -> io::Result<()> {
        let (mut read_half, write_half) = self.stream.split();
        let mut binary_packet_reader = FramedRead::new(read_half, BinaryPacketDecoder::default());

        // let mut writer = FramedWrite::new(write_half, BinaryPacketEncoder::default());
        let mut writer = FramedWrite::new(write_half, BinaryPacketEncoder::default());

        let mut binary_packet = binary_packet_reader
            .next()
            .await
            .ok_or(Error::other("failed to read binary packet"))??;

        let algo_nego = AlgorithmNegotiation::parse(&mut binary_packet.payload)?;

        let mut server_algo_nego = algo_nego.clone();
        server_algo_nego.server_host_key_algorithms =
            NameList::new(vec!["ssh-ed25519".to_string()]);

        println!("{:?}", server_algo_nego.server_host_key_algorithms);

        let server_algo_nego_encoded = server_algo_nego.encode();

        writer.send(server_algo_nego_encoded.clone()).await?;

        let mut ecdh = binary_packet_reader
            .next()
            .await
            .ok_or(Error::other("failed to read binary packet"))??;

        let ecdh = EcdhKex::parse(&mut ecdh.payload)?;

        // SigningKey経由でしかKeyPairを生成できないのは不用意にprivateを露出させないみたいな意図があるんでしょうかね
        // 何にしてもdocs読んで型変換探すのがだるいのでやめてほしい所存
        let server_signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);

        // サーバー側では秘密鍵を保持しておいて二回目以降で使い回し、クライアントは初回に送信された公開鍵を保存しておいて二回目以降で照合してmitmを防ぐ的な
        // WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! の話
        let server_keypair = KeypairBytes::from_bytes(&server_signing_key.to_keypair_bytes());
        let server_secret = EphemeralSecret::random(&mut OsRng);

        let server_shared = server_secret.diffie_hellman(&ecdh.client_public_key);
        let server_tmp_public = server_secret.public_key();

        let V_C = self.client_identification.clone().unwrap();
        let V_C = V_C.encode();
        let V_C = V_C.trim_end_matches("\r\n");

        let V_C = BytesMut::from(V_C);

        let V_S = BytesMut::from("SSH-2.0-OpenSSH_10.0");
        let I_C = algo_nego.encode();

        let I_S = server_algo_nego_encoded;
        let mut K_S_NAME = BytesMut::from("ssh-ed25519");
        let mut K_S_KEY = BytesMut::from(&server_keypair.public_key.unwrap().to_bytes()[..]);
        let mut k_s = BytesMut::new();

        k_s.put(SpString::encode(&K_S_NAME));
        k_s.put(SpString::encode(&K_S_KEY));

        // ecdh_reply.put(SpString::encode(&k_s));
        // println!("{:?}", K_S);

        let Q_C = BytesMut::from(&ecdh.client_public_key.to_sec1_bytes()[..]);

        let Q_S = BytesMut::from(&server_tmp_public.to_sec1_bytes()[..]);

        // let K = BytesMut::from(server_shared.raw_secret_bytes().as_slice());
        let mut K = BytesMut::new();
        encode_mpint(server_shared.raw_secret_bytes(), &mut K).unwrap();

        let mut exchange_concatation = BytesMut::new();
        // V_C.encode

        exchange_concatation.put(SpString::encode(&V_C));
        exchange_concatation.put(SpString::encode(&V_S));
        exchange_concatation.put(SpString::encode(&I_C));
        exchange_concatation.put(SpString::encode(&I_S));
        exchange_concatation.put(SpString::encode(&k_s.clone()));
        // exchange_concatation.put(SpString::encode(&K_S_KEY.clone()));
        exchange_concatation.put(SpString::encode(&Q_C));
        exchange_concatation.put(SpString::encode(&Q_S.clone()));
        exchange_concatation.put(&mut K.clone());

        let H = Sha256::digest(exchange_concatation);

        let mut ecdh_reply = BytesMut::new();
        ecdh_reply.put_u8(MessageNumber::SSH_MSG_KEX_ECDH_REPLY as u8);
        ecdh_reply.put(SpString::encode(&k_s));
        ecdh_reply.put(SpString::encode(&Q_S));

        let sign = server_signing_key.sign(&H);
        let mut sig_blob = BytesMut::new();
        sig_blob.put(SpString::encode(&BytesMut::from("ssh-ed25519")));
        sig_blob.put(SpString::encode(&BytesMut::from(&sign.to_bytes()[..])));

        ecdh_reply.put(SpString::encode(&sig_blob));
        // ecdh_reply.put(SpString::encode(&BytesMut::from(&sign.to_bytes()[..])));

        dump::<16>(&ecdh_reply);
        writer.send(ecdh_reply).await?;

        Ok(())
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
