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
    AlgorithmNegotiation, BinaryPacketCodec, ByteStream, Cipher, Encode, EncodeToBytesMut,
    EncryptedBinaryPacketCodec, Message, MessageNumber, NameList, Parse, Payload, Service,
    SshMpInt, SshPublicKey, SshString,
};
use ssh_server::{EcdhKex, SshSignature};
use std::io::{self, Error, Sink};
use tokio::io::AsyncWrite;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_util::codec::{Encoder, Framed, FramedRead};
//
#[tokio::main]
async fn main() -> io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:2020").await?;

    loop {
        let (stream, _) = listener.accept().await?;
        let mut ssh_server = SshServer::new(stream);
        ssh_server.handle_connection().await?;
    }
}

type Aes128Ctr128BE = ctr::Ctr128BE<aes::Aes128>;
pub struct SshServer {
    // binary_packet_reader: Framed<TcpStream, BinaryPacketDecoder>,
    stream: Option<TcpStream>,
    client_identification: Option<Identification>,
    client_kex_init_payload: Option<Bytes>,
    server_kex_init_payload: Option<Bytes>,

    kex_algorithms: String,
    server_host_key_algorithms: String,
    encryption_algorithms_client_to_server: String,
    encryption_algorithms_server_to_client: String,
    mac_algorithms_client_to_server: String,
    mac_algorithms_server_to_client: String,
    // cipher: Option<Cipher>,
    enc_codec: Option<Framed<TcpStream, EncryptedBinaryPacketCodec>>,
    shared_key: Option<Vec<u8>>,
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
use aes::Aes128;
use ctr::Ctr128BE; // or LE depending on spec
use ctr::cipher::{KeyIvInit, StreamCipher};
type Aes128Ctr = Ctr128BE<Aes128>;

impl SshServer {
    pub fn new(stream: TcpStream) -> Self {
        Self {
            stream: Some(stream),
            client_identification: None,
            client_kex_init_payload: None,
            server_kex_init_payload: None,
            kex_algorithms: "ecdh-sha2-nistp256".to_owned(),
            server_host_key_algorithms: "ecdsa-sha2-nistp256".to_owned(),
            encryption_algorithms_client_to_server: "aes128-ctr".to_owned(),
            encryption_algorithms_server_to_client: "aes128-ctr".to_owned(),
            mac_algorithms_client_to_server: "hmac-sha2-256".to_owned(),
            mac_algorithms_server_to_client: "hmac-sha2-256".to_owned(),
            // cipher: None,
            shared_key: None,
            enc_codec: None,
        }
    }

    pub async fn handle_connection(&mut self) -> io::Result<()> {
        let client_identification = self.excahnge_identification().await?;
        self.client_identification = Some(client_identification);

        let cipher = self.key_exchange().await?;

        let mut stream = self.stream.take().unwrap();
        let mut encrypted_binary_codec: Framed<&mut TcpStream, EncryptedBinaryPacketCodec> =
            Framed::new(&mut stream, EncryptedBinaryPacketCodec::new(cipher));

        self.service_request(&mut encrypted_binary_codec).await?;

        Ok(())
    }

    async fn service_request(
        &mut self,
        codec: &mut Framed<&mut TcpStream, EncryptedBinaryPacketCodec>,
    ) -> io::Result<()> {
        let service_req_msg = codec.next().await.unwrap()?;
        let service_req_msg = Service::parse(service_req_msg.payload.inner.clone())?;

        if service_req_msg.service_name.as_str() != "ssh-userauth" {
            todo!()
        }

        let mut service = BytesMut::new();
        service.put_u8(MessageNumber::SSH_MSG_SERVICE_ACCEPT as u8);
        SshString::new("ssh-userauth").encode(&mut service);

        let mut packet = BytesMut::new();
        // codec.codec_mut().encode(service.clone(), &mut packet)?;
        // codec.

        let sequence_number = 6 as u32;

        let mut mac = BytesMut::new();
        mac.put_u32(sequence_number);
        mac.put(packet.clone());

        let mac = hmac_sha256::HMAC::mac(mac, self.shared_key.as_mut().unwrap());

        let mut ff = BytesMut::new();
        codec.codec_mut().encode(service.clone(), &mut ff)?;
        ff.put(&mac[..]);

        dump::<8>(&ff);

        // codec.send(service).await?;
        codec.get_mut().write_all(&ff).await?;

        Ok(())
    }

    async fn key_exchange(&mut self) -> io::Result<Cipher> {
        let client_algorithm = self.alghorithm_negotiation().await?;

        let mut stream = self.stream.as_mut().unwrap();
        let mut binary_packet_codec = Framed::new(&mut stream, BinaryPacketCodec::Header);

        let mut ecdh = binary_packet_codec
            .next()
            .await
            .ok_or(Error::other("failed to read binary packet"))??;

        let ecdh = EcdhKex::parse(ecdh.payload.inner.clone())?;
        let server_signing_key = ecdsa::SigningKey::random(&mut OsRng);
        let server_secret = EphemeralSecret::random(&mut OsRng);
        let server_shared = server_secret.diffie_hellman(&ecdh.client_public_key);
        let server_tmp_public = server_secret.public_key();
        let verifying_key = server_signing_key.verifying_key();

        self.shared_key = Some(server_shared.raw_secret_bytes().to_vec());

        let k_s = SshPublicKey::new("nistp256", *verifying_key);
        let v_c = self
            .client_identification
            .as_ref()
            .unwrap()
            .as_crlf_excluded_str();

        let k = server_shared.raw_secret_bytes().to_vec();
        let q_c = ecdh.client_public_key.to_encoded_point(false).to_bytes();
        let q_s = server_tmp_public.to_encoded_point(false).to_bytes();

        let exchange_concatation = ByteStream::new()
            .ssh_string(v_c) // V_C
            .ssh_string("SSH-2.0-OpenSSH_10.0") // V_S
            .ssh_string(self.client_kex_init_payload.clone().unwrap()) // I_C
            .ssh_string(self.server_kex_init_payload.clone().unwrap()) // I_S
            .extend(k_s.clone()) // K_S
            .ssh_string(q_c) // Q_C
            .ssh_string(q_s.clone()) // Q_S
            .ssh_mpint(k.clone()); // K

        let h = Sha256::digest(exchange_concatation.buffer);

        let session_id = h.clone();
        let iv = ByteStream::new()
            .ssh_mpint(k.clone())
            .put(Bytes::from_iter(h.clone()))
            .put(Bytes::from("A"))
            .put(Bytes::from_iter(session_id.clone()));
        let iv = Sha256::digest(iv.buffer);
        let iv: [u8; 16] = iv[0..16].try_into().unwrap();
        // self.

        let sign: Signature = server_signing_key.sign(&h);
        let sign = SshSignature::new(sign, "nistp256");

        let msg = Message::new(MessageNumber::SSH_MSG_KEX_ECDH_REPLY)
            .extend(k_s)
            .ssh_string(q_s)
            .extend(sign);

        binary_packet_codec.send(msg.buffer).await?;

        let mut new_keys = binary_packet_codec
            .next()
            .await
            .ok_or(Error::other("failed to read binary packet"))??;

        let msg = Message::new(MessageNumber::SSH_MSG_NEWKEYS);
        binary_packet_codec.send(msg.buffer).await?;

        let enc_key_material = ByteStream::new()
            .ssh_mpint(k.clone())
            .put(Bytes::from_iter(h.clone()))
            .put(Bytes::from("C"))
            .put(Bytes::from_iter(session_id.clone()));
        let enc_key = Sha256::digest(enc_key_material.buffer);
        let enc_key: [u8; 16] = enc_key[0..16].try_into().unwrap();

        let mut cipher: aes::cipher::StreamCipherCoreWrapper<
            ctr::CtrCore<Aes128, ctr::flavors::Ctr128BE>,
        > = Aes128Ctr128BE::new(&enc_key.into(), &iv.into());

        // self.cipher = Some(cipher);

        // println!("hey");
        // let mut encrypted_binary_codec =
        //     FramedRead::new(stream, EncryptedBinaryPacketCodec::new(cipher));

        // let enc = encrypted_binary_codec.next().await.unwrap()?;

        // let mut test_buf = [0; 1024];

        // binary_packet_codec.get_mut().read(&mut test_buf).await?;

        // // println!("{:?}", &test_buf[..32]);
        // // cipher.apply_keystream(&mut test_buf[..32]);

        // for chunk in test_buf.chunks_mut(16) {
        //     cipher.apply_keystream(chunk);
        // }

        // println!("{}", String::from_utf8_lossy(&test_buf[10..32]));

        Ok(cipher)
    }
    async fn alghorithm_negotiation(&mut self) -> io::Result<AlgorithmNegotiation> {
        let mut stream = self.stream.as_mut().unwrap();
        let mut binary_packet_codec = Framed::new(&mut stream, BinaryPacketCodec::Header);

        let mut binary_packet = binary_packet_codec
            .next()
            .await
            .ok_or(Error::other("failed to read binary packet"))??;

        // parseでinner: BytesMutの内部カーソルが進んでしまうので、parseする前にコピー
        self.client_kex_init_payload = Some(binary_packet.payload.inner.clone().freeze());

        let algo_nego = AlgorithmNegotiation::parse(binary_packet.payload.inner.clone())?;

        // Selfに保存するなり何なり
        let mut server_algo_nego = algo_nego.clone();
        server_algo_nego.server_host_key_algorithms =
            NameList::new(vec![self.server_host_key_algorithms.clone()]);

        server_algo_nego.encryption_algorithms_client_to_server =
            NameList::new(vec![self.encryption_algorithms_client_to_server.clone()]);
        server_algo_nego.encryption_algorithms_server_to_client =
            NameList::new(vec![self.encryption_algorithms_server_to_client.clone()]);

        server_algo_nego.mac_algorithms_client_to_server =
            NameList::new(vec![self.mac_algorithms_client_to_server.clone()]);
        server_algo_nego.mac_algorithms_server_to_client =
            NameList::new(vec![self.mac_algorithms_server_to_client.clone()]);

        let server_algo_nego_encoded = server_algo_nego.encode();
        self.server_kex_init_payload = Some(server_algo_nego_encoded.clone().freeze());

        binary_packet_codec
            .send(server_algo_nego_encoded.clone())
            .await?;

        Ok(algo_nego)
    }

    async fn excahnge_identification(&mut self) -> io::Result<Identification> {
        let mut buf = BytesMut::new();

        loop {
            self.stream.as_mut().unwrap().read_buf(&mut buf).await?;
            if buf.windows(2).any(|w| w == b"\r\n") {
                break;
            }
        }

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

        self.stream
            .as_mut()
            .unwrap()
            .write_all(b"SSH-2.0-OpenSSH_10.0\r\n")
            .await?;

        Ok(Identification::new(protoversion, softwareversion))
    }

    async fn debug_read(&mut self) -> io::Result<String> {
        let mut buf = BytesMut::new();

        self.stream.as_mut().unwrap().read_buf(&mut buf).await?;

        Ok(String::from_utf8_lossy(&buf).to_string())
    }
}

fn dump<const N: usize>(src: &BytesMut) {
    for row in src.chunks(N) {
        println!("{:02x?}", row);
    }
}
