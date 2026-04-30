use aes::Aes128;
// use aes_wasm::aes128ctr::{self, IV};
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
use ssh_server::EcdhKex;
use ssh_server::{
    AlgorithmNegotiation, ByteStream, Encode, EncodeToBytesMut, Message, MessageNumber, NameList,
    Parse, Payload, SshMpInt, SshPublicKey, SshServer, SshSignature, SshString,
};
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

    let (stream, _) = listener.accept().await?;
    let mut ssh_server = SshServer::new(stream);
    // ssh_server.handle_connection().await?;
    let j = tokio::spawn(async {
        ssh_server.run().await.unwrap();
    });

    j.await?;

    Ok(())
}
