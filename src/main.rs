use bytes::{Buf, BufMut, BytesMut};
// use ecdsa::VerifyingKey;
use futures::{SinkExt, Stream, StreamExt};
use p256::elliptic_curve::PublicKey;
use p256::{EncodedPoint, NistP256};
// use sec1::EncodedPoint;
use ssh_server::{AlgorithmNegotiation, BinaryPacketDecoder, Encode, Parse};
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
}

impl SshServer {
    pub fn new(stream: TcpStream) -> Self {
        Self { stream }
    }

    pub async fn handle_connection(&mut self) -> io::Result<()> {
        let (protoversion, softwareversion) = self.excahnge_identification().await?;
        self.exchange_key().await?;

        Ok(())
    }

    async fn exchange_key(&mut self) -> io::Result<()> {
        let (mut read_half, write_half) = self.stream.split();
        let mut binary_packet_reader = FramedRead::new(read_half, BinaryPacketDecoder::default());

        let mut writer = FramedWrite::new(write_half, BinaryPacketEncoder::default());

        let mut binary_packet = binary_packet_reader
            .next()
            .await
            .ok_or(Error::other("failed to reed binary packet"))??;

        let algo_nego = AlgorithmNegotiation::parse(&mut binary_packet.payload)?;

        writer.send(algo_nego).await?;

        let mut ecdh = binary_packet_reader
            .next()
            .await
            .ok_or(Error::other("failed to reed binary packet"))??;

        let ecdh = EcdhKex::parse(&mut ecdh.payload)?;

        println!("{:?}", ecdh);

        Ok(())
    }

    async fn excahnge_identification(&mut self) -> io::Result<(String, String)> {
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

        Ok((protoversion, softwareversion))
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
