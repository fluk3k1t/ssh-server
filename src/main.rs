use bytes::{BufMut, BytesMut};
use futures::{SinkExt, Stream, StreamExt};
use ssh_server::BinaryPacketEncoder;
use ssh_server::{AlgorithmNegotiation, BinaryPacketDecoder, Encode, Parse};
use std::io::{self, Error, Sink};
use tokio::io::AsyncWrite;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
// use tokio_stream::StreamExt;
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
        let (read_half, mut write_half) = self.stream.split();
        let mut binary_packet_reader = FramedRead::new(read_half, BinaryPacketDecoder::default());

        // let mut writer = FramedWrite::new(write_half, BinaryPacketEncoder::default());

        let mut binary_packet = binary_packet_reader
            .next()
            .await
            .ok_or(Error::other("failed to reed binary packet"))??;

        println!("{:?}", binary_packet.payload.inner);

        let mut algo_nego = AlgorithmNegotiation::parse(&mut binary_packet.payload)?;

        // println!("{:#?}", algo_nego);

        let mut packet = algo_nego.encode();
        let mut bytes = BytesMut::new();

        let padding: u8 = 4;

        bytes.put_u32(packet.len() as u32 + padding as u32 + 1);
        bytes.put_u8(padding);
        bytes.extend_from_slice(&packet);
        bytes.put_bytes(0, padding as usize);

        println!("{:?}", bytes);

        // write_half.write_all(&algo_nego.encode()).await?;
        write_half.write_all(&bytes).await?;

        // writer.send(algo_nego).await?;
        // Stream
        // StreamExt
        // binary_packet_reader.write
        // Sink
        // writer.write_all(algo_nego);
        // Sink
        // AsyncWriteExt
        // AsyncWrite

        // binary_packet_reader

        // self.stream.write_atll_buf(&mut algo_nego.encode()).await?;

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
