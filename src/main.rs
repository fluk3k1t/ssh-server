use bytes::BytesMut;
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
};

use std::io::{self, Error};

#[tokio::main]
async fn main() -> io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:2020").await?;

    loop {
        let (stream, _) = listener.accept().await?;
        handle_connection(stream).await?;
    }
}

async fn handle_connection(mut stream: TcpStream) -> io::Result<()> {
    let mut buf = BytesMut::new();

    loop {
        stream.read_buf(&mut buf).await?;
        if buf.windows(2).any(|w| w == b"\r\n") {
            break;
        }
    }

    let identification = String::from_utf8_lossy(&buf);

    let (protoversion, softwareversion) = {
        let mut splitted = identification.split("-");
        let _ = splitted.next();
        (
            splitted
                .next()
                .ok_or(Error::other("failed to parse protoversion"))?,
            splitted
                .next()
                .ok_or(Error::other("failed to parse softwareversion"))?,
        )
    };

    Ok(())
}
