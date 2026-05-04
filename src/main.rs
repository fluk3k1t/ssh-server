use anyhow::Result;
use ssh_server::{BinaryPacketProtocol, SshServer, SshServerBuilder};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::Framed;
use tracing::{debug, trace};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    let listner = TcpListener::bind(("127.0.0.1", 2020)).await?;

    loop {
        let (stream, _) = listner.accept().await?;
        let mut ssh_server = SshServerBuilder::default().build(stream);
        ssh_server.run().await?;
    }

    Ok(())
}
