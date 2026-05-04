use anyhow::anyhow;
use tokio_util::bytes::Bytes;

use crate::{Parse, SshString};

#[derive(Debug)]
pub enum ServiceRequest {
    UserAuth,
    Connection,
}

impl Parse for ServiceRequest {
    type Item = Bytes;

    fn parse(src: &Self::Item) -> anyhow::Result<(Self, usize)>
    where
        Self: Sized,
    {
        let mut src = src.clone();

        let (service_name, n) = SshString::parse(&src)?;

        match service_name.to_string().as_str() {
            "ssh-userauth" => Ok((ServiceRequest::UserAuth, n)),
            "ssh-connection" => Ok((ServiceRequest::Connection, n)),
            _ => Err(anyhow!("unsupported service: {:?}", service_name)),
        }
    }
}
