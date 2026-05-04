use tokio_util::bytes::Bytes;

use crate::{Parse, SshString};

#[derive(Debug, Clone)]
pub struct AuthRequest {
    user_name: String,
    service_name: String,
    method: AuthMethod,
}

#[derive(Debug, Clone)]
pub enum AuthMethod {
    Password,
}

impl Parse for AuthRequest {
    type Item = Bytes;

    fn parse(src: &Self::Item) -> anyhow::Result<(Self, usize)>
    where
        Self: Sized,
    {
        let mut src = src.clone();

        let user_name = SshString::parse_mut(&mut src)?.to_string();
        let service_name = SshString::parse_mut(&mut src)?.to_string();
        let method = AuthMethod::parse_mut(&mut src)?;

        Ok((
            AuthRequest {
                user_name,
                service_name,
                method,
            },
            // TODO: fix or revise Parse trait
            0,
        ))
    }
}

impl Parse for AuthMethod {
    type Item = Bytes;

    fn parse(src: &Self::Item) -> anyhow::Result<(Self, usize)>
    where
        Self: Sized,
    {
        let mut src = src.clone();

        let (method, n) = SshString::parse(&mut src)?;

        match method.to_string().as_str() {
            "password" => Ok((AuthMethod::Password, n)),
            _ => todo!(),
        }
    }
}
