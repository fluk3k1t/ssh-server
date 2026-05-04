use tokio_util::bytes::{Buf, Bytes};

use crate::{Parse, SshString};

#[derive(Debug, Clone)]
pub struct AuthRequest {
    pub user_name: String,
    pub service_name: String,
    pub method: AuthMethod,
}

#[derive(Debug, Clone)]
pub enum AuthMethod {
    Password(String),
    None,
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

        let method = SshString::parse_mut(&mut src)?;

        match method.to_string().as_str() {
            "password" => {
                let _ = src.get_u8();
                let plain_password = SshString::parse_mut(&mut src)?.to_string();

                Ok((AuthMethod::Password(plain_password), 0))
            }
            "none" => Ok((AuthMethod::None, 0)),
            _ => todo!(),
        }
    }
}
