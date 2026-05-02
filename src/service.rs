use std::io;

use bytes::Buf;

use crate::{MessageNumber, Parse, SshString};

#[derive(Debug, Clone)]
pub struct Service {
    pub service_name: SshString,
}

impl Parse for Service {
    fn parse(mut src: bytes::BytesMut) -> io::Result<Self> {
        let msg = src.get_u8();

        if msg != MessageNumber::SSH_MSG_SERVICE_REQUEST as u8 {
            return Err(io::Error::other(format!("expected {} but", msg)));
        }

        println!("{:?}", src);

        let service_name = SshString::parse(&mut src);

        Ok(Service { service_name })
    }
}
