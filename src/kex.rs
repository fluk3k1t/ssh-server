use anyhow::Result;
use tokio_util::bytes::Bytes;

use crate::{Parse, SshNameList, SshString};

#[derive(Debug)]
pub struct Kex {}

impl Kex {}

impl Parse for Kex {
    type Item = Bytes;

    fn parse(src: &Self::Item) -> Result<(Self, usize)>
    where
        Self: Sized,
    {
        todo!()
    }
}
