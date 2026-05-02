use anyhow::Result;
use tokio_util::bytes::{Buf, Bytes};

use crate::BytesExt;

pub trait Parse {
    type Item;

    fn parse(src: &Self::Item) -> Result<(Self, usize)>
    where
        Self: Sized;

    fn parse_mut(src: &mut Self::Item) -> Result<Self>
    where
        Self: Sized,
        Self::Item: Buf,
    {
        let (res, n) = Self::parse(&src)?;
        src.advance(n);

        Ok(res)
    }
}

#[derive(Debug, Clone)]
pub struct Identification {
    softwareversion: String,
    protoversion: String,
}

impl Identification {
    pub fn new(protoversion: impl Into<String>, softwareversion: impl Into<String>) -> Self {
        Identification {
            softwareversion: softwareversion.into(),
            protoversion: protoversion.into(),
        }
    }

    pub fn as_crlf_excluded_str(&self) -> String {
        format!("SSH-{}-{}", self.protoversion, self.softwareversion)
            .trim_end_matches("\r\n")
            .to_string()
    }
}

#[derive(Debug)]
pub struct SshString {
    inner: Bytes,
}

impl Parse for SshString {
    type Item = Bytes;

    fn parse(src: &Self::Item) -> Result<(Self, usize)>
    where
        Self: Sized,
    {
        let mut src = src.clone();

        let length = src.try_get_u32()?;
        let str = src.try_split_to(length as usize)?;

        Ok((SshString { inner: str }, size_of::<u32>() + length as usize))
    }
}

#[derive(Debug, Clone)]
pub struct SshNameList {
    pub name_list: Vec<String>,
}

impl SshNameList {
    pub fn new(name_list: Vec<impl Into<String>>) -> Self {
        let name_list = name_list.into_iter().map(Into::<String>::into).collect();

        SshNameList { name_list }
    }
}

impl Parse for SshNameList {
    type Item = Bytes;

    fn parse(src: &Self::Item) -> Result<(Self, usize)>
    where
        Self: Sized,
    {
        let mut src = src.clone();

        let length = src.try_get_u32()?;

        let name_list = String::from_utf8_lossy(&src.split_to(length as usize))
            .split(",")
            .map(String::from)
            .collect::<Vec<_>>();

        Ok((
            SshNameList { name_list },
            size_of::<u32>() + length as usize,
        ))
    }
}
