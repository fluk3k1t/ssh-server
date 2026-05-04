use anyhow::{Error, Result};
use tokio_util::bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::{BytesExt, EncodeToBytesMut};

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

    pub fn to_crlf_excluded_str(&self) -> String {
        format!("SSH-{}-{}", self.protoversion, self.softwareversion)
            .trim_end_matches("\r\n")
            .to_string()
    }
}

#[derive(Debug, Clone)]
pub struct SshString {
    inner: Bytes,
}

impl SshString {
    pub fn new(inner: impl Into<Bytes>) -> Self {
        SshString {
            inner: inner.into(),
        }
    }

    pub fn from_str(str: impl Into<String>) -> Self {
        SshString {
            inner: Bytes::from(str.into()),
        }
    }
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

impl SshString {
    pub fn as_bytes(&self) -> Bytes {
        self.inner.clone()
    }

    pub fn to_string(&self) -> String {
        String::from_utf8_lossy(&self.inner).to_string()
    }
}

impl EncodeToBytesMut for SshString {
    fn encode_to_bytes_mut(&self, dst: &mut impl BufMut) {
        let length = self.inner.len();

        dst.put_u32(length as u32);
        dst.put(&self.inner[..]);
    }
}

impl Into<String> for SshString {
    fn into(self) -> String {
        String::from_utf8_lossy(&self.inner).to_string()
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

impl EncodeToBytesMut for SshNameList {
    fn encode_to_bytes_mut(&self, dst: &mut impl BufMut) {
        let name_list_bytes = self.name_list.join(",");
        let name_list_bytes = Vec::from_iter(name_list_bytes.into_bytes());

        let lenght: [u8; 4] = (name_list_bytes.len() as u32).to_be_bytes();

        dst.put(&lenght[..]);
        dst.put(&name_list_bytes[..]);
    }
}

pub trait SshBytesMut {
    fn put(mut self, src: impl EncodeToBytesMut) -> Self
    where
        Self: Sized + BufMut,
    {
        src.encode_to_bytes_mut(&mut self);
        self
    }
    fn put_bytes(self, from: Bytes) -> Self;
    fn put_ssh_string(self, str: impl Into<Bytes>) -> Self;
    fn put_ssh_mpint(self, mpint: impl Into<Bytes>) -> Self;
}

impl SshBytesMut for BytesMut {
    fn put_bytes(mut self, from: Bytes) -> Self {
        self.extend(from);
        self
    }

    fn put_ssh_string(mut self, str: impl Into<Bytes>) -> Self {
        let target = SshString::new(str.into());
        target.encode_to_bytes_mut(&mut self);
        self
    }

    fn put_ssh_mpint(mut self, mpint: impl Into<Bytes>) -> Self {
        SshMpint::new(mpint).encode_to_bytes_mut(&mut self);
        self
    }
}

#[derive(Debug, Clone)]
pub struct SshMpint {
    inner: Bytes,
}

impl SshMpint {
    pub fn new(inner: impl Into<Bytes>) -> Self {
        SshMpint {
            inner: inner.into(),
        }
    }
}

pub(crate) fn encode_mpint(s: &[u8], w: &mut impl BufMut) -> Result<()> {
    // Skip initial 0s.
    let mut i = 0;
    while i < s.len() && s[i] == 0 {
        i += 1
    }
    // If the first non-zero is >= 128, write its length (u32, BE), followed by 0.
    if s[i] & 0x80 != 0 {
        // ((s.len() - i + 1) as u32).encode(w)?;
        w.put_u32(((s.len() - i + 1) as u32));
        // 0u8.encode(w)?;
        w.put_u8(0);
    } else {
        // ((s.len() - i) as u32).encode(w)?;
        w.put_u32(((s.len() - i) as u32));
    }
    w.put(&s[i..]);

    Ok(())
}

impl EncodeToBytesMut for SshMpint {
    fn encode_to_bytes_mut(&self, dst: &mut impl BufMut) {
        encode_mpint(&self.inner, dst).unwrap();
    }
}
