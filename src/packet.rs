use crate::server::Aes128Ctr128BE;
use aes::{
    Aes128,
    cipher::{Array, StreamCipher, StreamCipherCoreWrapper},
};
use anyhow::Error;
use futures::SinkExt;
use hmac_sha256::HMAC;
use p256::U32;
use std::cmp::min;
use tokio::net::TcpStream;
use tracing::{debug, info};

use tokio_util::{
    bytes::{Buf, BufMut, Bytes, BytesMut},
    codec::{Decoder, Encoder, Framed},
};

#[derive(Debug)]
pub struct BinaryPacketProtocol {
    buffer: BytesMut,
    state: BinaryPacketProtocolState,
    pub s2c_seq_num: u32,
    pub c2s_seq_num: u32,
}

#[derive(Debug)]
pub enum BinaryPacketProtocolState {
    Header,
    Payload {
        payload_remaining: usize,
        padding_remaining: usize,
    },
    Padding {
        padding_remaining: usize,
    },
}

impl BinaryPacketProtocol {
    pub fn new() -> Self {
        BinaryPacketProtocol {
            buffer: BytesMut::with_capacity(32),
            state: BinaryPacketProtocolState::Header,
            s2c_seq_num: 0,
            c2s_seq_num: 0,
        }
    }
}

pub type BinaryPacket = Bytes;

impl Decoder for BinaryPacketProtocol {
    type Item = BinaryPacket;
    type Error = anyhow::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match &mut self.state {
            BinaryPacketProtocolState::Header => {
                if src.remaining() < size_of::<u32>() + size_of::<u8>() {
                    return Ok(None);
                }

                debug!("reading header");

                let packet_length = src.get_u32() as usize;
                let padding_length = src.get_u8() as usize;

                self.state = BinaryPacketProtocolState::Payload {
                    payload_remaining: packet_length - padding_length - 1,
                    padding_remaining: padding_length,
                };

                self.decode(src)
            }
            BinaryPacketProtocolState::Payload {
                payload_remaining,
                padding_remaining,
            } => {
                debug!("reading payload");

                let reading_length = min(*payload_remaining, src.remaining());
                *payload_remaining = payload_remaining.saturating_sub(reading_length);

                self.buffer.extend_from_slice(&src.split_to(reading_length));

                match *payload_remaining {
                    0 => {
                        self.state = BinaryPacketProtocolState::Padding {
                            padding_remaining: *padding_remaining,
                        };
                        self.decode(src)
                    }
                    _ => Ok(None),
                }
            }
            BinaryPacketProtocolState::Padding { padding_remaining } => {
                debug!("reading padding");

                let reading_length = min(*padding_remaining, src.remaining());
                *padding_remaining = padding_remaining.saturating_sub(reading_length);

                src.advance(reading_length);

                match *padding_remaining {
                    0 => {
                        let payload = self.buffer.clone();
                        self.buffer.clear();

                        self.state = BinaryPacketProtocolState::Header;
                        self.buffer.clear();
                        src.clear();

                        self.c2s_seq_num += 1;

                        Ok(Some(payload.freeze()))
                    }
                    _ => Ok(None),
                }
            }
        }
    }
}

impl Encoder<Bytes> for BinaryPacketProtocol {
    type Error = Error;

    fn encode(&mut self, item: Bytes, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let mut padding_length = 4;

        while (4 + 1 + item.len() + padding_length) % 8 != 0 {
            padding_length += 1;
        }

        let packet_length = 1 + item.len() + padding_length;

        dst.put_u32(packet_length as u32);
        dst.put_u8(padding_length as u8);
        dst.put(item);
        dst.put_bytes(0, padding_length);

        self.s2c_seq_num += 1;

        Ok(())
    }
}

pub type Cipher = StreamCipherCoreWrapper<ctr::CtrCore<Aes128, ctr::flavors::Ctr128BE>>;

#[derive(Debug, Clone)]
pub enum EncryptedBinaryPacketCodecState {
    Header,
    Payload(usize, usize, Vec<u8>),
    Padding(usize, Vec<u8>),
    Mac(Vec<u8>),
}
pub struct EncryptedBinaryPacketCodec {
    c2s_cipher: Cipher,
    s2c_cipher: Cipher,
    c2s_hmac_key: Array<u8, U32>,
    s2c_hmac_key: Array<u8, U32>,
    state: EncryptedBinaryPacketCodecState,
    packet_length: Option<u32>,
    padding_length: Option<u8>,
    s2c_seq_num: u32,
    c2s_seq_num: u32,
}

impl EncryptedBinaryPacketCodec {
    pub fn new(
        c2s_cipher: Cipher,
        s2c_cipher: Cipher,
        c2s_hmac_key: Array<u8, U32>,
        s2c_hmac_key: Array<u8, U32>,
        c2s_seq_num: u32,
        s2c_seq_num: u32,
    ) -> Self {
        EncryptedBinaryPacketCodec {
            c2s_cipher,
            s2c_cipher,
            c2s_hmac_key,
            s2c_hmac_key,
            state: EncryptedBinaryPacketCodecState::Header,
            packet_length: None,
            padding_length: None,
            c2s_seq_num,
            s2c_seq_num,
        }
    }
}

impl Decoder for EncryptedBinaryPacketCodec {
    type Item = BinaryPacket;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match &mut self.state {
            EncryptedBinaryPacketCodecState::Mac(payload) => {
                if src.remaining() < 32 {
                    return Ok(None);
                }

                debug!("reading mac");

                let _mac = src.split_to(32);

                src.clear();

                self.c2s_seq_num += 1;

                let payload = payload.clone();
                self.state = EncryptedBinaryPacketCodecState::Header;

                Ok(Some(Bytes::from_iter(payload)))
            }
            EncryptedBinaryPacketCodecState::Header => {
                if src.remaining() < size_of::<u32>() + size_of::<u8>() {
                    return Ok(None);
                }

                debug!("reading header");

                // packet_length, padding_lengthフィールドのみを復号
                self.c2s_cipher
                    .apply_keystream(&mut src[..(size_of::<u32>() + size_of::<u8>())]);

                let packet_length = src.get_u32() as usize;
                let padding_length = src.get_u8() as usize;

                self.state = EncryptedBinaryPacketCodecState::Payload(
                    packet_length - padding_length - 1,
                    padding_length,
                    Vec::new(),
                );

                self.decode(src)
            }
            EncryptedBinaryPacketCodecState::Payload(
                payload_remaining,
                padding_remaining,
                payload,
            ) => {
                debug!("reading payload");

                let reading_length = min(*payload_remaining, src.remaining());
                *payload_remaining = payload_remaining.saturating_sub(reading_length);

                payload.extend_from_slice(&src.split_to(reading_length));

                match *payload_remaining {
                    0 => {
                        let mut payload = payload.clone();
                        self.c2s_cipher.apply_keystream(&mut payload);

                        self.state =
                            EncryptedBinaryPacketCodecState::Padding(*padding_remaining, payload);
                        self.decode(src)
                    }
                    _ => Ok(None),
                }
            }

            EncryptedBinaryPacketCodecState::Padding(padding_remaining, payload) => {
                debug!("reading padding");

                let reading_length = min(*padding_remaining, src.remaining());
                *padding_remaining = padding_remaining.saturating_sub(reading_length);

                let mut padding = src.split_to(reading_length);

                // ctrモードを想定しているのでpaddingも復号する
                // モードによって実装変わるやんと思いつつ
                self.c2s_cipher.apply_keystream(&mut padding);

                match *padding_remaining {
                    0 => {
                        self.state = EncryptedBinaryPacketCodecState::Mac(payload.clone());

                        self.decode(src)
                    }
                    _ => Ok(None),
                }
            }
        }
    }
}

impl Encoder<Bytes> for EncryptedBinaryPacketCodec {
    type Error = Error;

    fn encode(&mut self, item: Bytes, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let mut padding_length = 4;

        while (4 + 1 + item.len() + padding_length) % 16 != 0 {
            padding_length += 1;
        }

        let packet_length = 1 + item.len() + padding_length;

        dst.put_u32(packet_length as u32);
        dst.put_u8(padding_length as u8);
        dst.put(item);
        dst.put_bytes(0, padding_length);

        let mut for_mac = BytesMut::new();
        for_mac.put_u32(self.s2c_seq_num);
        for_mac.extend(dst.clone());

        let mut hmac = HMAC::new(self.s2c_hmac_key);

        hmac.update(for_mac);
        let mac = hmac.clone().finalize();

        self.s2c_cipher.apply_keystream(dst);

        dst.extend(&mac[..]);

        self.s2c_seq_num += 1;

        Ok(())
    }
}

pub enum Codec {
    Plain(BinaryPacketProtocol),
    Encrypted(EncryptedBinaryPacketCodec),
}

impl Codec {
    pub fn upgrade(
        &mut self,
        c2s_cipher: Cipher,
        s2c_cipher: Cipher,
        c2s_hmac_key: Array<u8, U32>,
        s2c_hmac_key: Array<u8, U32>,
    ) {
        let (c2s_seq_num, s2c_seq_num) = {
            match self {
                Codec::Plain(plain) => (plain.c2s_seq_num, plain.s2c_seq_num),
                Codec::Encrypted(enc) => (enc.c2s_seq_num, enc.s2c_seq_num),
            }
        };

        *self = Codec::Encrypted(EncryptedBinaryPacketCodec::new(
            c2s_cipher,
            s2c_cipher,
            c2s_hmac_key,
            s2c_hmac_key,
            c2s_seq_num,
            s2c_seq_num,
        ));
    }
}

impl Decoder for Codec {
    type Error = Error;
    type Item = Bytes;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self {
            Codec::Plain(codec) => codec.decode(src),
            Codec::Encrypted(codec) => codec.decode(src),
        }
    }
}

impl Encoder<Bytes> for Codec {
    type Error = Error;

    fn encode(&mut self, item: Bytes, dst: &mut BytesMut) -> Result<(), Self::Error> {
        match self {
            Codec::Plain(codec) => codec.encode(item, dst),
            Codec::Encrypted(codec) => codec.encode(item, dst),
        }
    }
}
