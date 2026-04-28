use std::{cmp::min, io};

use bytes::{Buf, BufMut};
use tokio_util::codec::{Decoder, Encoder};

use bytes::BytesMut;

use crate::Encode;

#[derive(Debug)]
pub struct BinaryPacket {
    pub payload: Payload,
}

#[derive(Debug)]
pub struct Payload {
    pub inner: BytesMut,
}

impl Payload {
    pub fn new(inner: impl Into<BytesMut>) -> Self {
        Payload {
            inner: inner.into(),
        }
    }
}

#[derive(Debug)]
pub enum BinaryPacketDecoder {
    Header,
    Payload(usize, usize, Vec<u8>),
    Padding(usize, Vec<u8>),
}

impl Default for BinaryPacketDecoder {
    fn default() -> Self {
        BinaryPacketDecoder::Header
    }
}

impl Decoder for BinaryPacketDecoder {
    type Item = BinaryPacket;
    type Error = io::Error;

    fn decode(&mut self, src: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self {
            BinaryPacketDecoder::Header => {
                if src.remaining() < size_of::<u32>() + size_of::<u8>() {
                    return Ok(None);
                }

                let packet_length = src.get_u32() as usize;
                let padding_length = src.get_u8() as usize;

                println!("pakcet length {}", packet_length);
                println!("padding_length {}", padding_length);

                *self = BinaryPacketDecoder::Payload(
                    packet_length - padding_length - 1,
                    padding_length,
                    Vec::new(),
                );

                self.decode(src)
            }
            BinaryPacketDecoder::Payload(payload_remaining, padding_remaining, payload) => {
                let reading_length = min(*payload_remaining, src.remaining());
                *payload_remaining = payload_remaining.saturating_sub(reading_length);

                // println!("spliteto");

                payload.extend_from_slice(&src.split_to(reading_length));

                match *payload_remaining {
                    0 => {
                        *self = BinaryPacketDecoder::Padding(*padding_remaining, payload.clone());
                        self.decode(src)
                    }
                    _ => Ok(None),
                }
            }
            BinaryPacketDecoder::Padding(padding_remaining, payload) => {
                let reading_length = min(*padding_remaining, src.remaining());
                *padding_remaining = padding_remaining.saturating_sub(reading_length);

                // println!("advance");

                src.advance(reading_length);

                match *padding_remaining {
                    0 => {
                        let payload = payload.clone();

                        *self = BinaryPacketDecoder::Header;
                        src.clear();

                        Ok(Some(BinaryPacket {
                            payload: Payload::new(BytesMut::from_iter(payload)),
                        }))
                    }
                    _ => Ok(None),
                }
            }
        }
    }
}

pub struct BinaryPacketEncoder;

impl Default for BinaryPacketEncoder {
    fn default() -> Self {
        BinaryPacketEncoder
    }
}
