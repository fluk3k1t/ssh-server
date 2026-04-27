use std::{cmp::min, io};

use bytes::Buf;
use tokio_util::codec::{Decoder, Encoder};

use bytes::BytesMut;

use crate::{AlgorithmNegotiation, Encode};

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
                let packet_length = src.get_u32() as usize;
                let padding_length = src.get_u8() as usize;

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

                src.advance(reading_length);

                match *padding_remaining {
                    0 => Ok(Some(BinaryPacket {
                        payload: Payload::new(BytesMut::from_iter(payload.clone())),
                    })),
                    _ => Ok(None),
                }
            }
        }
    }
}

pub struct BinaryPacketEncoder {}

impl Default for BinaryPacketEncoder {
    fn default() -> Self {
        BinaryPacketEncoder {}
    }
}

impl Encoder<AlgorithmNegotiation> for BinaryPacketEncoder {
    type Error = io::Error;

    fn encode(
        &mut self,
        item: AlgorithmNegotiation,
        dst: &mut BytesMut,
    ) -> Result<(), Self::Error> {
        Ok(dst.extend_from_slice(&item.encode()))
    }
}
