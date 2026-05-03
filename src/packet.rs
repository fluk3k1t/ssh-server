use anyhow::Error;
use std::cmp::min;
use tracing::debug;

use tokio_util::{
    bytes::{Buf, BufMut, Bytes, BytesMut},
    codec::{Decoder, Encoder},
};

#[derive(Debug)]
pub struct BinaryPacketProtocol {
    buffer: BytesMut,
    state: BinaryPacketProtocolState,
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
        }
    }
}

pub type BinaryPacket = Bytes;

impl Decoder for BinaryPacketProtocol {
    type Item = BinaryPacket;
    type Error = anyhow::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        println!("decode {:?}", src);
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

        Ok(())
    }
}
