use std::{cmp::min, io};

use bytes::{Buf, BufMut};
use tokio_util::codec::{Decoder, Encoder};

use bytes::BytesMut;

use crate::{Encode, MessageNumber};

#[derive(Debug)]
pub struct BinaryPacket {
    pub payload: Payload,
}

// impl BinaryPacket {
//     pub fn expect(&mut self, message_number: MessageNumber) -> io::Result<()> {

//     }
// }

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
pub enum BinaryPacketCodec {
    Header,
    Payload(usize, usize, Vec<u8>),
    Padding(usize, Vec<u8>),
}

impl Default for BinaryPacketCodec {
    fn default() -> Self {
        BinaryPacketCodec::Header
    }
}

impl Decoder for BinaryPacketCodec {
    type Item = BinaryPacket;
    type Error = io::Error;

    fn decode(&mut self, src: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self {
            BinaryPacketCodec::Header => {
                if src.remaining() < size_of::<u32>() + size_of::<u8>() {
                    return Ok(None);
                }

                let packet_length = src.get_u32() as usize;
                let padding_length = src.get_u8() as usize;

                println!("pakcet length {}", packet_length);
                println!("padding_length {}", padding_length);

                *self = BinaryPacketCodec::Payload(
                    packet_length - padding_length - 1,
                    padding_length,
                    Vec::new(),
                );

                self.decode(src)
            }
            BinaryPacketCodec::Payload(payload_remaining, padding_remaining, payload) => {
                let reading_length = min(*payload_remaining, src.remaining());
                *payload_remaining = payload_remaining.saturating_sub(reading_length);

                // println!("spliteto");

                payload.extend_from_slice(&src.split_to(reading_length));

                match *payload_remaining {
                    0 => {
                        *self = BinaryPacketCodec::Padding(*padding_remaining, payload.clone());
                        self.decode(src)
                    }
                    _ => Ok(None),
                }
            }
            BinaryPacketCodec::Padding(padding_remaining, payload) => {
                let reading_length = min(*padding_remaining, src.remaining());
                *padding_remaining = padding_remaining.saturating_sub(reading_length);

                // println!("advance");

                src.advance(reading_length);

                match *padding_remaining {
                    0 => {
                        let payload = payload.clone();

                        *self = BinaryPacketCodec::Header;
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

impl Encoder<BytesMut> for BinaryPacketCodec {
    type Error = io::Error;

    fn encode(&mut self, item: BytesMut, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let mut padding_length = 4;

        while (4 + 1 + item.len() + padding_length) % 8 != 0 {
            padding_length += 1;
        }

        // println!("{:?} {} {}", padding_length, all_length, all_length % 8,);

        let packet_length = 1 + item.len() + padding_length;

        dst.put_u32(packet_length as u32);
        dst.put_u8(padding_length as u8);
        dst.put(item);
        dst.put_bytes(0, padding_length);

        Ok(())
    }
}
