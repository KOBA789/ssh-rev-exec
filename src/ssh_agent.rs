use std::{io, mem::size_of};

use anyhow::anyhow;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

#[derive(Debug, Clone)]
pub struct Message {
    pub message_type: u8,
    pub contents: Bytes,
}

impl Message {
    pub fn failure() -> Self {
        Self {
            message_type: SSH_AGENT_FAILURE,
            contents: Bytes::new(),
        }
    }

    pub fn extension_failure() -> Self {
        Self {
            message_type: SSH_AGENT_EXTENSION_FAILURE,
            contents: Bytes::new(),
        }
    }
}

pub struct Extension {
    pub extension_type: Bytes,
    pub contents: Bytes,
}

impl TryFrom<Bytes> for Extension {
    type Error = anyhow::Error;

    fn try_from(mut bytes: Bytes) -> Result<Self, Self::Error> {
        if bytes.len() < size_of::<u32>() {
            return Err(anyhow!("message contents is too short for extension"));
        }
        let ext_type_len = bytes.get_u32() as usize;
        if bytes.len() < ext_type_len {
            return Err(anyhow!("length of extension type is mismatch"));
        }
        let extension_type = bytes.split_to(ext_type_len);
        Ok(Self {
            extension_type,
            contents: bytes,
        })
    }
}

impl From<Extension> for Bytes {
    fn from(ext: Extension) -> Self {
        let mut bytes = BytesMut::with_capacity(4 + ext.extension_type.len() + ext.contents.len());
        bytes.put_u32(ext.extension_type.len() as u32);
        bytes.put(ext.extension_type);
        bytes.put(ext.contents);
        bytes.freeze()
    }
}

pub struct Codec;
impl Decoder for Codec {
    type Item = Message;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        //log::trace!("Decode: {:?}", src);
        if src.len() < size_of::<u32>() {
            return Ok(None);
        }
        let len = u32::from_be_bytes([src[0], src[1], src[2], src[3]]) as usize;
        if len == 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "message length must not be zero",
            ));
        }
        if src.len() < len + size_of::<u32>() {
            return Ok(None);
        }
        src.advance(4);
        let mut body = src.split_to(len);
        let message_type = body[0];
        let content = body.split_off(1).freeze();
        Ok(Some(Message {
            message_type,
            contents: content,
        }))
    }
}

impl<'a> Encoder<&'a Message> for Codec {
    type Error = io::Error;

    fn encode(&mut self, msg: &'a Message, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let len = (msg.contents.len() + 1) as u32;
        let len_bytes = len.to_be_bytes();
        dst.put_slice(&len_bytes);
        dst.put_u8(msg.message_type);
        dst.put_slice(&msg.contents);
        Ok(())
    }
}

pub const SSH_AGENT_FAILURE: u8 = 5;
pub const SSH_AGENT_SUCCESS: u8 = 6;
pub const SSH_AGENTC_EXTENSION: u8 = 27;
pub const SSH_AGENT_EXTENSION_FAILURE: u8 = 28;
