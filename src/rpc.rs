use std::{collections::HashMap, mem::size_of};

use anyhow::{anyhow, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use num_enum::TryFromPrimitive;
use serde::{Deserialize, Serialize};

use crate::ssh_agent::{Extension, Message, SSH_AGENTC_EXTENSION};

pub const EXTENSION_TYPE: &[u8] = b"ssh-rev-exec.1@koba789.com";

pub fn build_request_message(req: Request) -> Result<Message> {
    let req_bytes = req.into_bytes()?;
    let ext = Extension {
        extension_type: EXTENSION_TYPE.into(),
        contents: req_bytes,
    };
    Ok(Message {
        message_type: SSH_AGENTC_EXTENSION,
        contents: ext.into(),
    })
}

#[derive(Debug, TryFromPrimitive)]
#[repr(u8)]
pub enum OpCode {
    Exec = 0,
    Stdin = 1,
    Watch = 2,
}

#[derive(Debug)]
pub enum Request {
    Exec(Exec),
    Stdin(Bytes),
    Watch,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Exec {
    pub cmd: String,
    pub args: Vec<String>,
    pub envs: HashMap<String, String>,
    pub cwd: Option<String>,
}

impl Request {
    pub fn into_bytes(self) -> Result<Bytes> {
        match self {
            Request::Exec(exec) => Self::exec(&exec),
            Request::Stdin(stdin) => Ok(Self::stdin(stdin)),
            Request::Watch => Ok(Self::watch()),
        }
    }

    pub fn exec(exec: &Exec) -> Result<Bytes> {
        let mut bytes = BytesMut::from([OpCode::Exec as u8].as_slice());
        serde_json::to_writer((&mut bytes).writer(), exec)?;
        Ok(bytes.freeze())
    }

    pub fn stdin(stdin: Bytes) -> Bytes {
        let mut bytes = BytesMut::from([OpCode::Stdin as u8].as_slice());
        bytes.put(stdin);
        bytes.freeze()
    }

    pub fn watch() -> Bytes {
        Bytes::from([OpCode::Watch as u8].as_slice())
    }
}

impl TryFrom<Bytes> for Request {
    type Error = anyhow::Error;

    fn try_from(mut bytes: Bytes) -> Result<Self, Self::Error> {
        if bytes.is_empty() {
            return Err(anyhow!("content must not be empty"));
        }
        let code = bytes.split_to(1);
        match OpCode::try_from(code[0])? {
            OpCode::Exec => Ok(Request::Exec(serde_json::from_slice(&bytes)?)),
            OpCode::Stdin => Ok(Request::Stdin(bytes)),
            OpCode::Watch => Ok(Request::Watch),
        }
    }
}

#[derive(TryFromPrimitive)]
#[repr(u8)]
pub enum EventCode {
    Cancelled = 0,
    Stdout = 1,
    Stderr = 2,
    Exited = 3,
}

pub enum Event {
    Cancelled,
    Stdout(Bytes),
    Stderr(Bytes),
    Exited(i32),
}

impl Event {
    pub fn into_bytes(self) -> Bytes {
        match self {
            Event::Cancelled => Self::cancelled(),
            Event::Stdout(stdout) => Self::stdout(&stdout),
            Event::Stderr(stderr) => Self::stderr(&stderr),
            Event::Exited(status) => Self::exited(status),
        }
    }

    pub fn cancelled() -> Bytes {
        Bytes::from([EventCode::Cancelled as u8].as_slice())
    }

    pub fn stdout(stdout: &[u8]) -> Bytes {
        let mut bytes = BytesMut::from([EventCode::Stdout as u8].as_slice());
        bytes.put_slice(stdout);
        bytes.freeze()
    }

    pub fn stderr(stderr: &[u8]) -> Bytes {
        let mut bytes = BytesMut::from([EventCode::Stderr as u8].as_slice());
        bytes.put_slice(stderr);
        bytes.freeze()
    }

    pub fn exited(status: i32) -> Bytes {
        let mut bytes = BytesMut::from([EventCode::Exited as u8].as_slice());
        bytes.put_i32(status);
        bytes.freeze()
    }
}

impl TryFrom<Bytes> for Event {
    type Error = anyhow::Error;

    fn try_from(mut bytes: Bytes) -> Result<Self, Self::Error> {
        if bytes.is_empty() {
            return Err(anyhow!("content must not be empty"));
        }
        let code = bytes.split_to(1);
        match EventCode::try_from(code[0])? {
            EventCode::Cancelled => Ok(Event::Cancelled),
            EventCode::Stdout => Ok(Event::Stdout(bytes)),
            EventCode::Stderr => Ok(Event::Stderr(bytes)),
            EventCode::Exited => {
                if bytes.len() < size_of::<i32>() {
                    return Err(anyhow!("malformed event: status code must be an i32"));
                }
                Ok(Event::Exited(bytes.get_i32()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stdout() {
        let content_bytes = Event::stdout(b"hello");
        assert_eq!(b"\x01hello", &*content_bytes);
    }
}
