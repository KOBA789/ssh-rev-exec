use std::{path::Path, sync::Arc};

use anyhow::{anyhow, Context, Result};
use bytes::{Bytes, BytesMut};
use futures::{
    future::{self, Either},
    FutureExt, SinkExt, TryStreamExt,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, Stderr, Stdin, Stdout},
    net::{
        unix::{OwnedReadHalf, OwnedWriteHalf},
        UnixStream,
    },
    sync::Mutex,
};
use tokio_util::codec::{FramedRead, FramedWrite};

use crate::{
    rpc::{build_request_message, Event, Exec, Request},
    ssh_agent::{self, SSH_AGENT_EXTENSION_FAILURE, SSH_AGENT_FAILURE, SSH_AGENT_SUCCESS},
};

pub struct RevExec {
    outgoing: Outgoing,
    incoming: Incoming,
}

impl RevExec {
    pub async fn open(ssh_auth_sock: &Path) -> Result<Self> {
        let (r, w) = UnixStream::connect(ssh_auth_sock).await?.into_split();
        let incoming = Incoming(FramedRead::new(r, ssh_agent::Codec));
        let outgoing = Outgoing(FramedWrite::new(w, ssh_agent::Codec));
        Ok(Self { outgoing, incoming })
    }

    pub async fn exec(
        mut self,
        exec: Exec,
        mut stdin: Stdin,
        mut stdout: Stdout,
        mut stderr: Stderr,
    ) -> Result<i32> {
        self.outgoing.exec(exec).await.context("send exec req")?;
        self.incoming.recv().await.context("recv exec reply")?;
        self.outgoing.watch().await.context("first watch req")?;

        let outgoing = Arc::new(Mutex::new(self.outgoing));
        let outgoing2 = outgoing.clone();

        let incoming_loop_fut = async move {
            loop {
                let Some(event) = self.incoming.recv().await? else {
                    continue;
                };
                match event {
                    Event::Cancelled => {
                        outgoing.lock().await.watch().await?;
                    }
                    Event::Stdout(bytes) => {
                        stdout.write_all(&bytes).await?;
                        outgoing.lock().await.watch().await?;
                    }
                    Event::Stderr(bytes) => {
                        stderr.write_all(&bytes).await?;
                        outgoing.lock().await.watch().await?;
                    }
                    Event::Exited(code) => return anyhow::Ok(code),
                }
            }
        }
        .boxed();
        let stdin_loop_fut = async move {
            loop {
                let mut buf = BytesMut::with_capacity(256);
                stdin.read_buf(&mut buf).await?;
                let is_eof = buf.is_empty();
                let mut outgoing = outgoing2.lock().await;
                outgoing.stdin(buf.freeze()).await?;
                if is_eof {
                    break;
                }
            }
            anyhow::Ok(())
        }
        .boxed();

        match future::try_select(incoming_loop_fut, stdin_loop_fut).await {
            Ok(Either::Left((exit_code, _))) => Ok(exit_code),
            Ok(Either::Right((_, incoming_loop_fut))) => Ok(incoming_loop_fut.await?),
            Err(either) => Err(either.factor_first().0),
        }
    }
}

struct Incoming(FramedRead<OwnedReadHalf, ssh_agent::Codec>);

impl Incoming {
    async fn recv(&mut self) -> Result<Option<Event>> {
        let message = self
            .0
            .try_next()
            .await?
            .ok_or_else(|| anyhow!("connection was closed unexpectedly"))?;
        match message.message_type {
            SSH_AGENT_FAILURE => Err(anyhow!("SSH_AGENT_FAILURE")),
            SSH_AGENT_EXTENSION_FAILURE => Err(anyhow!("SSH_AGENT_EXTENSION_FAILURE")),
            SSH_AGENT_SUCCESS => {
                if message.contents.is_empty() {
                    Ok(None)
                } else {
                    let event = message.contents.try_into()?;
                    Ok(Some(event))
                }
            }
            message_type => Err(anyhow!("unknown message type: {}", message_type)),
        }
    }
}

struct Outgoing(FramedWrite<OwnedWriteHalf, ssh_agent::Codec>);

impl Outgoing {
    async fn exec(&mut self, exec: Exec) -> Result<()> {
        let request = build_request_message(Request::Exec(exec))?;
        self.0.send(&request).await?;
        Ok(())
    }

    async fn watch(&mut self) -> Result<()> {
        let request = build_request_message(Request::Watch)?;
        self.0.send(&request).await?;
        Ok(())
    }

    async fn stdin(&mut self, bytes: Bytes) -> Result<()> {
        let request = build_request_message(Request::Stdin(bytes))?;
        self.0.send(&request).await?;
        Ok(())
    }
}
