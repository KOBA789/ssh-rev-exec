use std::{
    path::{Path, PathBuf},
    process::Stdio,
};

use anyhow::{anyhow, Result};
use bytes::{Bytes, BytesMut};
use futures::{
    future::{self, Either},
    FutureExt, SinkExt, TryStreamExt,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        unix::{OwnedReadHalf, OwnedWriteHalf},
        UnixListener, UnixStream,
    },
    process::{self, Child, ChildStderr, ChildStdin, ChildStdout},
    sync::{mpsc, oneshot},
};
use tokio_util::codec::{FramedRead, FramedWrite};

use crate::{
    rpc::{Event, Exec, Request, EXTENSION_TYPE},
    ssh_agent::{self, Extension, Message, SSH_AGENTC_EXTENSION, SSH_AGENT_SUCCESS},
};
pub struct RevAgent {
    listener: UnixListener,
    upstream_sock_path: Option<PathBuf>,
}

impl RevAgent {
    pub fn new(listener: UnixListener, upstream_sock_path: Option<PathBuf>) -> Self {
        Self {
            listener,
            upstream_sock_path,
        }
    }

    pub fn open(listen_sock_path: &Path, upstream_sock_path: Option<PathBuf>) -> Result<Self> {
        log::trace!("Opening RevAgent");
        let listener = UnixListener::bind(listen_sock_path)?;
        Ok(Self::new(listener, upstream_sock_path))
    }

    pub async fn run(self) -> Result<()> {
        log::trace!("Running");
        loop {
            let (client, _addr) = self.listener.accept().await?;
            tokio::spawn(handle_client(self.upstream_sock_path.clone(), client));
        }
    }
}

async fn handle_client(upstream_sock_path: Option<PathBuf>, client: UnixStream) -> Result<()> {
    let (client_r, client_w) = client.into_split();
    let mut incoming = FramedRead::new(client_r, ssh_agent::Codec);
    let mut outgoing = FramedWrite::new(client_w, ssh_agent::Codec);
    let upstream = if let Some(path) = upstream_sock_path.as_deref() {
        Some(UpstreamAgent::open(path).await?)
    } else {
        None
    };

    let (reply_tx, mut reply_rx) = mpsc::channel(100);
    let (request_tx, request_rx) = mpsc::channel(100);
    let (rev_ext_tx, rev_ext_rx) = mpsc::channel(100);
    let reply_loop_fut = async move {
        while let Some(oneshot) = reply_rx.recv().await {
            match oneshot.await {
                Ok(reply) => {
                    outgoing.send(&reply).await?;
                }
                Err(_err) => {
                    outgoing.send(&Message::failure()).await?;
                }
            }
        }
        anyhow::Ok(())
    }
    .boxed();
    let pipe_loop_fut = async move {
        while let Some(request) = incoming.try_next().await? {
            let (oneshot_tx, oneshot_rx) = oneshot::channel::<Message>();
            reply_tx.send(oneshot_rx).await?;
            request_tx.send((request, oneshot_tx)).await?;
        }
        anyhow::Ok(())
    }
    .boxed();
    let rev_ext = RevExt {
        requests: rev_ext_rx,
    };
    let rev_ext_fut = rev_ext.run().boxed();
    let router = Router {
        requests: request_rx,
        upstream,
        rev_ext: rev_ext_tx,
    };
    let request_handler_fut = router.run().boxed();

    future::select_ok([
        reply_loop_fut,
        pipe_loop_fut,
        rev_ext_fut,
        request_handler_fut,
    ])
    .await?;
    Ok(())
}

struct Router {
    requests: mpsc::Receiver<(Message, oneshot::Sender<Message>)>,
    upstream: Option<UpstreamAgent>,
    rev_ext: mpsc::Sender<(Bytes, oneshot::Sender<Message>)>,
}

impl Router {
    async fn run(mut self) -> Result<()> {
        while let Some((request, reply_tx)) = self.requests.recv().await {
            self.handle_request(request, reply_tx).await?;
        }
        Ok(())
    }

    async fn handle_request(
        &mut self,
        request: Message,
        reply_tx: oneshot::Sender<Message>,
    ) -> Result<()> {
        match request.message_type {
            SSH_AGENTC_EXTENSION => {
                let reply = move |reply_tx: oneshot::Sender<_>, msg| {
                    reply_tx.send(msg).map_err(|_| anyhow!("failed to reply"))
                };
                let Ok::<Extension, _>(ext) = request.contents.try_into() else {
                    reply(reply_tx, Message::failure())?;
                    return Ok(());
                };
                if &*ext.extension_type != EXTENSION_TYPE {
                    reply(reply_tx, Message::failure())?;
                    return Ok(());
                }
                Ok(self.rev_ext.send((ext.contents, reply_tx)).await?)
            }
            // TODO: support "4.7.1.  Query extension"
            // https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent#section-4.7.1
            _ => self.forward_to_upstream(request, reply_tx).await,
        }
    }

    async fn forward_to_upstream(
        &mut self,
        request: Message,
        reply_tx: oneshot::Sender<Message>,
    ) -> Result<()> {
        let reply = move |msg| reply_tx.send(msg).map_err(|_| anyhow!("failed to reply"));
        if let Some(upstream) = self.upstream.as_mut() {
            upstream.write.send(&request).await?;
            let reply_msg = upstream
                .read
                .try_next()
                .await?
                .ok_or_else(|| anyhow!("upstream agent has gone"))?;
            reply(reply_msg)?;
        } else {
            reply(Message::failure())?;
        }
        Ok(())
    }
}

struct RevExt {
    requests: mpsc::Receiver<(Bytes, oneshot::Sender<Message>)>,
}

#[derive(Debug)]
struct Running {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: Option<ChildStdout>,
    stderr: Option<ChildStderr>,
}

impl RevExt {
    async fn run(mut self) -> Result<()> {
        let Some(running) = self.handle_exec().await? else {
            return Ok(())
        };
        self.handle_stdin_watch(running).await?;
        Ok(())
    }

    async fn handle_exec(&mut self) -> Result<Option<Running>> {
        while let Some((request, reply_tx)) = self.requests.recv().await {
            let reply = move |msg| reply_tx.send(msg).map_err(|_| anyhow!("failed to reply"));
            if let Ok(Request::Exec(exec)) = Request::try_from(request) {
                let (child, stdin, stdout, stderr) = Self::exec(&exec).await?;
                let running = Running {
                    child,
                    stdin: Some(stdin),
                    stdout: Some(stdout),
                    stderr: Some(stderr),
                };
                reply(Message {
                    message_type: SSH_AGENT_SUCCESS,
                    contents: Bytes::new(),
                })?;
                return Ok(Some(running));
            } else {
                reply(Message::extension_failure())?;
            }
        }
        Ok(None)
    }

    async fn handle_stdin_watch(&mut self, mut r: Running) -> Result<()> {
        let mut peek_buf: Option<(Bytes, oneshot::Sender<Message>)> = None;
        while let Some((request, reply_tx)) = {
            if let Some(peek_buf) = peek_buf.take() {
                Some(peek_buf)
            } else {
                self.requests.recv().await
            }
        } {
            let reply = move |msg| reply_tx.send(msg).map_err(|_| anyhow!("failed to reply"));
            let Ok(request) = Request::try_from(request) else {
                reply(Message::extension_failure())?;
                continue;
            };
            match request {
                Request::Stdin(bytes) => {
                    if let Some(stdin) = r.stdin.as_mut() {
                        if bytes.is_empty() {
                            stdin.shutdown().await?;
                            drop(r.stdin.take()); // drop stdin to close
                        } else {
                            stdin.write_all(&bytes).await?;
                        }
                        reply(Message {
                            message_type: SSH_AGENT_SUCCESS,
                            contents: Bytes::new(),
                        })?;
                    } else {
                        reply(Message::extension_failure())?;
                    }
                }
                Request::Watch => {
                    let watch_fut = Self::watch(&mut r.stdout, &mut r.stderr, &mut r.child).boxed();
                    let peek_fut = self.requests.recv().boxed();
                    match future::select(watch_fut, peek_fut).await {
                        Either::Left((Ok(event), _)) => {
                            reply(Message {
                                message_type: SSH_AGENT_SUCCESS,
                                contents: event.into_bytes(),
                            })?;
                        }
                        Either::Left((Err(_err), _)) => {
                            // TODO: logging
                            reply(Message::extension_failure())?;
                        }
                        Either::Right((next_tuple, _)) => {
                            peek_buf = next_tuple;
                            reply(Message {
                                message_type: SSH_AGENT_SUCCESS,
                                contents: Event::Cancelled.into_bytes(),
                            })?;
                        }
                    }
                }
                _ => {
                    reply(Message::extension_failure())?;
                }
            }
        }
        Ok(())
    }

    async fn exec(exec: &Exec) -> Result<(process::Child, ChildStdin, ChildStdout, ChildStderr)> {
        let mut command = process::Command::new(&exec.cmd);
        command.args(&exec.args);
        command.envs(exec.envs.iter());
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
        command.stdin(Stdio::piped());
        command.kill_on_drop(true);
        if let Some(cwd) = exec.cwd.as_deref() {
            command.current_dir(cwd);
        }
        let mut child = command.spawn()?;
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        Ok((child, stdin, stdout, stderr))
    }

    async fn watch(
        stdout_opt: &mut Option<ChildStdout>,
        stderr_opt: &mut Option<ChildStderr>,
        child: &mut Child,
    ) -> Result<Event> {
        let exited_fut = async {
            let exit_status = child.wait().await?;
            let code = exit_status.code().unwrap_or_default();
            anyhow::Ok(Event::Exited(code))
        }
        .boxed();

        if stdout_opt.is_none() && stderr_opt.is_none() {
            return exited_fut.await;
        }

        let stdout_fut = async {
            let mut buf = BytesMut::with_capacity(4096); // FIXME: magic number
            if let Some(stdout) = stdout_opt {
                log::trace!("Reading stdout");
                stdout.read_buf(&mut buf).await?;
                log::trace!("Read from stdout: {:?}", &buf);
                if buf.is_empty() {
                    log::trace!("stdout was reached to EOS");
                    *stdout_opt = None;
                }
                anyhow::Ok(Event::Stdout(buf.freeze()))
            } else {
                log::trace!("FOREVER STDOUT");
                future::pending().await
            }
        }
        .boxed();
        let stderr_fut = async {
            let mut buf = BytesMut::with_capacity(4096); // FIXME: magic number
            if let Some(stderr) = stderr_opt {
                log::trace!("Reading stderr");
                stderr.read_buf(&mut buf).await?;
                log::trace!("Read from stderr: {:?}", &buf);
                if buf.is_empty() {
                    log::trace!("stderr was reached to EOS");
                    *stderr_opt = None;
                }
                anyhow::Ok(Event::Stderr(buf.freeze()))
            } else {
                log::trace!("FOREVER STDERR");
                future::pending().await
            }
        }
        .boxed();
        match future::try_select(stdout_fut, stderr_fut).await {
            Ok(either) => Ok(either.factor_first().0),
            Err(either) => Err(either.factor_first().0),
        }
    }
}

struct UpstreamAgent {
    read: FramedRead<OwnedReadHalf, ssh_agent::Codec>,
    write: FramedWrite<OwnedWriteHalf, ssh_agent::Codec>,
}

impl UpstreamAgent {
    async fn open(path: &Path) -> Result<Self> {
        let upstream = UnixStream::connect(path).await?;
        let (r, w) = upstream.into_split();
        let read = FramedRead::new(r, ssh_agent::Codec);
        let write = FramedWrite::new(w, ssh_agent::Codec);
        Ok(UpstreamAgent { read, write })
    }
}
