use crate::shell::proto::{
    RemotePtyDataPayload, RemotePtyEventPayload, ShellClientMessage, ShellServerMessage, WindowSize,
};

use super::shell::Shell;
use super::ShellStream;
use crate::shell::network::{NetworkPeer, NetworkPeerConfig, NetworkPeerRole};
use anyhow::{Context, Error, Result};
use async_trait::async_trait;
use futures::StreamExt;
use log::*;
use std::collections::HashMap;
use std::env;
use std::ffi::{CString, OsString};
use std::fs::File as StdFile;
use std::io::{self, Write};
use std::net::ToSocketAddrs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::os::unix::prelude::PermissionsExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{ExitStatus, Stdio};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, WriteHalf};
use tokio::net::{TcpStream, UnixListener, UnixStream};
use tokio::process::{Child, Command};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::{fs, prelude::*};
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use webpki::DNSNameRef;

pub struct RemotePtyShell {
    connections: HashMap<u32, WriteHalf<UnixStream>>,
    con_id: u32,
    read_tx: UnboundedSender<(u32, Result<Vec<u8>>)>,
    state: Option<StreamingState>,
    network_peer_config: NetworkPeerConfig,
}

struct StreamingState {
    proc: Child,
    sock_listener: UnixListener,
    read_rx: UnboundedReceiver<(u32, Result<Vec<u8>>)>,
}

struct RptyCommandConfig {
    sock_path: String,
    term: String,
    ps1: &'static str,
}

enum RptyBash {
    Path(String),
    Memfd(StdFile),
}

impl RemotePtyShell {
    pub(super) async fn new(
        term: &str,
        color: bool,
        network_peer_config: NetworkPeerConfig,
    ) -> Result<Self> {
        info!("creating remote pty shell");

        let rpty_bash = download_rpty_bash().await?;
        let (sock_path, sock_listener) = create_pty_sock().await?;

        let command_config = RptyCommandConfig {
            sock_path,
            term: term.to_string(),
            ps1: if color {
                r"\[\e[0;38;5;242m\][rpty] \[\e[0;92m\]\u\[\e[0;92m\]@\[\e[0;92m\]\H\[\e[0m\]:\[\e[0;38;5;39m\]\w\[\e[0m\]\$ \[\e[0m\]"
            } else {
                r"[rpty] \u@\H:\w\$ "
            },
        };

        let proc = spawn_rpty_bash(rpty_bash, &command_config).await?;

        let (read_tx, read_rx) = unbounded_channel();

        info!("created remote pty shell");
        Ok(Self {
            connections: HashMap::new(),
            con_id: 0,
            read_tx,
            state: Some(StreamingState {
                proc,
                sock_listener,
                read_rx,
            }),
            network_peer_config,
        })
    }

    async fn do_stream_io(mut self: Pin<&mut Self>, stream: &mut ShellStream) -> Result<()> {
        let mut state = self.state.take().unwrap();
        let (mut network_peer, mut network_peer_rx, mut network_peer_tx) =
            NetworkPeer::new(self.network_peer_config.clone(), NetworkPeerRole::Server).await;

        tokio::spawn(network_peer.run());

        loop {
            tokio::select! {
                new_con = state.sock_listener.accept() => match new_con {
                    Ok(new_con) => self.handle_new_connection(stream, new_con.0).await?,
                    Err(err) => return Err(err).context("failed to accept connection")
                },
                new_read = state.read_rx.recv() => match new_read {
                    Some(new_read) => self.handle_new_read(stream, new_read.0, new_read.1).await?,
                    None => return Err(Error::msg("failed to read message"))
                },
                network_msg = network_peer_rx.recv() => match network_msg {
                    Some(network_msg) => stream.write(&ShellServerMessage::Network(network_msg)).await?,
                    None => {
                        debug!("network peer channel closed");
                    }
                },
                msg = stream.next() => match msg {
                    Some(Ok(ShellClientMessage::RemotePtyData(payload))) => {
                        self.handle_data(stream, payload).await?;
                    }
                    Some(Ok(ShellClientMessage::Network(payload))) => {
                        let _ = network_peer_tx.send(payload);
                    }
                    Some(Ok(message)) => {
                        return Err(Error::msg(format!("received unexpected message from shell client {:?}", message)));
                    }
                    Some(Err(err)) => {
                        return Err(Error::from(err).context("received invalid message from shell client"));
                    }
                    None => {
                        warn!("client shell stream ended");
                        return Ok(());
                    }
                },
                res = &mut state.proc => match res {
                    Ok(exit_code) => {
                        self.handle_exit(stream, exit_code).await?;
                        return Ok(());
                    }
                    Err(err) => return Err(Error::from(err).context("failed to wait for proc to exit"))
                }
            };
        }
    }

    async fn handle_new_connection(
        &mut self,
        stream: &mut ShellStream,
        connection: UnixStream,
    ) -> Result<()> {
        let (mut rx, tx) = tokio::io::split(connection);

        let con_id = self.con_id;
        self.con_id += 1;
        self.connections.insert(con_id, tx);

        stream
            .write(&ShellServerMessage::RemotePtyEvent(
                RemotePtyEventPayload::Connect(con_id),
            ))
            .await?;

        let read_tx = self.read_tx.clone();
        tokio::task::spawn(async move {
            let mut buff = [0u8; 1024];
            loop {
                match rx.read(&mut buff).await {
                    Ok(0) => {
                        let _ = read_tx.send((con_id, Err(Error::msg("stream eof"))));
                        break;
                    }
                    Ok(n) => {
                        let _ = read_tx.send((con_id, Ok(buff[..n].to_vec())));
                    }
                    Err(err) => {
                        let _ =
                            read_tx.send((con_id, Err(err).context("failed to read from stream")));
                        break;
                    }
                };
            }
        });

        Ok(())
    }

    async fn handle_data(
        &mut self,
        stream: &mut ShellStream,
        payload: RemotePtyDataPayload,
    ) -> Result<()> {
        let con = match self.connections.get_mut(&payload.con_id) {
            Some(con) => con,
            None => return Err(Error::msg("unknown connection id")),
        };

        let res = con
            .write_all(&payload.data.as_slice())
            .await
            .context("failed to write to unix stream");

        if let Err(err) = res {
            stream
                .write(&ShellServerMessage::RemotePtyEvent(
                    RemotePtyEventPayload::Close(payload.con_id),
                ))
                .await?;
            return Err(err);
        }

        Ok(())
    }

    async fn handle_new_read(
        &mut self,
        stream: &mut ShellStream,
        con_id: u32,
        res: Result<Vec<u8>>,
    ) -> Result<()> {
        match res {
            Ok(data) => {
                stream
                    .write(&ShellServerMessage::RemotePtyEvent(
                        RemotePtyEventPayload::Payload(RemotePtyDataPayload { con_id, data }),
                    ))
                    .await?;
            }
            Err(err) => {
                debug!("rpty read error: {}", err);
                self.connections.remove(&con_id);

                stream
                    .write(&ShellServerMessage::RemotePtyEvent(
                        RemotePtyEventPayload::Close(con_id),
                    ))
                    .await?;
            }
        }

        Ok(())
    }

    async fn handle_exit(&mut self, stream: &mut ShellStream, exit_code: ExitStatus) -> Result<()> {
        stream
            .write(&ShellServerMessage::Exited(
                exit_code.code().map(|i| i as u8).unwrap_or(0),
            ))
            .await
    }
}

#[async_trait]
impl Shell for RemotePtyShell {
    async fn read(&mut self, _buff: &mut [u8]) -> Result<usize> {
        unreachable!()
    }

    async fn write(&mut self, _buff: &[u8]) -> Result<()> {
        unreachable!()
    }

    fn resize(&mut self, _size: WindowSize) -> Result<()> {
        unreachable!()
    }

    fn exit_code(&self) -> Result<u8> {
        unreachable!()
    }

    fn network_peer_config(&self) -> &NetworkPeerConfig {
        &self.network_peer_config
    }

    fn custom_io_handling(&self) -> bool {
        true
    }

    async fn stream_io(&mut self, stream: &mut ShellStream) -> Result<()> {
        Pin::new(self).do_stream_io(stream).await
    }
}

async fn spawn_rpty_bash(rpty_bash: RptyBash, config: &RptyCommandConfig) -> Result<Child> {
    match rpty_bash {
        RptyBash::Path(path) => match create_rpty_command(&path, config).spawn() {
            Ok(proc) => Ok(proc),
            Err(err) if err.kind() == io::ErrorKind::PermissionDenied => {
                warn!(
                    "failed to execute rpty bash from {}; retrying through memfd",
                    path
                );
                spawn_rpty_bash_memfd(&path, config)
                    .await
                    .with_context(|| "Failed to start shell through memfd")
            }
            Err(err) => Err(Error::from(err).context("Failed to start shell")),
        },
        RptyBash::Memfd(memfd) => spawn_rpty_bash_memfd_file(memfd, config)
            .with_context(|| "Failed to start shell through downloaded memfd"),
    }
}

fn create_rpty_command(path: &str, config: &RptyCommandConfig) -> Command {
    let mut command = Command::new(path);
    configure_rpty_command(&mut command, config);
    command
}

fn configure_rpty_command(command: &mut Command, config: &RptyCommandConfig) {
    command
        .env("RPTY_TRANSPORT", format!("unix:{}", config.sock_path))
        .env("TERM", &config.term)
        .env("PS1", config.ps1)
        .arg("--noprofile")
        .arg("--norc")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
}

async fn spawn_rpty_bash_memfd(path: &str, config: &RptyCommandConfig) -> Result<Child> {
    let memfd = tokio::task::spawn_blocking({
        let path = path.to_string();
        move || copy_file_to_memfd(&path)
    })
    .await
    .context("failed to join memfd copy task")??;

    spawn_rpty_bash_memfd_file(memfd, config)
}

fn spawn_rpty_bash_memfd_file(memfd: StdFile, config: &RptyCommandConfig) -> Result<Child> {
    let exec_payload = MemfdExecPayload::new(memfd, config)?;
    let mut command = Command::new("/proc/self/exe");
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    unsafe {
        command.pre_exec(move || exec_payload.execveat());
    }

    command.spawn().map_err(Error::from)
}

fn copy_file_to_memfd(path: &str) -> io::Result<StdFile> {
    let mut source = StdFile::open(path)?;
    let mut memfd = create_memfd()?;
    io::copy(&mut source, &mut memfd)?;
    make_memfd_executable(&memfd)?;

    Ok(memfd)
}

fn copy_bytes_to_memfd(bytes: &[u8]) -> io::Result<StdFile> {
    let mut memfd = create_memfd()?;
    memfd.write_all(bytes)?;
    make_memfd_executable(&memfd)?;

    Ok(memfd)
}

fn make_memfd_executable(memfd: &StdFile) -> io::Result<()> {
    let mode = 0o700;
    let chmod_res = unsafe { libc::fchmod(memfd.as_raw_fd(), mode) };
    if chmod_res == -1 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

fn create_memfd() -> io::Result<StdFile> {
    const MFD_EXEC: libc::c_uint = 0x0010;

    let name = CString::new("bash-rpty").unwrap();
    let fd = unsafe { libc::syscall(libc::SYS_memfd_create, name.as_ptr(), MFD_EXEC) };
    let fd = if fd == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
        unsafe { libc::syscall(libc::SYS_memfd_create, name.as_ptr(), 0) }
    } else {
        fd
    };

    if fd == -1 {
        return Err(io::Error::last_os_error());
    }

    Ok(unsafe { StdFile::from_raw_fd(fd as libc::c_int) })
}

struct MemfdExecPayload {
    memfd: StdFile,
    empty_path: CString,
    _argv: Vec<CString>,
    _env: Vec<CString>,
    argv_ptrs: Vec<usize>,
    env_ptrs: Vec<usize>,
}

impl MemfdExecPayload {
    fn new(memfd: StdFile, config: &RptyCommandConfig) -> Result<Self> {
        let empty_path = CString::new("").unwrap();
        let argv = vec![
            CString::new("bash-rpty").unwrap(),
            CString::new("--noprofile").unwrap(),
            CString::new("--norc").unwrap(),
        ];
        let env = rpty_env(config)?;
        let argv_ptrs = cstring_ptrs(&argv);
        let env_ptrs = cstring_ptrs(&env);

        Ok(Self {
            memfd,
            empty_path,
            _argv: argv,
            _env: env,
            argv_ptrs,
            env_ptrs,
        })
    }

    fn execveat(&self) -> io::Result<()> {
        const AT_EMPTY_PATH: libc::c_int = 0x1000;

        let result = unsafe {
            libc::syscall(
                libc::SYS_execveat,
                self.memfd.as_raw_fd(),
                self.empty_path.as_ptr(),
                self.argv_ptrs.as_ptr() as *const *const libc::c_char,
                self.env_ptrs.as_ptr() as *const *const libc::c_char,
                AT_EMPTY_PATH,
            )
        };

        if result == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

fn cstring_ptrs(values: &[CString]) -> Vec<usize> {
    let mut ptrs = values
        .iter()
        .map(|value| value.as_ptr() as usize)
        .collect::<Vec<_>>();
    ptrs.push(0);
    ptrs
}

fn rpty_env(config: &RptyCommandConfig) -> Result<Vec<CString>> {
    let overrides = [
        (
            OsString::from("RPTY_TRANSPORT"),
            OsString::from(format!("unix:{}", config.sock_path)),
        ),
        (OsString::from("TERM"), OsString::from(&config.term)),
        (OsString::from("PS1"), OsString::from(config.ps1)),
    ];

    let mut env = env::vars_os()
        .filter(|(key, _)| {
            !overrides
                .iter()
                .any(|(override_key, _)| override_key == key)
        })
        .collect::<Vec<_>>();
    env.extend(overrides);

    env.into_iter()
        .map(|(key, value)| {
            let mut bytes = key.as_os_str().as_bytes().to_vec();
            bytes.push(b'=');
            bytes.extend(value.as_os_str().as_bytes());
            CString::new(bytes).context("environment variable contained nul byte")
        })
        .collect()
}

async fn download_rpty_bash() -> Result<RptyBash> {
    let arch = if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        panic!("unknown cpu arch")
    };

    let url_path = format!("/bash-linux-{arch}-stripped");

    let hostname = "rpty-artifacts.tunshell.com";
    let sock_addr = (hostname, 443)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| Error::msg(format!("could not resolve {hostname}")))?;

    let mut tls_config = tokio_rustls::rustls::ClientConfig::default();
    tls_config
        .root_store
        .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);

    let connector = TlsConnector::from(Arc::new(tls_config));

    debug!("connecting to rpty-artifacts.tunshel.com:443");
    let tcp = TcpStream::connect(sock_addr).await?;
    let mut tls = connector
        .connect(
            DNSNameRef::try_from_ascii(hostname.as_bytes()).unwrap(),
            tcp,
        )
        .await?;

    debug!("downloading rpty bash");
    tls.write_all(format!("GET {url_path} HTTP/1.1\nHost: {hostname}\n\n").as_bytes())
        .await?;

    let line = read_line(&mut tls).await?;

    if !line.contains("200 OK") {
        error!("unexpected response from server: {}", line);
        return Err(Error::msg("unexpected response from server"));
    }

    let mut content_length = 0;

    loop {
        let header = read_line(&mut tls).await?;

        if header.to_lowercase().starts_with("content-length:") {
            content_length = header
                .split_once(':')
                .unwrap()
                .1
                .trim()
                .parse::<u64>()
                .unwrap_or(0);
        }

        if header.is_empty() {
            // body starts now
            break;
        }
    }

    if content_length == 0 {
        return Err(Error::msg("failed to find content-length from response"));
    }

    debug!("reading rpty bash artifact");
    let mut buff = [0u8; 1024];
    let mut body = Vec::with_capacity(content_length as usize);
    let mut downloaded = 0;
    while downloaded < content_length {
        let n = tls.read(&mut buff).await.context("failed to read")?;
        if n == 0 {
            break;
        }

        body.extend_from_slice(&buff[..n]);
        downloaded += n as u64;
    }

    if downloaded != content_length {
        return Err(Error::msg(format!(
            "download size {downloaded} was not the same as content length {content_length}"
        )));
    }

    debug!("finished downloading file");

    let local_path = get_exe_dir()
        .map(|tmp_dir| format!("{tmp_dir}/bash-rpty"))
        .ok();

    if let Some(local_path) = local_path {
        match save_rpty_bash_to_file(&local_path, &body).await {
            Ok(()) => return Ok(RptyBash::Path(local_path)),
            Err(err) => {
                warn!(
                    "failed to save rpty bash to {}; retrying download through memfd: {}",
                    local_path, err
                );
            }
        }
    } else {
        warn!("failed to find rpty bash disk cache directory; retrying download through memfd");
    }

    let memfd = tokio::task::spawn_blocking(move || copy_bytes_to_memfd(&body))
        .await
        .context("failed to join memfd write task")?
        .context("failed to write downloaded rpty bash to memfd")?;

    Ok(RptyBash::Memfd(memfd))
}

async fn save_rpty_bash_to_file(local_path: &str, body: &[u8]) -> Result<()> {
    debug!("saving rpty bash to {}", local_path);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .open(local_path)
        .await
        .with_context(|| format!("failed to open rpty download file {local_path}"))?;

    file.write_all(body)
        .await
        .with_context(|| format!("failed to write rpty download file {local_path}"))?;

    debug!("making executable");
    std::fs::set_permissions(local_path, std::fs::Permissions::from_mode(0o744))
        .with_context(|| format!("failed to chmod rpty download file {local_path}"))?;
    debug!("done");

    Ok(())
}

async fn read_line(tls: &mut TlsStream<TcpStream>) -> Result<String> {
    let mut buff = vec![];

    loop {
        let char = tls.read_u8().await.context("failed to read")?;

        // ignore carriage return
        if char == 13 {
            continue;
        }

        // break on newline
        if char == 10 {
            break;
        }

        buff.push(char);
    }

    String::from_utf8(buff).context("failed to parse as utf8")
}

async fn get_temp_dir() -> Result<String> {
    for dir in temp_dir_candidates() {
        match ensure_writable_dir(&dir) {
            Ok(()) => {
                return dir
                    .to_str()
                    .map(|dir| dir.to_string())
                    .ok_or_else(|| Error::msg("failed to convert temp dir to str"));
            }
            Err(err) => {
                debug!("skipping rpty temp dir {}: {}", dir.display(), err);
            }
        }
    }

    Err(Error::msg("could not find writable temp dir for rpty"))
}

fn get_exe_dir() -> Result<String> {
    let tmp_dir = env::current_exe().map_err(|_| Error::msg("could not get running exe path"))?;
    let tmp_dir = tmp_dir
        .parent()
        .ok_or_else(|| Error::msg("could not get path parent"))?;
    let tmp_dir = tmp_dir
        .to_str()
        .ok_or_else(|| Error::msg("failed to convert exe dir to str"))?;

    Ok(tmp_dir.to_string())
}

fn temp_dir_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    if let Ok(exe) = env::current_exe() {
        if let Some(parent) = exe.parent() {
            candidates.push(parent.to_path_buf());
        }
    }

    if let Ok(cwd) = env::current_dir() {
        candidates.push(cwd);
    }

    candidates.extend(
        ["TMPDIR", "TEMP", "TMP", "XDG_RUNTIME_DIR"]
            .iter()
            .filter_map(env::var_os)
            .map(PathBuf::from),
    );
    candidates.push(PathBuf::from("/tmp"));

    let mut unique = Vec::new();
    for candidate in candidates {
        if !unique.iter().any(|dir| dir == &candidate) {
            unique.push(candidate);
        }
    }

    unique
}

fn ensure_writable_dir(dir: &Path) -> io::Result<()> {
    let probe_path = dir.join(format!(".tunshell-write-test-{}", std::process::id()));
    let probe_file = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .open(&probe_path)?;
    drop(probe_file);
    let _ = std::fs::remove_file(probe_path);
    Ok(())
}

async fn create_pty_sock() -> Result<(String, UnixListener)> {
    let tmp_dir = get_temp_dir().await?;
    let pid = std::process::id();
    let sock_path = format!("{tmp_dir}/rpty.{pid}.sock");

    let listener =
        UnixListener::bind(sock_path.clone()).context("failed to create unix sock for rpty")?;

    Ok((sock_path, listener))
}

impl Drop for StreamingState {
    fn drop(&mut self) {
        // we dont want the shell hanging arou
        let _ = self.proc.kill();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn spawn_rpty_bash_memfd_executes_file() {
        let config = test_config();

        let child = match spawn_rpty_bash_memfd("/bin/true", &config).await {
            Ok(child) => child,
            Err(err) if error_has_errno(&err, libc::ENOSYS) => {
                eprintln!("skipping memfd exec test: memfd_create/execveat is unavailable");
                return;
            }
            Err(err) => panic!("spawn through memfd: {}", err),
        };
        let status = child.await.expect("wait for child");

        assert!(status.success());
    }

    #[tokio::test]
    async fn spawn_downloaded_rpty_bash_memfd_executes_file() {
        let config = test_config();
        let bytes = std::fs::read("/bin/true").expect("read test binary");
        let memfd = match copy_bytes_to_memfd(&bytes) {
            Ok(memfd) => memfd,
            Err(err) if err.raw_os_error() == Some(libc::ENOSYS) => {
                eprintln!("skipping memfd exec test: memfd_create is unavailable");
                return;
            }
            Err(err) => panic!("write memfd: {}", err),
        };

        let child = match spawn_rpty_bash_memfd_file(memfd, &config) {
            Ok(child) => child,
            Err(err) if error_has_errno(&err, libc::ENOSYS) => {
                eprintln!("skipping memfd exec test: execveat is unavailable");
                return;
            }
            Err(err) => panic!("spawn downloaded memfd: {}", err),
        };
        let status = child.await.expect("wait for child");

        assert!(status.success());
    }

    fn error_has_errno(err: &Error, errno: i32) -> bool {
        err.chain().any(|cause| {
            cause
                .downcast_ref::<io::Error>()
                .and_then(|io_error| io_error.raw_os_error())
                == Some(errno)
        })
    }

    fn test_config() -> RptyCommandConfig {
        RptyCommandConfig {
            sock_path: "/tmp/tunshell-test.sock".to_string(),
            term: "xterm".to_string(),
            ps1: "$ ",
        }
    }
}
