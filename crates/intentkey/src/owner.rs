//! Private owner input and transport; never part of the agent protocol.

use std::{
    fs::{File, OpenOptions},
    io::{self, Write},
    os::fd::{AsRawFd, FromRawFd},
    os::unix::fs::OpenOptionsExt,
    path::Path,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use intentkey_core::owner::{OwnerRequest, OwnerResponse, SecretErrorCode, owner_socket_path};
use nix::{
    fcntl::{FcntlArg, FdFlag, OFlag, fcntl},
    sys::{
        socket::{UnixAddr, getsockname},
        stat::{SFlag, fstat},
        termios::{self, LocalFlags, SetArg, SpecialCharacterIndices, Termios},
    },
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, unix::AsyncFd},
    net::UnixStream,
    signal::unix::{SignalKind, signal},
    time::timeout,
};
use zeroize::Zeroizing;

const PASSPHRASE_LIMIT: usize = 1024;
const VALUE_LIMIT: usize = 65_536;
const METADATA_LIMIT: usize = 65_536;
const INPUT_DEADLINE: Duration = Duration::from_secs(120);
const ADMISSION_DEADLINE: Duration = Duration::from_secs(5);
const FRAME_DEADLINE: Duration = Duration::from_secs(30);
const RESPONSE_DEADLINE: Duration = Duration::from_secs(120);

/// Reads the private input completely before opening the dedicated owner socket.
///
/// FD mode requires EOF after its frames; init confirmation is the parent's job.
/// Handled terminal signals cancel input; the integrating CLI must exit on error.
pub async fn run(
    socket: &Path,
    request: OwnerRequest,
    secret_fd: Option<i32>,
) -> Result<OwnerResponse, SecretErrorCode> {
    // Tokio's handlers remain process-wide after a subscription is dropped. Keep
    // subscriptions alive through transport too, rather than ignoring later signals.
    let mut interrupt = signal(SignalKind::interrupt()).map_err(output_error)?;
    let mut terminate = signal(SignalKind::terminate()).map_err(output_error)?;
    let mut hangup = signal(SignalKind::hangup()).map_err(output_error)?;
    let mut quit = signal(SignalKind::quit()).map_err(output_error)?;
    let mut suspend = signal(SignalKind::from_raw(nix::libc::SIGTSTP)).map_err(output_error)?;
    tokio::select! {
        biased;
        _ = interrupt.recv() => Err(SecretErrorCode::Unavailable),
        _ = terminate.recv() => Err(SecretErrorCode::Unavailable),
        _ = hangup.recv() => Err(SecretErrorCode::Unavailable),
        _ = quit.recv() => Err(SecretErrorCode::Unavailable),
        _ = suspend.recv() => Err(SecretErrorCode::Unavailable),
        result = exchange(socket, &request, secret_fd) => result,
    }
}

async fn exchange(
    socket: &Path,
    request: &OwnerRequest,
    secret_fd: Option<i32>,
) -> Result<OwnerResponse, SecretErrorCode> {
    let (passphrase, value) = collect_input(request, secret_fd).await?;
    let mut stream = timeout(
        ADMISSION_DEADLINE,
        UnixStream::connect(owner_socket_path(socket)),
    )
    .await
    .map_err(|_| SecretErrorCode::Timeout)?
    .map_err(|_| SecretErrorCode::Unavailable)?;
    timeout(
        FRAME_DEADLINE,
        write_request(
            &mut stream,
            request,
            &passphrase,
            value.as_deref().map(Vec::as_slice),
        ),
    )
    .await
    .map_err(|_| SecretErrorCode::Timeout)??;
    drop(passphrase);
    drop(value);
    timeout(RESPONSE_DEADLINE, read_response(&mut stream))
        .await
        .map_err(|_| SecretErrorCode::Timeout)?
}

const fn needs_value(request: &OwnerRequest) -> bool {
    matches!(
        request,
        OwnerRequest::Store { .. } | OwnerRequest::Update { .. }
    )
}

async fn write_request<W: AsyncWrite + Unpin>(
    output: &mut W,
    request: &OwnerRequest,
    passphrase: &[u8],
    value: Option<&[u8]>,
) -> Result<(), SecretErrorCode> {
    let metadata = serde_json::to_vec(request).map_err(|_| SecretErrorCode::InvalidInput)?;
    if metadata.len() > METADATA_LIMIT {
        return Err(SecretErrorCode::TooLarge);
    }
    output.write_u16(1).await.map_err(output_error)?;
    output
        .write_u32(u32::try_from(metadata.len()).map_err(|_| SecretErrorCode::TooLarge)?)
        .await
        .map_err(output_error)?;
    output.write_all(&metadata).await.map_err(output_error)?;
    write_frame(output, passphrase).await?;
    if let Some(value) = value {
        write_frame(output, value).await?;
    }
    output.flush().await.map_err(output_error)
}

async fn write_frame<W: AsyncWrite + Unpin>(
    output: &mut W,
    bytes: &[u8],
) -> Result<(), SecretErrorCode> {
    output
        .write_u32(u32::try_from(bytes.len()).map_err(|_| SecretErrorCode::TooLarge)?)
        .await
        .map_err(output_error)?;
    output.write_all(bytes).await.map_err(output_error)
}

fn output_error(_: io::Error) -> SecretErrorCode {
    SecretErrorCode::Unavailable
}

fn input_error(error: io::Error) -> SecretErrorCode {
    let code = if error.kind() == io::ErrorKind::UnexpectedEof {
        SecretErrorCode::InvalidInput
    } else {
        SecretErrorCode::Unavailable
    };
    drop(error);
    code
}

async fn read_secret_frame<R: AsyncRead + Unpin>(
    input: &mut R,
    limit: usize,
) -> Result<Zeroizing<Vec<u8>>, SecretErrorCode> {
    let length = input.read_u32().await.map_err(input_error)? as usize;
    if length == 0 {
        return Err(SecretErrorCode::InvalidInput);
    }
    if length > limit {
        return Err(SecretErrorCode::TooLarge);
    }
    let mut bytes = Zeroizing::new(vec![0; length]);
    input.read_exact(&mut bytes).await.map_err(input_error)?;
    Ok(bytes)
}

async fn read_response<R: AsyncRead + Unpin>(
    input: &mut R,
) -> Result<OwnerResponse, SecretErrorCode> {
    // Zeroize even invalid peer bytes: parser errors must never escape this boundary.
    let bytes = read_secret_frame(input, METADATA_LIMIT).await?;
    serde_json::from_slice(&bytes).map_err(|_| SecretErrorCode::InvalidInput)
}

// No Debug implementation: neither input buffers nor terminal state are printable.
struct Input {
    fd: AsyncFd<File>,
    terminal: Option<Termios>,
    original_flags: Option<OFlag>,
}

impl Input {
    fn new(file: File) -> Result<Self, SecretErrorCode> {
        let flags = OFlag::from_bits_truncate(
            fcntl(file.as_raw_fd(), FcntlArg::F_GETFL).map_err(|_| SecretErrorCode::Unavailable)?,
        );
        let fd = AsyncFd::new(file).map_err(output_error)?;
        fcntl(
            fd.get_ref().as_raw_fd(),
            FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK),
        )
        .map_err(|_| SecretErrorCode::Unavailable)?;
        Ok(Self {
            fd,
            terminal: None,
            original_flags: Some(flags),
        })
    }

    fn disable_echo(&mut self) -> Result<(), SecretErrorCode> {
        let original =
            termios::tcgetattr(self.fd.get_ref()).map_err(|_| SecretErrorCode::Unavailable)?;
        let mut private = original.clone();
        // Noncanonical mode avoids the kernel's much smaller canonical line limit.
        private
            .local_flags
            .remove(LocalFlags::ECHO | LocalFlags::ECHONL | LocalFlags::ICANON);
        private.control_chars[SpecialCharacterIndices::VMIN as usize] = 1;
        private.control_chars[SpecialCharacterIndices::VTIME as usize] = 0;
        self.terminal = Some(original);
        termios::tcflush(self.fd.get_ref(), termios::FlushArg::TCIFLUSH)
            .map_err(|_| SecretErrorCode::Unavailable)?;
        termios::tcsetattr(self.fd.get_ref(), SetArg::TCSANOW, &private)
            .map_err(|_| SecretErrorCode::Unavailable)
    }

    fn restore(&mut self) -> Result<(), SecretErrorCode> {
        if let Some(terminal) = &self.terminal {
            // Never drain terminal output here: an unread PTY can block forever.
            let flushed = termios::tcflush(self.fd.get_ref(), termios::FlushArg::TCIFLUSH);
            termios::tcsetattr(self.fd.get_ref(), SetArg::TCSANOW, terminal)
                .map_err(|_| SecretErrorCode::Unavailable)?;
            self.terminal = None;
            flushed.map_err(|_| SecretErrorCode::Unavailable)?;
        }
        if let Some(flags) = self.original_flags {
            fcntl(self.fd.get_ref().as_raw_fd(), FcntlArg::F_SETFL(flags))
                .map_err(|_| SecretErrorCode::Unavailable)?;
            self.original_flags = None;
        }
        Ok(())
    }

    async fn prompt(fd: &AsyncFd<File>, text: &[u8]) -> Result<(), SecretErrorCode> {
        let mut remaining = text;
        while !remaining.is_empty() {
            let mut ready = fd.writable().await.map_err(output_error)?;
            match ready.try_io(|fd| (&mut fd.get_ref()).write(remaining)) {
                Ok(Ok(0)) => return Err(SecretErrorCode::Unavailable),
                Ok(Ok(written)) => remaining = &remaining[written..],
                Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => {}
                Ok(Err(_)) => return Err(SecretErrorCode::Unavailable),
                Err(_) => {}
            }
        }
        Ok(())
    }
}

impl Drop for Input {
    fn drop(&mut self) {
        // Normal/error/signal paths report restoration failure to the caller.
        // Cancellation has no caller, so emit only the fixed error code.
        if self.restore().is_err() && writeln!(io::stderr(), "Unavailable").is_err() {
            std::process::abort();
        }
    }
}

impl AsyncRead for Input {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            let mut ready = std::task::ready!(self.fd.poll_read_ready(cx))?;
            match ready.try_io(|fd| {
                nix::unistd::read(fd.get_ref().as_raw_fd(), buf.initialize_unfilled())
                    .map_err(io::Error::from)
            }) {
                Ok(Ok(count)) => {
                    buf.advance(count);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => {}
                Ok(Err(error)) => return Poll::Ready(Err(error)),
                Err(_) => {}
            }
        }
    }
}

fn inherited_input(fd: i32) -> Result<Input, SecretErrorCode> {
    if fd < 3 {
        return Err(SecretErrorCode::Unsupported);
    }
    let duplicate =
        fcntl(fd, FcntlArg::F_DUPFD_CLOEXEC(3)).map_err(|_| SecretErrorCode::Unsupported)?;
    // SAFETY: successful F_DUPFD_CLOEXEC returns a new exclusively owned descriptor.
    // File takes ownership exactly once; no raw libc calls or borrowed-FD assumptions.
    let file = unsafe { File::from_raw_fd(duplicate) };
    let kind = SFlag::from_bits_truncate(
        fstat(file.as_raw_fd())
            .map_err(|_| SecretErrorCode::Unsupported)?
            .st_mode,
    ) & SFlag::S_IFMT;
    if kind != SFlag::S_IFIFO
        && (kind != SFlag::S_IFSOCK || getsockname::<UnixAddr>(file.as_raw_fd()).is_err())
    {
        return Err(SecretErrorCode::Unsupported);
    }
    // Mark the inherited original as well as our duplicate close-on-exec.
    let flags = FdFlag::from_bits_truncate(
        fcntl(fd, FcntlArg::F_GETFD).map_err(|_| SecretErrorCode::Unavailable)?,
    );
    fcntl(fd, FcntlArg::F_SETFD(flags | FdFlag::FD_CLOEXEC))
        .map_err(|_| SecretErrorCode::Unavailable)?;
    Input::new(file)
}

type InputSecrets = (Zeroizing<Vec<u8>>, Option<Zeroizing<Vec<u8>>>);

async fn collect_input(
    request: &OwnerRequest,
    secret_fd: Option<i32>,
) -> Result<InputSecrets, SecretErrorCode> {
    let mut input = if let Some(fd) = secret_fd {
        inherited_input(fd)?
    } else {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(
                OFlag::O_NONBLOCK.bits() | OFlag::O_CLOEXEC.bits() | OFlag::O_NOCTTY.bits(),
            )
            .open("/dev/tty")
            .map_err(output_error)?;
        let mut input = Input::new(file)?;
        input.disable_echo()?;
        input
    };
    let result = timeout(
        INPUT_DEADLINE,
        read_inputs(&mut input, request, secret_fd.is_none()),
    )
    .await
    .unwrap_or(Err(SecretErrorCode::Timeout));
    input.restore()?;
    result
}

async fn read_inputs(
    input: &mut Input,
    request: &OwnerRequest,
    tty: bool,
) -> Result<InputSecrets, SecretErrorCode> {
    let passphrase = if tty {
        Input::prompt(&input.fd, b"Passphrase: ").await?;
        let passphrase = read_line(input, PASSPHRASE_LIMIT).await?;
        if matches!(request, OwnerRequest::Init) {
            Input::prompt(&input.fd, b"\nConfirm passphrase: ").await?;
            let confirmation = read_line(input, PASSPHRASE_LIMIT).await?;
            if passphrase[..] != confirmation[..] {
                return Err(SecretErrorCode::InvalidInput);
            }
        }
        passphrase
    } else {
        read_secret_frame(input, PASSPHRASE_LIMIT).await?
    };
    let value = if needs_value(request) {
        Some(if tty {
            Input::prompt(&input.fd, b"\nValue: ").await?;
            read_line(input, VALUE_LIMIT).await?
        } else {
            read_secret_frame(input, VALUE_LIMIT).await?
        })
    } else {
        None
    };
    if tty {
        Input::prompt(&input.fd, b"\n").await?;
    } else {
        let mut extra = Zeroizing::new([0_u8; 1]);
        if input.read(&mut *extra).await.map_err(input_error)? != 0 {
            return Err(SecretErrorCode::InvalidInput);
        }
    }
    Ok((passphrase, value))
}

async fn read_line<R: AsyncRead + Unpin>(
    input: &mut R,
    limit: usize,
) -> Result<Zeroizing<Vec<u8>>, SecretErrorCode> {
    // Fixed allocation: growing a Vec could free an unwiped previous allocation.
    let mut bytes = Zeroizing::new(vec![0; limit]);
    let mut length = 0;
    let mut byte = Zeroizing::new([0_u8; 1]);
    loop {
        input.read_exact(&mut *byte).await.map_err(input_error)?;
        match byte[0] {
            b'\n' | b'\r' => {
                if length == 0 {
                    return Err(SecretErrorCode::InvalidInput);
                }
                bytes.truncate(length);
                return Ok(bytes);
            }
            4 => return Err(SecretErrorCode::InvalidInput), // terminal EOF key
            8 | 127 => {
                if length > 0 {
                    length -= 1;
                    bytes[length] = 0;
                }
            }
            _ if length == limit => return Err(SecretErrorCode::TooLarge),
            _ => {
                bytes[length] = byte[0];
                length += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn marker(length: usize) -> Zeroizing<Vec<u8>> {
        let mut bytes = Zeroizing::new(vec![0; length]);
        let result = std::fs::File::open("/dev/urandom")
            .and_then(|mut source| source.read_exact(&mut bytes));
        assert!(result.is_ok());
        bytes
    }

    #[tokio::test]
    async fn rejects_oversized_empty_and_truncated_frames() {
        for length in [0_u32, 1025, u32::MAX] {
            let bytes = length.to_be_bytes();
            let mut input = &bytes[..];
            assert!(
                read_secret_frame(&mut input, PASSPHRASE_LIMIT)
                    .await
                    .is_err()
            );
        }
        let secret = marker(32);
        let mut bytes = Zeroizing::new(Vec::new());
        bytes.extend_from_slice(&32_u32.to_be_bytes());
        bytes.extend_from_slice(&secret[..31]);
        let mut input = &bytes[..];
        assert!(matches!(
            read_secret_frame(&mut input, PASSPHRASE_LIMIT).await,
            Err(SecretErrorCode::InvalidInput)
        ));
        let mut input = &bytes[..2];
        assert!(
            read_secret_frame(&mut input, PASSPHRASE_LIMIT)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn metadata_and_secret_frames_are_separate() -> Result<(), SecretErrorCode> {
        let passphrase = marker(32);
        let value = marker(80);
        let request = OwnerRequest::Store {
            kind: intentkey_core::owner::NativeKind::Password,
        };
        let mut wire = Zeroizing::new(Vec::with_capacity(512));
        write_request(&mut *wire, &request, &passphrase, Some(&value)).await?;
        assert_eq!(u16::from_be_bytes([wire[0], wire[1]]), 1);
        let length = u32::from_be_bytes([wire[2], wire[3], wire[4], wire[5]]) as usize;
        let metadata = &wire[6..6 + length];
        assert!(matches!(
            serde_json::from_slice::<OwnerRequest>(metadata),
            Ok(OwnerRequest::Store { .. })
        ));
        assert!(
            !metadata
                .windows(passphrase.len())
                .any(|part| part == &passphrase[..])
        );
        assert!(!metadata.windows(value.len()).any(|part| part == &value[..]));
        let mut frames = &wire[6 + length..];
        let decoded = read_secret_frame(&mut frames, PASSPHRASE_LIMIT).await?;
        assert!(decoded[..].eq(&passphrase[..]));
        let decoded = read_secret_frame(&mut frames, VALUE_LIMIT).await?;
        assert!(decoded[..].eq(&value[..]));
        assert!(frames.is_empty());
        Ok(())
    }

    #[test]
    fn unsupported_descriptors_fail() -> Result<(), SecretErrorCode> {
        use std::os::fd::AsRawFd;
        for fd in [-1, 0, 1, 2, i32::MAX] {
            assert!(inherited_input(fd).is_err());
        }
        let file = std::fs::File::open(concat!(env!("CARGO_MANIFEST_DIR"), "/src/owner.rs"))
            .map_err(output_error)?;
        assert!(matches!(
            inherited_input(file.as_raw_fd()),
            Err(SecretErrorCode::Unsupported)
        ));
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").map_err(output_error)?;
        assert!(matches!(
            inherited_input(socket.as_raw_fd()),
            Err(SecretErrorCode::Unsupported)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn exact_limits_and_bounded_terminal_lines() -> Result<(), SecretErrorCode> {
        for limit in [PASSPHRASE_LIMIT, VALUE_LIMIT] {
            let mut secret = marker(limit);
            for byte in &mut *secret {
                *byte = b'a' + *byte % 26;
            }
            let mut wire = Zeroizing::new(Vec::with_capacity(limit + 4));
            write_frame(&mut *wire, &secret).await?;
            let decoded = read_secret_frame(&mut &wire[..], limit).await?;
            assert!(decoded[..].eq(&secret[..]));
            wire.clear();
            wire.extend_from_slice(&secret);
            wire.push(b'\n');
            let decoded = read_line(&mut &wire[..], limit).await?;
            assert!(decoded[..].eq(&secret[..]));
            wire[limit] = secret[0];
            wire.push(b'\n');
            assert!(matches!(
                read_line(&mut &wire[..], limit).await,
                Err(SecretErrorCode::TooLarge)
            ));
        }
        Ok(())
    }

    #[tokio::test]
    async fn inherited_pipe_requires_exact_frames_and_eof() -> Result<(), SecretErrorCode> {
        let secret = marker(32);
        for extra in [false, true] {
            let (read, write) = nix::unistd::pipe().map_err(|_| SecretErrorCode::Unavailable)?;
            let mut input = inherited_input(read.as_raw_fd())?;
            let original_flags = input.original_flags;
            let mut writer = File::from(write);
            io::Write::write_all(&mut writer, &32_u32.to_be_bytes()).map_err(output_error)?;
            io::Write::write_all(&mut writer, &secret).map_err(output_error)?;
            if extra {
                io::Write::write_all(&mut writer, &secret[..1]).map_err(output_error)?;
            }
            drop(writer);
            let result = timeout(
                Duration::from_secs(5),
                read_inputs(&mut input, &OwnerRequest::Unlock, false),
            )
            .await
            .map_err(|_| SecretErrorCode::Timeout)?;
            input.restore()?;
            let flags = OFlag::from_bits_truncate(
                fcntl(read.as_raw_fd(), FcntlArg::F_GETFL)
                    .map_err(|_| SecretErrorCode::Unavailable)?,
            );
            assert_eq!(Some(flags), original_flags);
            if extra {
                assert!(matches!(result, Err(SecretErrorCode::InvalidInput)));
            } else {
                let (passphrase, value) = result?;
                assert!(passphrase[..].eq(&secret[..]));
                assert!(value.is_none());
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn terminal_confirmation_failure_restores_echo() -> Result<(), SecretErrorCode> {
        let pty = nix::pty::openpty(None, None).map_err(|_| SecretErrorCode::Unavailable)?;
        let slave = File::from(pty.slave);
        let original = termios::tcgetattr(&slave).map_err(|_| SecretErrorCode::Unavailable)?;
        let mut input = Input::new(slave.try_clone().map_err(output_error)?)?;
        input.disable_echo()?;
        let private = termios::tcgetattr(&slave).map_err(|_| SecretErrorCode::Unavailable)?;
        assert!(
            !private
                .local_flags
                .intersects(LocalFlags::ECHO | LocalFlags::ECHONL | LocalFlags::ICANON)
        );
        let mut bytes = marker(32);
        for byte in &mut *bytes {
            *byte = b'a' + *byte % 26;
        }
        let mut master = File::from(pty.master);
        io::Write::write_all(&mut master, &bytes).map_err(output_error)?;
        io::Write::write_all(&mut master, b"\n").map_err(output_error)?;
        bytes[0] = if bytes[0] == b'a' { b'b' } else { b'a' };
        io::Write::write_all(&mut master, &bytes).map_err(output_error)?;
        io::Write::write_all(&mut master, b"\n").map_err(output_error)?;
        let result = timeout(
            Duration::from_secs(5),
            read_inputs(&mut input, &OwnerRequest::Init, true),
        )
        .await
        .map_err(|_| SecretErrorCode::Timeout)?;
        drop(input);
        assert!(matches!(result, Err(SecretErrorCode::InvalidInput)));
        let restored = termios::tcgetattr(&slave).map_err(|_| SecretErrorCode::Unavailable)?;
        assert_eq!(restored, original);
        Ok(())
    }

    #[tokio::test]
    async fn run_uses_owner_socket_and_framed_unix_fd() -> Result<(), SecretErrorCode> {
        use std::os::unix::fs::DirBuilderExt;
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| SecretErrorCode::Unavailable)?
            .as_nanos();
        let directory =
            std::path::PathBuf::from(format!("/tmp/ik-owner-{}-{nonce}", std::process::id()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .map_err(output_error)?;
        let agent = directory.join("agent.sock");
        let socket = owner_socket_path(&agent);
        let listener = tokio::net::UnixListener::bind(&socket).map_err(output_error)?;
        let secret = marker(32);
        let (reader, mut writer) = std::os::unix::net::UnixStream::pair().map_err(output_error)?;
        io::Write::write_all(&mut writer, &32_u32.to_be_bytes()).map_err(output_error)?;
        io::Write::write_all(&mut writer, &secret).map_err(output_error)?;
        writer
            .shutdown(std::net::Shutdown::Write)
            .map_err(output_error)?;
        let server = async {
            let (mut stream, _) = listener.accept().await.map_err(output_error)?;
            assert_eq!(stream.read_u16().await.map_err(input_error)?, 1);
            let metadata = read_secret_frame(&mut stream, METADATA_LIMIT).await?;
            assert!(matches!(
                serde_json::from_slice::<OwnerRequest>(&metadata),
                Ok(OwnerRequest::Unlock)
            ));
            let received = read_secret_frame(&mut stream, PASSPHRASE_LIMIT).await?;
            assert!(received[..].eq(&secret[..]));
            let response = serde_json::to_vec(&OwnerResponse::State(
                intentkey_core::owner::VaultStatus::Unlocked,
            ))
            .map_err(|_| SecretErrorCode::InvalidInput)?;
            write_frame(&mut stream, &response).await
        };
        let result = timeout(Duration::from_secs(5), async {
            tokio::try_join!(
                run(&agent, OwnerRequest::Unlock, Some(reader.as_raw_fd())),
                server
            )
        })
        .await;
        drop(listener);
        std::fs::remove_file(socket).map_err(output_error)?;
        std::fs::remove_dir(directory).map_err(output_error)?;
        let (response, ()) = result.map_err(|_| SecretErrorCode::Timeout)??;
        assert!(matches!(
            response,
            OwnerResponse::State(intentkey_core::owner::VaultStatus::Unlocked)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn invalid_responses_return_only_fixed_codes() -> Result<(), SecretErrorCode> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(100));
        write_frame(&mut *bytes, &marker(64)).await?;
        assert!(matches!(
            read_response(&mut &bytes[..]).await,
            Err(SecretErrorCode::InvalidInput)
        ));
        let length = 65_537_u32.to_be_bytes();
        assert!(matches!(
            read_response(&mut &length[..]).await,
            Err(SecretErrorCode::TooLarge)
        ));
        Ok(())
    }
}
