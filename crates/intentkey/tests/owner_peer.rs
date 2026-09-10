//! Real owner CLI transport checks, using runtime-random noncredential inputs.

use std::{
    error::Error,
    fs::{self, File},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, PermissionsExt, symlink},
    },
    path::{Path, PathBuf},
    process::Stdio,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use intentkey_core::owner::{OwnerRequest, OwnerResponse, VaultStatus};
use nix::fcntl::{FcntlArg, FdFlag, fcntl};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixListener,
    process::Command,
    sync::Notify,
    time::timeout,
};
use zeroize::Zeroizing;

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;
const DEADLINE: Duration = Duration::from_secs(10);
static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct Directory(PathBuf);

impl Directory {
    fn new() -> TestResult<Self> {
        let path = PathBuf::from(format!(
            "/tmp/ik-peer-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Self(path))
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        assert!(
            fs::remove_dir_all(&self.0).is_ok(),
            "fixture cleanup failed"
        );
    }
}

#[tokio::test]
async fn public_runtime_refuses_before_sending_secret() -> TestResult {
    let directory = Directory::new()?;
    fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o777))?;
    let socket = directory.0.join("owner.sock");
    let listener = UnixListener::bind(&socket)?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
    let (output, received, marker_received) = exchange(&directory.0, listener).await?;
    // The marker flag proves baseline disclosure without printing private bytes.
    assert!(
        received == 0,
        "owner bytes escaped; marker received: {marker_received}"
    );
    assert!(!output.status.success());
    assert!(matches!(
        serde_json::from_slice::<OwnerResponse>(&output.stdout)?,
        OwnerResponse::Error(intentkey_core::owner::SecretErrorCode::Unavailable)
    ));
    assert_eq!(
        fs::metadata(&directory.0)?.permissions().mode() & 0o777,
        0o777
    );
    Ok(())
}

#[tokio::test]
async fn private_same_uid_endpoint_remains_usable() -> TestResult {
    let directory = Directory::new()?;
    let socket = directory.0.join("owner.sock");
    let listener = UnixListener::bind(&socket)?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
    let (output, received, marker_received) = exchange(&directory.0, listener).await?;
    assert!(output.status.success());
    assert!(received > 0 && marker_received);
    assert!(matches!(
        serde_json::from_slice::<OwnerResponse>(&output.stdout)?,
        OwnerResponse::State(VaultStatus::Unlocked)
    ));
    Ok(())
}

#[tokio::test]
async fn nonprivate_paths_refuse_without_repair() -> TestResult {
    for (directory_mode, socket_mode) in [(0o755, 0o600), (0o770, 0o600), (0o700, 0o666)] {
        let directory = Directory::new()?;
        let socket = directory.0.join("owner.sock");
        let listener = UnixListener::bind(&socket)?;
        fs::set_permissions(&directory.0, fs::Permissions::from_mode(directory_mode))?;
        fs::set_permissions(&socket, fs::Permissions::from_mode(socket_mode))?;
        assert_refused(exchange(&directory.0, listener).await?)?;
        assert_eq!(
            fs::metadata(&directory.0)?.permissions().mode() & 0o777,
            directory_mode
        );
        assert_eq!(
            fs::metadata(&socket)?.permissions().mode() & 0o777,
            socket_mode
        );
    }
    Ok(())
}

#[tokio::test]
async fn preplanted_socket_and_immediate_directory_symlinks_refuse() -> TestResult {
    for directory_link in [false, true] {
        let directory = Directory::new()?;
        let target = directory.0.join("private");
        fs::DirBuilder::new().mode(0o700).create(&target)?;
        let socket = target.join("owner.sock");
        let listener = UnixListener::bind(&socket)?;
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
        let path = if directory_link {
            let link = directory.0.join("linked");
            symlink(&target, &link)?;
            link
        } else {
            symlink(&socket, directory.0.join("owner.sock"))?;
            directory.0.clone()
        };
        assert_refused(exchange(&path, listener).await?)?;
    }
    Ok(())
}

fn assert_refused(
    (output, received, marker_received): (std::process::Output, usize, bool),
) -> TestResult {
    assert!(
        received == 0,
        "owner bytes escaped; marker received: {marker_received}"
    );
    assert!(!output.status.success());
    assert!(matches!(
        serde_json::from_slice::<OwnerResponse>(&output.stdout)?,
        OwnerResponse::Error(intentkey_core::owner::SecretErrorCode::Unavailable)
    ));
    Ok(())
}

async fn exchange(
    directory: &Path,
    listener: UnixListener,
) -> TestResult<(std::process::Output, usize, bool)> {
    let mut marker = Zeroizing::new(vec![0; 32]);
    File::open("/dev/urandom")?.read_exact(&mut marker)?;
    let (reader, mut writer) = std::os::unix::net::UnixStream::pair()?;
    writer.write_all(&32_u32.to_be_bytes())?;
    writer.write_all(&marker)?;
    drop(writer);
    let input_fd = reader.as_raw_fd();
    let mut command = Command::new(env!("CARGO_BIN_EXE_intentkey"));
    command
        .arg("--socket")
        .arg(directory.join("agent.sock"))
        .args(["vault", "--secret-fd", &input_fd.to_string(), "unlock"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    // SAFETY: the child hook performs only an async-signal-safe fcntl on a live
    // inherited descriptor. Clearing CLOEXEC here cannot leak it to sibling tests.
    unsafe {
        command.pre_exec(move || {
            fcntl(input_fd, FcntlArg::F_SETFD(FdFlag::empty()))?;
            Ok(())
        });
    }
    let exited = Notify::new();
    let expected_length =
        2 + 4 + serde_json::to_vec(&OwnerRequest::Unlock)?.len() + 4 + marker.len();
    let server = async {
        // Subscribe before spawning the CLI. Exit is the exact no-connect signal;
        // prefer queued accepts so an already closed connection is still inspected.
        let accepted = tokio::select! {
            biased;
            accepted = listener.accept() => Some(accepted?.0),
            () = exited.notified() => match listener.into_std()?.accept() {
                Ok((stream, _)) => {
                    stream.set_nonblocking(true)?;
                    Some(tokio::net::UnixStream::from_std(stream)?)
                },
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => None,
                Err(error) => return Err(error.into()),
            },
        };
        let mut received = Zeroizing::new(vec![0; expected_length]);
        let mut count = 0;
        if let Some(mut stream) = accepted {
            while count < expected_length {
                let read = stream.read(&mut received[count..]).await?;
                if read == 0 {
                    break;
                }
                count += read;
            }
            if count == expected_length {
                let response = serde_json::to_vec(&OwnerResponse::State(VaultStatus::Unlocked))?;
                stream.write_u32(u32::try_from(response.len())?).await?;
                stream.write_all(&response).await?;
            }
        }
        let marker_received = received[..count]
            .windows(marker.len())
            .any(|part| part == &marker[..]);
        Ok::<_, Box<dyn Error + Send + Sync>>((count, marker_received))
    };
    let client = async {
        let child = command.spawn()?;
        drop(reader);
        let output = child.wait_with_output().await?;
        exited.notify_one();
        Ok::<_, Box<dyn Error + Send + Sync>>(output)
    };
    let ((received, marker_received), output) =
        timeout(DEADLINE, async { tokio::try_join!(server, client) }).await??;
    for bytes in [&output.stdout, &output.stderr] {
        assert!(
            !bytes.windows(marker.len()).any(|part| part == &marker[..]),
            "private input in CLI output"
        );
    }
    Ok((output, received, marker_received))
}
