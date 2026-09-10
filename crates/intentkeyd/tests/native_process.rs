//! Actual CLI/daemon encrypted owner lifecycle. Inputs are random noncredentials.

use intentkey_core::{
    DaemonRequest, DaemonResponse, Intent, ItemDescriptor, ItemKind, LoginUse, PrepareUseRequest,
    RefusalCode, SessionCapability, TargetOrigin, UseOperation,
    owner::{OwnerResponse, SecretErrorCode, VaultStatus, owner_socket_path},
};
use nix::fcntl::{FcntlArg, FdFlag, fcntl};
use std::{
    error::Error,
    fs::{self, File},
    io::{BufRead, BufReader, Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::mpsc,
    time::Duration,
};
use zeroize::Zeroizing;

include!("provider_process.rs.inc");

type TestResult<T> = Result<T, Box<dyn Error + Send + Sync>>;
const DEADLINE: Duration = Duration::from_secs(120);

struct Daemon {
    child: Child,
    stopped: mpsc::Receiver<Vec<u8>>,
    socket: PathBuf,
}

impl Daemon {
    fn start(root: &Path) -> TestResult<Self> {
        let socket = root.join("runtime/agent.sock");
        let (ready_tx, ready) = mpsc::channel();
        let (stopped_tx, stopped) = mpsc::channel();
        let mut child = Command::new(env!("CARGO_BIN_EXE_intentkeyd"))
            .arg("--socket")
            .arg(&socket)
            .env("HOME", root)
            .env("XDG_DATA_HOME", root.join("data"))
            .env("XDG_RUNTIME_DIR", root.join("runtime"))
            .env("RUST_LOG", "intentkeyd=info")
            .env("NO_COLOR", "1")
            .env("PROVIDER_POISON", "must-not-reach-provider")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;
        let stderr = child.stderr.take().ok_or("missing stderr")?;
        std::thread::spawn(move || {
            let mut output = Vec::new();
            for line in BufReader::new(stderr).split(b'\n') {
                let Ok(line) = line else { return };
                if line
                    .windows(b"intentkeyd.ready".len())
                    .any(|s| s == b"intentkeyd.ready")
                    && ready_tx.send(()).is_err()
                {
                    return;
                }
                output.extend_from_slice(&line);
                output.push(b'\n');
            }
            let _ = stopped_tx.send(output);
        });
        let daemon = Self {
            child,
            stopped,
            socket,
        };
        ready.recv_timeout(DEADLINE)?;
        Ok(daemon)
    }

    fn stop(&mut self) -> TestResult<Vec<u8>> {
        assert!(
            Command::new("kill")
                .args(["-INT", &self.child.id().to_string()])
                .status()?
                .success()
        );
        let output = self.stopped.recv_timeout(DEADLINE)?;
        assert!(self.child.wait()?.success());
        assert!(!self.socket.exists());
        assert!(!owner_socket_path(&self.socket).exists());
        Ok(output)
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if self.child.try_wait().is_ok_and(|s| s.is_none()) {
            assert!(self.child.kill().is_ok());
        }
        assert!(self.child.wait().is_ok());
    }
}

fn marker(length: usize) -> TestResult<Zeroizing<Vec<u8>>> {
    let mut value = Zeroizing::new(vec![0; length]);
    getrandom::fill(&mut value)?;
    Ok(value)
}

fn no_marker(bytes: &[u8], markers: &[&[u8]]) {
    for marker in markers {
        assert!(
            !bytes.windows(marker.len()).any(|part| part == *marker),
            "private input escaped"
        );
    }
}

fn owner(
    root: &Path,
    args: &[&str],
    pass: &[u8],
    value: Option<&[u8]>,
    markers: &[&[u8]],
) -> TestResult<OwnerResponse> {
    // cargo build --workspace supplies both actual binaries before this process test.
    let cli = Path::new(env!("CARGO_BIN_EXE_intentkeyd")).with_file_name("intentkey");
    let (reader, writer) = nix::unistd::pipe()?;
    assert!(reader.as_raw_fd() >= 3);
    fcntl(writer.as_raw_fd(), FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))?;
    let child = Command::new(cli)
        .arg("--socket")
        .arg(root.join("runtime/agent.sock"))
        .args([
            "--format",
            "json",
            "vault",
            "--secret-fd",
            &reader.as_raw_fd().to_string(),
        ])
        .args(args)
        .env("HOME", root)
        .env("XDG_DATA_HOME", root.join("data"))
        .env("XDG_RUNTIME_DIR", root.join("runtime"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    drop(reader);
    let pid = child.id();
    let pass = Zeroizing::new(pass.to_vec());
    let value = value.map(|bytes| Zeroizing::new(bytes.to_vec()));
    let (written_tx, written) = mpsc::channel();
    let writing = std::thread::spawn(move || {
        let result = (|| -> TestResult<()> {
            let mut writer = File::from(writer);
            writer.write_all(&u32::try_from(pass.len())?.to_be_bytes())?;
            writer.write_all(&pass)?;
            if let Some(value) = value {
                writer.write_all(&u32::try_from(value.len())?.to_be_bytes())?;
                writer.write_all(&value)?;
            }
            Ok(())
        })();
        let _ = written_tx.send(result);
    });
    let (sender, receiver) = mpsc::channel();
    let reaping = std::thread::spawn(move || {
        let _ = sender.send(child.wait_with_output());
    });
    let output: Output = match receiver.recv_timeout(DEADLINE) {
        Ok(output) => output?,
        Err(error) => {
            assert!(
                Command::new("kill")
                    .args(["-KILL", &pid.to_string()])
                    .status()?
                    .success()
            );
            receiver.recv_timeout(DEADLINE)??;
            reaping.join().map_err(|_| "child reaper panicked")?;
            let write_result = written.recv_timeout(DEADLINE)?;
            writing.join().map_err(|_| "private writer panicked")?;
            if let Err(write_error) = write_result {
                return Err(format!("{error}; private pipe write failed: {write_error}").into());
            }
            return Err(error.into());
        }
    };
    reaping.join().map_err(|_| "child reaper panicked")?;
    let write_result = written.recv_timeout(DEADLINE)?;
    writing.join().map_err(|_| "private writer panicked")?;
    write_result?;
    no_marker(&output.stdout, markers);
    no_marker(&output.stderr, markers);
    let response: OwnerResponse = serde_json::from_slice(&output.stdout)
        .map_err(|_| "CLI did not return a metadata-only owner response")?;
    assert_eq!(
        output.status.success(),
        !matches!(response, OwnerResponse::Error(_))
    );
    Ok(response)
}

fn error(response: &OwnerResponse, expected: SecretErrorCode) {
    assert!(matches!(response, OwnerResponse::Error(actual) if *actual == expected));
}

fn no_plaintext_files(root: &Path, markers: &[&[u8]]) -> TestResult<()> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            no_plaintext_files(&entry.path(), markers)?;
        } else if entry.file_type()?.is_file() {
            no_marker(&fs::read(entry.path())?, markers);
        }
    }
    Ok(())
}

fn agent(root: &Path, request: &DaemonRequest, markers: &[&[u8]]) -> TestResult<DaemonResponse> {
    let mut stream = std::os::unix::net::UnixStream::connect(root.join("runtime/agent.sock"))?;
    stream.set_read_timeout(Some(DEADLINE))?;
    stream.set_write_timeout(Some(DEADLINE))?;
    let bytes = serde_json::to_vec(request)?;
    stream.write_all(&u32::try_from(bytes.len())?.to_be_bytes())?;
    stream.write_all(&bytes)?;
    let mut length = [0; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    assert!(length <= 65_536);
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes)?;
    no_marker(&bytes, markers);
    Ok(serde_json::from_slice(&bytes)?)
}

fn catalog(
    root: &Path,
    session: &SessionCapability,
    expected: &[ItemDescriptor],
    markers: &[&[u8]],
) -> TestResult<()> {
    let response = agent(
        root,
        &DaemonRequest::ListItems {
            session: session.clone(),
        },
        markers,
    )?;
    assert!(matches!(response, DaemonResponse::ItemsListed { items } if items == expected));
    for item in expected {
        let (operation, selected_component, action) = if item.kind == ItemKind::Login {
            (
                UseOperation::Login(LoginUse::Password),
                Some(item.login_components[0].id.clone()),
                "sign_in",
            )
        } else {
            (UseOperation::ApiCredential, None, "api_credential")
        };
        let response = agent(
            root,
            &DaemonRequest::PrepareUse(PrepareUseRequest {
                session: session.clone(),
                item_id: item.item_id.clone(),
                revision: item.revision,
                intent: Intent {
                    action: action.into(),
                    target: TargetOrigin::parse("https://example.com")?,
                },
                operation,
                selected_component,
                ttl_ms: 60_000,
            }),
            markers,
        )?;
        assert!(matches!(
            response,
            DaemonResponse::Rejected {
                code: RefusalCode::Unsupported,
                ..
            }
        ));
    }
    Ok(())
}

#[test]
fn actual_cli_encrypted_lifecycle() -> TestResult<()> {
    let temporary = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()?;
    let root = fs::canonicalize(temporary.path())?;
    let pass = marker(32)?;
    let wrong = marker(32)?;
    let value = marker(65_536)?;
    let replacement = marker(128)?;
    let markers = [&pass[..], &wrong[..], &value[..], &replacement[..]];
    let daemon = Daemon::start(&root)?;
    let DaemonResponse::SessionOpened { session } =
        agent(&root, &DaemonRequest::OpenSession, &markers)?
    else {
        return Err("expected agent session".into());
    };
    catalog(&root, &session, &[], &markers)?;
    assert!(matches!(
        owner(&root, &["init"], &pass, None, &markers)?,
        OwnerResponse::State(VaultStatus::Unlocked)
    ));
    error(
        &owner(&root, &["init"], &pass, None, &markers)?,
        SecretErrorCode::AlreadyInitialized,
    );
    let OwnerResponse::Item(item) = owner(
        &root,
        &["store", "--kind", "password"],
        &pass,
        Some(&value),
        &markers,
    )?
    else {
        return Err("expected item".into());
    };
    let id = item.item_id.as_str();
    assert_eq!(item.revision, 1);
    catalog(&root, &session, std::slice::from_ref(&item), &markers)?;
    error(
        &owner(
            &root,
            &["update", "--item-id", id, "--revision", "0"],
            &pass,
            Some(&replacement),
            &markers,
        )?,
        SecretErrorCode::RevisionMismatch,
    );
    let OwnerResponse::Item(updated) = owner(
        &root,
        &["update", "--item-id", id, "--revision", "1"],
        &pass,
        Some(&replacement),
        &markers,
    )?
    else {
        return Err("expected update".into());
    };
    assert_eq!(updated.revision, 2);
    catalog(&root, &session, std::slice::from_ref(&updated), &markers)?;
    error(
        &owner(
            &root,
            &["remove", "--item-id", id, "--revision", "1"],
            &pass,
            None,
            &markers,
        )?,
        SecretErrorCode::RevisionMismatch,
    );
    lockout_and_restart(&root, &session, &markers, &updated, daemon)
}

fn lockout_and_restart(
    root: &Path,
    session: &SessionCapability,
    markers: &[&[u8]; 4],
    updated: &ItemDescriptor,
    mut daemon: Daemon,
) -> TestResult<()> {
    let [pass, wrong, value, _replacement] = *markers;
    error(
        &owner(root, &["list"], wrong, None, markers)?,
        SecretErrorCode::AuthenticationFailed,
    );
    catalog(root, session, &[], markers)?;
    error(
        &owner(root, &["list"], pass, None, markers)?,
        SecretErrorCode::Locked,
    );
    error(
        &owner(
            root,
            &["store", "--kind", "bearer"],
            pass,
            Some(value),
            markers,
        )?,
        SecretErrorCode::Locked,
    );
    assert!(matches!(
        owner(root, &["unlock"], pass, None, markers)?,
        OwnerResponse::State(VaultStatus::Unlocked)
    ));
    assert!(
        matches!(owner(root, &["list"], pass, None, markers)?, OwnerResponse::Items(items) if items == [updated.clone()])
    );
    assert!(matches!(
        owner(root, &["lock"], pass, None, markers)?,
        OwnerResponse::State(VaultStatus::Locked)
    ));
    catalog(root, session, &[], markers)?;
    assert!(matches!(
        owner(root, &["unlock"], pass, None, markers)?,
        OwnerResponse::State(VaultStatus::Unlocked)
    ));
    no_plaintext_files(root, markers)?;
    no_marker(&daemon.stop()?, markers);
    // Remove all runtime state to prove native durability does not depend on it.
    fs::remove_dir_all(root.join("runtime"))?;
    let daemon = Daemon::start(root)?;
    let DaemonResponse::SessionOpened { session } =
        agent(root, &DaemonRequest::OpenSession, markers)?
    else {
        return Err("expected new agent session".into());
    };
    catalog(root, &session, &[], markers)?;
    error(
        &owner(root, &["list"], pass, None, markers)?,
        SecretErrorCode::Locked,
    );
    assert!(matches!(
        owner(root, &["unlock"], pass, None, markers)?,
        OwnerResponse::State(VaultStatus::Unlocked)
    ));
    assert!(
        matches!(owner(root, &["list"], pass, None, markers)?, OwnerResponse::Items(items) if items == [updated.clone()])
    );
    catalog(root, &session, std::slice::from_ref(updated), markers)?;
    tamper_and_remove(root, &session, markers, updated.item_id.as_str(), daemon)
}

fn tamper_and_remove(
    root: &Path,
    session: &SessionCapability,
    markers: &[&[u8]; 4],
    id: &str,
    mut daemon: Daemon,
) -> TestResult<()> {
    let pass = markers[0];
    let vault = root.join("data/intentkey/native.vault");
    assert_eq!(fs::metadata(&vault)?.mode() & 0o7777, 0o600);
    let original = fs::read(&vault)?;
    let mut tampered = original.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    fs::write(&vault, tampered)?;
    error(
        &owner(root, &["list"], pass, None, markers)?,
        SecretErrorCode::AuthenticationFailed,
    );
    catalog(root, session, &[], markers)?;
    fs::write(&vault, original)?;
    error(
        &owner(root, &["list"], pass, None, markers)?,
        SecretErrorCode::Locked,
    );
    assert!(matches!(
        owner(root, &["unlock"], pass, None, markers)?,
        OwnerResponse::State(VaultStatus::Unlocked)
    ));
    assert!(matches!(
        owner(
            root,
            &["remove", "--item-id", id, "--revision", "2"],
            pass,
            None,
            markers
        )?,
        OwnerResponse::Removed(_)
    ));
    assert!(
        matches!(owner(root, &["list"], pass, None, markers)?, OwnerResponse::Items(items) if items.is_empty())
    );
    catalog(root, session, &[], markers)?;
    let OwnerResponse::Item(generated) = owner(root, &["generate"], pass, None, markers)? else {
        return Err("expected generated item".into());
    };
    catalog(root, session, &[generated], markers)?;
    no_marker(&daemon.stop()?, markers);
    no_plaintext_files(root, markers)?;
    Ok(())
}
