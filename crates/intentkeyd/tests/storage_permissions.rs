//! Real-process checks for private daemon storage and non-destructive path rejection.

use std::{
    error::Error,
    fs,
    io::{BufRead, BufReader},
    os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    path::Path,
    process::{Child, Command, ExitStatus, Stdio},
    sync::mpsc::{self, Receiver},
    thread::JoinHandle,
    time::Duration,
};

use intentkey_core::{DaemonRequest, DaemonResponse, read_wire_value, write_wire_value};
use tokio::{net::UnixStream, time::timeout};

const DEADLINE: Duration = Duration::from_secs(10);
type TestResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

#[derive(Debug, PartialEq, Eq)]
enum Event {
    Ready,
    Stopped,
}

struct Daemon {
    child: Child,
    events: Receiver<Event>,
    output: Option<JoinHandle<TestResult<String>>>,
    _home: tempfile::TempDir,
}

impl Daemon {
    fn start(socket: &Path) -> TestResult<Self> {
        // Isolate durable storage even for rejected socket paths and concurrent daemons.
        let home = private_directory()?;
        let home_path = fs::canonicalize(home.path())?;
        // Inherit the caller's normal umask. Never mutate the Rust test process umask.
        let mut child = Command::new(env!("CARGO_BIN_EXE_intentkeyd"))
            .arg("--socket")
            .arg(socket)
            .env("HOME", &home_path)
            .env("XDG_DATA_HOME", home_path.join("data"))
            .env("XDG_RUNTIME_DIR", home_path.join("runtime"))
            .env("RUST_LOG", "intentkeyd=info")
            .env("NO_COLOR", "1")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;
        let stderr = child.stderr.take().ok_or("missing daemon stderr")?;
        let (sender, events) = mpsc::channel();
        let output = std::thread::spawn(move || -> TestResult<String> {
            let mut output = String::new();
            for line in BufReader::new(stderr).lines() {
                let line = line?;
                if line.contains("intentkeyd.ready") {
                    sender.send(Event::Ready)?;
                }
                output.push_str(&line);
                output.push('\n');
            }
            sender.send(Event::Stopped)?;
            Ok(output)
        });
        Ok(Self {
            child,
            events,
            output: Some(output),
            _home: home,
        })
    }

    async fn ready(&mut self, socket: &Path) -> TestResult<()> {
        let event = self.events.recv_timeout(DEADLINE)?;
        if event != Event::Ready {
            let output = self
                .output
                .take()
                .ok_or("missing output reader")?
                .join()
                .map_err(|_| "output reader panicked")??;
            return Err(format!("daemon failed before readiness: {output}").into());
        }
        assert!(
            self.child.try_wait()?.is_none(),
            "daemon exited after readiness"
        );
        // Exercise the real protocol, also ensuring the shutdown select is active.
        timeout(DEADLINE, async {
            let mut stream = UnixStream::connect(socket).await?;
            write_wire_value(&mut stream, &DaemonRequest::OpenSession).await?;
            let response: DaemonResponse = read_wire_value(&mut stream).await?;
            assert!(matches!(response, DaemonResponse::SessionOpened { .. }));
            Ok::<(), Box<dyn Error + Send + Sync>>(())
        })
        .await??;
        Ok(())
    }

    fn exited(&mut self) -> TestResult<(ExitStatus, String)> {
        assert_eq!(self.events.recv_timeout(DEADLINE)?, Event::Stopped);
        let status = self.child.wait()?;
        let output = self
            .output
            .take()
            .ok_or("output already joined")?
            .join()
            .map_err(|_| "daemon output reader panicked")??;
        Ok((status, output))
    }

    fn stop(&mut self) -> TestResult<()> {
        let signal = Command::new("kill")
            .args(["-INT", &self.child.id().to_string()])
            .status()?;
        assert!(signal.success());
        let (status, output) = self.exited()?;
        assert!(status.success(), "{status}: {output}");
        Ok(())
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let status = self.child.try_wait();
        assert!(status.is_ok(), "could not inspect daemon exit status");
        if status.is_ok_and(|status| status.is_none()) {
            assert!(self.child.kill().is_ok(), "could not kill daemon");
        }
        assert!(self.child.wait().is_ok(), "could not reap daemon");
        if let Some(output) = self.output.take() {
            assert!(output.join().is_ok_and(|result| result.is_ok()));
        }
    }
}

fn private_directory() -> TestResult<tempfile::TempDir> {
    Ok(tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()?)
}

fn mode(path: &Path) -> TestResult<u32> {
    Ok(fs::symlink_metadata(path)?.mode() & 0o777)
}

fn private_storage(parent: &Path) -> TestResult<()> {
    assert_eq!(mode(parent)?, 0o700, "directory mode");
    for name in ["state.sqlite3", "state.sqlite3.lock", "intentkeyd.sock"] {
        assert_eq!(mode(&parent.join(name))?, 0o600, "{name} mode");
        assert_eq!(
            fs::symlink_metadata(parent.join(name))?.uid(),
            fs::metadata(parent)?.uid()
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn newly_created_storage_is_private_and_restarts() -> TestResult<()> {
    let root = private_directory()?;
    let outer = root.path().join("new-private-storage");
    let parent = outer.join("nested");
    let socket = parent.join("intentkeyd.sock");
    let mut daemon = Daemon::start(&socket)?;
    daemon.ready(&socket).await?;
    private_storage(&parent)?;
    assert_eq!(mode(&outer)?, 0o700);
    assert_eq!(
        fs::metadata(&parent)?.uid(),
        fs::metadata(root.path())?.uid()
    );
    let database_inode = fs::metadata(parent.join("state.sqlite3"))?.ino();
    daemon.stop()?;
    assert!(!socket.try_exists()?);

    let mut restarted = Daemon::start(&socket)?;
    restarted.ready(&socket).await?;
    private_storage(&parent)?;
    assert_eq!(
        fs::metadata(parent.join("state.sqlite3"))?.ino(),
        database_inode
    );
    restarted.stop()?;
    assert!(!socket.try_exists()?);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn first_database_in_existing_private_parent_is_private() -> TestResult<()> {
    let root = private_directory()?;
    let socket = root.path().join("intentkeyd.sock");
    let mut daemon = Daemon::start(&socket)?;
    daemon.ready(&socket).await?;
    private_storage(root.path())?;
    daemon.stop()?;
    Ok(())
}

#[test]
fn public_existing_parent_is_rejected_without_chmod() -> TestResult<()> {
    let root = tempfile::tempdir()?;
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755))?;
    let socket = root.path().join("intentkeyd.sock");
    let mut daemon = Daemon::start(&socket)?;
    let (status, output) = daemon.exited()?;
    assert!(!status.success(), "{output}");
    assert_eq!(mode(root.path())?, 0o755);
    assert!(!socket.try_exists()?);
    assert!(!root.path().join("state.sqlite3").try_exists()?);
    Ok(())
}

#[test]
fn symlink_targets_are_rejected_without_modifying_referents() -> TestResult<()> {
    for name in [
        "parent",
        "intentkeyd.sock",
        "state.sqlite3",
        "state.sqlite3.lock",
        "state.sqlite3-journal",
        "state.sqlite3-wal",
        "state.sqlite3-shm",
    ] {
        let root = private_directory()?;
        let target = root.path().join("user-data");
        let original = b"unrelated user file\n";
        let parent = root.path().join("parent");
        if name == "parent" {
            fs::create_dir(&target)?;
            fs::set_permissions(&target, fs::Permissions::from_mode(0o700))?;
            symlink(&target, &parent)?;
        } else {
            fs::create_dir(&parent)?;
            fs::set_permissions(&parent, fs::Permissions::from_mode(0o700))?;
            fs::write(&target, original)?;
            fs::set_permissions(&target, fs::Permissions::from_mode(0o644))?;
            symlink(&target, parent.join(name))?;
        }
        let before = fs::metadata(&target)?;
        let mut daemon = Daemon::start(&parent.join("intentkeyd.sock"))?;
        let (status, output) = daemon.exited()?;
        assert!(!status.success(), "{name}: {output}");
        let link = if name == "parent" {
            parent
        } else {
            parent.join(name)
        };
        assert!(fs::symlink_metadata(link)?.file_type().is_symlink());
        let after = fs::metadata(&target)?;
        assert_eq!(before.mode(), after.mode(), "{name}");
        assert_eq!(before.ino(), after.ino(), "{name}");
        if name != "parent" {
            assert_eq!(fs::read(&target)?, original, "{name}");
        }
    }
    Ok(())
}

#[test]
fn dangling_storage_symlinks_are_not_followed() -> TestResult<()> {
    for name in ["intentkeyd.sock", "state.sqlite3", "state.sqlite3.lock"] {
        let root = private_directory()?;
        let target = root.path().join("missing-user-file");
        let link = root.path().join(name);
        symlink(&target, &link)?;
        let mut daemon = Daemon::start(&root.path().join("intentkeyd.sock"))?;
        let (status, output) = daemon.exited()?;
        assert!(!status.success(), "{name}: {output}");
        assert!(!target.try_exists()?);
        assert!(fs::symlink_metadata(link)?.file_type().is_symlink());
    }
    Ok(())
}

#[test]
fn public_or_hardlinked_storage_files_are_rejected_unchanged() -> TestResult<()> {
    for name in ["state.sqlite3", "state.sqlite3.lock"] {
        for hardlinked in [false, true] {
            let root = private_directory()?;
            let path = root.path().join(name);
            fs::write(&path, b"user file")?;
            if hardlinked {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
                fs::hard_link(&path, root.path().join("user-file-alias"))?;
            } else {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
            }
            let before = fs::metadata(&path)?;
            let mut daemon = Daemon::start(&root.path().join("intentkeyd.sock"))?;
            let (status, output) = daemon.exited()?;
            assert!(!status.success(), "{name}: {output}");
            let after = fs::metadata(&path)?;
            assert_eq!(after.mode(), before.mode());
            assert_eq!(after.ino(), before.ino());
            assert_eq!(after.nlink(), before.nlink());
            assert_eq!(fs::read(path)?, b"user file");
        }
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_does_not_unlink_a_replacement_user_file() -> TestResult<()> {
    let root = private_directory()?;
    let socket = root.path().join("intentkeyd.sock");
    let mut daemon = Daemon::start(&socket)?;
    daemon.ready(&socket).await?;
    fs::remove_file(&socket)?;
    fs::write(&socket, b"replacement user file")?;
    daemon.stop()?;
    assert_eq!(fs::read(socket)?, b"replacement user file");
    Ok(())
}

#[test]
fn user_file_at_socket_path_is_never_unlinked() -> TestResult<()> {
    let root = private_directory()?;
    let socket = root.path().join("intentkeyd.sock");
    fs::write(&socket, b"user file")?;
    let before = fs::metadata(&socket)?;
    let mut daemon = Daemon::start(&socket)?;
    let (status, output) = daemon.exited()?;
    assert!(!status.success(), "{output}");
    assert_eq!(fs::read(&socket)?, b"user file");
    assert_eq!(fs::metadata(&socket)?.ino(), before.ino());
    assert_eq!(fs::metadata(&socket)?.mode(), before.mode());
    Ok(())
}
