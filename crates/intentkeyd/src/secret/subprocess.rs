//! Fixed-command subprocess boundary. No vendor output is printable or serializable.
use std::{
    fmt, fs,
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::Command,
    signal::unix::{Signal, SignalKind, signal},
    sync::oneshot,
    task::JoinHandle,
    time::timeout,
};
use zeroize::Zeroizing;

pub(super) const DEADLINE: Duration = Duration::from_secs(10);
pub(super) const MAX_STDOUT: usize = 256 * 1024;
pub(super) const MAX_STDERR: usize = 256 * 1024;

/// Validated vendor identifier, never a value, label, or command-line fragment.
#[derive(Clone)]
pub(super) struct Identifier(String);
impl Identifier {
    pub(super) fn new(value: &str) -> Result<Self, RunnerError> {
        if value.is_empty()
            || value.len() > 256
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
            || value.starts_with('-')
        {
            return Err(RunnerError::InvalidConfiguration);
        }
        Ok(Self(value.to_owned()))
    }
    pub(super) fn as_str(&self) -> &str {
        &self.0
    }
}

/// Only read-only, selected-scope commands are representable.
pub(super) enum ProviderCommand {
    ProtonVaultList,
    ProtonList {
        share_id: Identifier,
    },
    ProtonField {
        share_id: Identifier,
        item_id: Identifier,
        field: Identifier,
    },
    OnePasswordVaultList,
    OnePasswordList {
        vault_id: Identifier,
    },
    OnePasswordGet {
        vault_id: Identifier,
        item_id: Identifier,
    },
    OnePasswordRead {
        vault_id: Identifier,
        item_id: Identifier,
        field: Identifier,
    },
}

/// Validated configuration supplied by the authenticated owner, not the agent.
#[derive(Clone)]
pub(super) struct SubprocessConfig {
    executable: PathBuf,
    home: PathBuf,
    session_dir: PathBuf,
}
impl SubprocessConfig {
    pub(super) fn new(
        executable: PathBuf,
        home: PathBuf,
        session_dir: PathBuf,
    ) -> Result<Self, RunnerError> {
        validate_path(&executable, false)?;
        validate_path(&home, true)?;
        validate_path(&session_dir, true)?;
        Ok(Self {
            executable,
            home,
            session_dir,
        })
    }
}

fn validate_path(path: &Path, directory: bool) -> Result<(), RunnerError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
    {
        return Err(RunnerError::InvalidConfiguration);
    }
    let uid = nix::unistd::Uid::effective().as_raw();
    // Reject symlinks and untrusted writable ancestors. Root-owned sticky /tmp
    // is allowed; the actual approved session/HOME must still be owner-only.
    for ancestor in path.ancestors() {
        let metadata =
            fs::symlink_metadata(ancestor).map_err(|_| RunnerError::InvalidConfiguration)?;
        if metadata.file_type().is_symlink()
            || (metadata.uid() != uid && metadata.uid() != 0)
            || (metadata.mode() & 0o022 != 0
                && !(metadata.is_dir() && metadata.mode() & 0o1000 != 0))
        {
            return Err(RunnerError::InvalidConfiguration);
        }
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| RunnerError::InvalidConfiguration)?;
    if directory {
        if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o077 != 0 {
            return Err(RunnerError::InvalidConfiguration);
        }
    } else if !metadata.is_file() || metadata.mode() & 0o111 == 0 {
        return Err(RunnerError::InvalidConfiguration);
    }
    Ok(())
}

/// Code-only errors: no source error, argv, stdout, stderr, or path is retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RunnerError {
    InvalidConfiguration,
    Spawn,
    Io,
    NonZero,
    Timeout,
    TooLarge,
    Cancelled,
}
impl fmt::Display for RunnerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfiguration => "InvalidConfiguration",
            Self::Spawn => "Spawn",
            Self::Io => "Io",
            Self::NonZero => "NonZero",
            Self::Timeout => "Timeout",
            Self::TooLarge => "TooLarge",
            Self::Cancelled => "Cancelled",
        })
    }
}
impl std::error::Error for RunnerError {}

/// Secret-bearing bytes. Deliberately no Debug, Display, Clone or serialization.
/// The wrapper prevents Zeroizing<Vec<u8>>'s own Debug implementation leaking data.
pub(super) struct SecretOutput(Zeroizing<Vec<u8>>);
impl SecretOutput {
    pub(super) fn as_slice(&self) -> &[u8] {
        &self.0
    }
}
impl std::ops::Deref for SecretOutput {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

/// Production constructor has no caller-controlled timeout, limits, or environment.
pub(super) struct SubprocessRunner {
    config: SubprocessConfig,
    token: Zeroizing<Vec<u8>>,
}
impl SubprocessRunner {
    pub(super) fn new(config: SubprocessConfig) -> Self {
        Self {
            config,
            token: Zeroizing::new(Vec::new()),
        }
    }
    pub(super) fn with_service_account(
        mut self,
        token: &[u8],
    ) -> Result<Self, intentkey_core::owner::SecretErrorCode> {
        if token.len() > 8192 || !token.iter().all(u8::is_ascii_graphic) {
            return Err(intentkey_core::owner::SecretErrorCode::InvalidInput);
        }
        self.token = Zeroizing::new(token.to_vec());
        Ok(self)
    }
    pub(super) async fn run(&self, command: ProviderCommand) -> Result<SecretOutput, RunnerError> {
        let mut running = self.start(command)?;
        // Dropping this future closes the cancellation sender. The supervisor
        // retains ownership until real group termination and child reaping finish.
        (&mut running.task)
            .await
            .map_err(|_| RunnerError::Io)?
            .map(SecretOutput)
    }
    fn start(&self, command: ProviderCommand) -> Result<Running, RunnerError> {
        let mut command = self.command(command)?;
        // Subscribe before spawn so a fast exit cannot be missed. The owned child
        // is not polled/reaped until its process group has been terminated.
        let exited = signal(SignalKind::child()).map_err(|_| RunnerError::Io)?;
        let child = command.spawn().map_err(|_| RunnerError::Spawn)?;
        let group = ProcessGroup::new(child)?;
        let (cancel, cancelled) = oneshot::channel();
        let task = tokio::spawn(supervise(group, cancelled, exited));
        Ok(Running {
            _cancel: cancel,
            task,
        })
    }
    fn command(&self, operation: ProviderCommand) -> Result<Command, RunnerError> {
        // Revalidate each time: a persisted connection is not a lasting filesystem grant.
        validate_path(&self.config.executable, false)?;
        validate_path(&self.config.home, true)?;
        validate_path(&self.config.session_dir, true)?;
        let mut command = Command::new(&self.config.executable);
        command
            .kill_on_drop(true)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env_clear()
            .env("HOME", &self.config.home)
            .env("XDG_CONFIG_HOME", &self.config.session_dir)
            .env("XDG_DATA_HOME", &self.config.session_dir)
            .env("XDG_CACHE_HOME", &self.config.session_dir)
            .env("XDG_STATE_HOME", &self.config.session_dir)
            .env("XDG_RUNTIME_DIR", &self.config.session_dir)
            .env("TMPDIR", &self.config.session_dir)
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .current_dir(&self.config.session_dir)
            .process_group(0);
        if !self.token.is_empty() {
            use std::os::unix::ffi::OsStrExt;
            command.env(
                "OP_SERVICE_ACCOUNT_TOKEN",
                std::ffi::OsStr::from_bytes(&self.token),
            );
        }
        if matches!(
            &operation,
            ProviderCommand::ProtonVaultList
                | ProviderCommand::ProtonList { .. }
                | ProviderCommand::ProtonField { .. }
        ) {
            // Pinned upstream fs session workflow: no keychain or inherited auth state.
            command
                .env("PROTON_PASS_SESSION_DIR", &self.config.session_dir)
                .env("PROTON_PASS_KEY_PROVIDER", "fs");
        }
        self.arguments(&mut command, operation);
        Ok(command)
    }
    fn arguments(&self, command: &mut Command, operation: ProviderCommand) {
        match operation {
            ProviderCommand::ProtonVaultList => {
                command.args(["vault", "list", "--output", "json"]);
            }
            ProviderCommand::ProtonList { share_id } => {
                command.args([
                    "item",
                    "list",
                    "--share-id",
                    share_id.as_str(),
                    "--output",
                    "json",
                ]);
            }
            ProviderCommand::ProtonField {
                share_id,
                item_id,
                field,
            } => {
                command.args([
                    "item",
                    "view",
                    "--share-id",
                    share_id.as_str(),
                    "--item-id",
                    item_id.as_str(),
                    "--field",
                    field.as_str(),
                    "--output",
                    "json",
                ]);
            }
            ProviderCommand::OnePasswordVaultList => {
                command
                    .args([
                        "vault",
                        "list",
                        "--format",
                        "json",
                        "--cache=false",
                        "--config",
                    ])
                    .arg(&self.config.session_dir);
            }
            ProviderCommand::OnePasswordList { vault_id } => {
                command
                    .args([
                        "item",
                        "list",
                        "--vault",
                        vault_id.as_str(),
                        "--categories",
                        "Login",
                        "--format",
                        "json",
                        "--cache=false",
                        "--config",
                    ])
                    .arg(&self.config.session_dir);
            }
            ProviderCommand::OnePasswordGet { vault_id, item_id } => {
                command
                    .args([
                        "item",
                        "get",
                        item_id.as_str(),
                        "--vault",
                        vault_id.as_str(),
                        "--format",
                        "json",
                        "--cache=false",
                        "--config",
                    ])
                    .arg(&self.config.session_dir);
            }
            ProviderCommand::OnePasswordRead {
                vault_id,
                item_id,
                field,
            } => {
                // All three segments are validated opaque IDs: no secret value,
                // arbitrary URI, section traversal or shell syntax is accepted.
                let reference = format!(
                    "op://{}/{}/{}",
                    vault_id.as_str(),
                    item_id.as_str(),
                    field.as_str()
                );
                command
                    .arg("read")
                    .arg(reference)
                    .args(["--no-newline", "--cache=false", "--config"])
                    .arg(&self.config.session_dir);
            }
        }
    }
}
struct Running {
    _cancel: oneshot::Sender<()>,
    task: JoinHandle<Result<Zeroizing<Vec<u8>>, RunnerError>>,
}

struct ProcessGroup {
    child: tokio::process::Child,
    pid: i32,
    armed: bool,
}
impl ProcessGroup {
    fn new(child: tokio::process::Child) -> Result<Self, RunnerError> {
        let pid =
            i32::try_from(child.id().ok_or(RunnerError::Spawn)?).map_err(|_| RunnerError::Spawn)?;
        Ok(Self {
            child,
            pid,
            armed: true,
        })
    }
    fn kill(&self) -> Result<(), RunnerError> {
        // SAFETY: the child is a dedicated group leader. It is not reaped until
        // after this signal; waitid(WNOWAIT) prevents PID/group-ID reuse races.
        if unsafe { libc::kill(-self.pid, libc::SIGKILL) } == -1 {
            let errno = std::io::Error::last_os_error().raw_os_error();
            if errno == Some(libc::ESRCH) {
                return Ok(());
            }
            // Darwin returns EPERM (not ESRCH) for a group containing only
            // zombies. Confirm our leader has exited without reaping it.
            if cfg!(target_os = "macos") && errno == Some(libc::EPERM) && exit_observed(self.pid)? {
                return Ok(());
            }
            return Err(RunnerError::Io);
        }
        Ok(())
    }
}
impl Drop for ProcessGroup {
    fn drop(&mut self) {
        // Runtime shutdown fallback: signal before Tokio drops/reaps the child.
        // Normal completion and caller cancellation always use the awaited path.
        if self.armed && self.kill().is_err() {
            tracing::error!(code = "ProviderCleanupFailed");
        }
    }
}

async fn supervise(
    mut group: ProcessGroup,
    mut cancelled: oneshot::Receiver<()>,
    exited: Signal,
) -> Result<Zeroizing<Vec<u8>>, RunnerError> {
    let work = async {
        let stdout = group.child.stdout.take().ok_or(RunnerError::Io)?;
        let stderr = group.child.stderr.take().ok_or(RunnerError::Io)?;
        let (stdout, _, ()) = tokio::try_join!(
            read_bounded(stdout, MAX_STDOUT),
            read_bounded(stderr, MAX_STDERR),
            observe_exit(group.pid, exited)
        )?;
        Ok(stdout)
    };
    let result = tokio::select! {
        biased;
        _ = &mut cancelled => Err(RunnerError::Cancelled),
        result = timeout(DEADLINE, work) => result.unwrap_or(Err(RunnerError::Timeout)),
    };
    // WNOWAIT keeps the group ID reserved, including after a successful exit.
    // Signal all helpers BEFORE the sole reaping wait; never kill a recycled PID.
    let killed = group.kill();
    if killed.is_err() && group.child.start_kill().is_err() {
        tracing::error!(code = "ProviderCleanupFailed");
    }
    group.armed = false;
    let waited = group.child.wait().await.map_err(|_| RunnerError::Io);
    killed?;
    let status = waited?;
    let output = result?;
    if !status.success() {
        return Err(RunnerError::NonZero);
    }
    Ok(output)
}

async fn observe_exit(pid: i32, mut exited: Signal) -> Result<(), RunnerError> {
    loop {
        if exit_observed(pid)? {
            return Ok(());
        }
        exited.recv().await.ok_or(RunnerError::Io)?;
    }
}

fn exit_observed(pid: i32) -> Result<bool, RunnerError> {
    loop {
        let mut information = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
        // SAFETY: information is writable and pid is our unreaped direct child.
        // WNOHANG is a single nonblocking probe, then we await SIGCHLD; this is
        // event-driven, not a polling timer or a blocking runtime thread.
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                pid.cast_unsigned(),
                information.as_mut_ptr(),
                libc::WEXITED | libc::WNOWAIT | libc::WNOHANG,
            )
        };
        if result == -1 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(RunnerError::Io);
        }
        // SAFETY: waitid succeeded; storage was zeroed for the no-event case.
        let information = unsafe { information.assume_init() };
        // SAFETY: successful waitid initialized the child identity fields.
        return Ok((unsafe { information.si_pid() }) == pid);
    }
}

async fn read_bounded<R: AsyncRead + Unpin>(
    mut reader: R,
    limit: usize,
) -> Result<Zeroizing<Vec<u8>>, RunnerError> {
    // Allocate the fixed maximum once: no realloc leaves plaintext in freed heaps.
    let mut output = Zeroizing::new(vec![0; limit]);
    let mut length = 0;
    loop {
        if length == limit {
            let mut extra = Zeroizing::new([0u8; 1]);
            if reader
                .read(&mut extra[..])
                .await
                .map_err(|_| RunnerError::Io)?
                != 0
            {
                return Err(RunnerError::TooLarge);
            }
            return Ok(output);
        }
        let count = reader
            .read(&mut output[length..])
            .await
            .map_err(|_| RunnerError::Io)?;
        if count == 0 {
            output.truncate(length);
            return Ok(output);
        }
        length += count;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const FIXTURE: &str = r#"
use std::{env, fs, io::{Read, Write}, path::PathBuf, os::unix::net::UnixStream, process::{self, Command}};
fn main() {
 let home = std::path::PathBuf::from(env::var_os("HOME").unwrap());
 let mode = fs::read_to_string(home.join("mode")).unwrap();
 if env::args().nth(1).as_deref() == Some("worker") {
   let mut signal = UnixStream::connect(home.join("ready.sock")).unwrap();
   signal.write_all(&process::id().to_be_bytes()).unwrap();
   loop { std::thread::park(); }
 }
 match mode.as_str() {
  "hang" | "overflow-hang" | "stderr-overflow-hang" => {
   let mut signal = UnixStream::connect(home.join("ready.sock")).unwrap();
   signal.write_all(&process::id().to_be_bytes()).unwrap();
   let mut worker = Command::new(env::current_exe().unwrap()).arg("worker").spawn().unwrap();
   if mode != "hang" {
     let mut go = [0];
     signal.read_exact(&mut go).unwrap();
     let block = vec![b'x'; 256 * 1024 + 1];
     if mode == "overflow-hang" { std::io::stdout().write_all(&block).unwrap(); }
     else { std::io::stderr().write_all(&block).unwrap(); }
   }
   worker.wait().unwrap();
  }
  "nonzero" => { eprintln!("fixture-{}", process::id()); process::exit(7); }
  "oversize" => { let block = vec![b'x'; 8192]; for _ in 0..2048 { if std::io::stdout().write_all(&block).is_err() { return; } } }
  "stderr-oversize" => { let block = vec![b'x'; 8192]; for _ in 0..2048 { if std::io::stderr().write_all(&block).is_err() { return; } } }
  "stdout-boundary" => { std::io::stdout().write_all(&vec![b'x'; 256 * 1024]).unwrap(); }
  "stderr-boundary" => { std::io::stderr().write_all(&vec![b'x'; 256 * 1024]).unwrap(); }
  "stdout-over-boundary" => { std::io::stdout().write_all(&vec![b'x'; 256 * 1024 + 1]).unwrap(); }
  "stderr-over-boundary" => { std::io::stderr().write_all(&vec![b'x'; 256 * 1024 + 1]).unwrap(); }
  "command" => {
   let expected = fs::read_to_string(home.join("argv")).unwrap();
   assert!(env::args().skip(1).collect::<Vec<_>>() == expected.lines().map(str::to_owned).collect::<Vec<_>>());
   let mut keys = env::vars().map(|(key, _)| key).collect::<Vec<_>>();
   keys.sort();
   let mut allowed = vec!["HOME", "LANG", "LC_ALL", "TMPDIR", "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_RUNTIME_DIR", "XDG_STATE_HOME"];
   if expected.lines().any(|arg| arg == "--output") {
     allowed.extend(["PROTON_PASS_KEY_PROVIDER", "PROTON_PASS_SESSION_DIR"]);
     assert!(env::var("PROTON_PASS_KEY_PROVIDER").unwrap() == "fs");
     assert!(PathBuf::from(env::var_os("PROTON_PASS_SESSION_DIR").unwrap()) == home);
   }
   allowed.sort();
   assert!(keys == allowed);
   assert!(env::current_dir().unwrap() == home);
   let mut input = Vec::new();
   std::io::stdin().read_to_end(&mut input).unwrap();
   assert!(input.is_empty());
  }
  "malformed" => { std::io::stdout().write_all(b"\xffnot-json").unwrap(); }
  "eof" => {}
  "success" => { let mut input=Vec::new();std::io::stdin().read_to_end(&mut input).unwrap();assert!(input.is_empty()); print!("fixture-{}", process::id()); }
  _ => process::exit(9),
 }
}
"#;
    fn fixture() -> Result<PathBuf, Box<dyn std::error::Error>> {
        static BINARY: std::sync::OnceLock<Result<PathBuf, String>> = std::sync::OnceLock::new();
        BINARY
            .get_or_init(|| {
                let directory = tempfile::tempdir().map_err(|e| e.to_string())?.keep();
                let source = directory.join("fixture.rs");
                std::fs::write(&source, FIXTURE).map_err(|e| e.to_string())?;
                let executable = directory.join("fixture");
                let status = std::process::Command::new("rustc")
                    .arg("--edition=2024")
                    .arg(source)
                    .arg("-o")
                    .arg(&executable)
                    .status()
                    .map_err(|e| e.to_string())?;
                if !status.success() {
                    return Err("fixture compilation failed".to_owned());
                }
                executable.canonicalize().map_err(|e| e.to_string())
            })
            .clone()
            .map_err(Into::into)
    }
    fn setup(
        mode: &str,
    ) -> Result<(tempfile::TempDir, SubprocessConfig), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        std::fs::write(directory.path().join("mode"), mode)?;
        let path = directory.path().canonicalize()?;
        let config =
            SubprocessConfig::new(fixture()?, path.clone(), path).map_err(|_| "configuration")?;
        Ok((directory, config))
    }
    #[tokio::test]
    async fn cancellation_kills_and_reaps_before_return() -> Result<(), Box<dyn std::error::Error>>
    {
        let (directory, config) = setup("hang")?;
        let listener = tokio::net::UnixListener::bind(directory.path().join("ready.sock"))?;
        let runner = SubprocessRunner::new(config);
        let Running {
            _cancel: cancel,
            task,
        } = runner.start(ProviderCommand::ProtonList {
            share_id: Identifier::new("share")?,
        })?;
        let (mut leader, _) = timeout(Duration::from_secs(20), listener.accept()).await??;
        let pid = leader.read_u32().await?;
        let (mut descendant, _) = timeout(Duration::from_secs(20), listener.accept()).await??;
        let _descendant_pid = descendant.read_u32().await?;
        drop(cancel);
        assert!(matches!(
            timeout(Duration::from_secs(20), task).await??,
            Err(RunnerError::Cancelled)
        ));
        // SAFETY: kill with signal 0 only checks this fixture PID.
        let reaped = unsafe { libc::kill(i32::try_from(pid)?, 0) } == -1;
        // Clean up even on the intentionally failing pre-fix assertion.
        if !reaped {
            assert_eq!(
                // SAFETY: the fixture created this dedicated process group.
                unsafe { libc::kill(-i32::try_from(pid)?, libc::SIGKILL) },
                0
            );
        }
        assert!(reaped, "cancel must kill and reap the fixture leader");
        assert_eq!(
            timeout(Duration::from_secs(5), descendant.read_u8())
                .await?
                .err()
                .map(|e| e.kind()),
            Some(std::io::ErrorKind::UnexpectedEof)
        );
        Ok(())
    }

    #[tokio::test]
    async fn process_limits_exit_and_timeout() -> Result<(), Box<dyn std::error::Error>> {
        for (mode, expected) in [
            ("nonzero", Some(RunnerError::NonZero)),
            ("oversize", Some(RunnerError::TooLarge)),
            ("stderr-oversize", Some(RunnerError::TooLarge)),
            ("eof", None),
            ("success", None),
        ] {
            let (_directory, config) = setup(mode)?;
            let result = SubprocessRunner::new(config)
                .run(ProviderCommand::ProtonList {
                    share_id: Identifier::new("share")?,
                })
                .await;
            assert_eq!(result.err(), expected);
        }
        let (directory, config) = setup("hang")?;
        let listener = tokio::net::UnixListener::bind(directory.path().join("ready.sock"))?;
        let runner = SubprocessRunner::new(config);
        let running = runner.start(ProviderCommand::ProtonList {
            share_id: Identifier::new("share")?,
        })?;
        let (mut leader, _) = timeout(Duration::from_secs(20), listener.accept()).await??;
        let pid = leader.read_u32().await?;
        let (mut descendant, _) = timeout(Duration::from_secs(20), listener.accept()).await??;
        descendant.read_u32().await?;
        assert!(matches!(
            timeout(Duration::from_secs(20), running.task).await??,
            Err(RunnerError::Timeout)
        ));
        // SAFETY: signal zero checks only the fixture PID after cleanup completion.
        assert_eq!(unsafe { libc::kill(i32::try_from(pid)?, 0) }, -1);
        assert_eq!(
            timeout(Duration::from_secs(5), descendant.read_u8())
                .await?
                .err()
                .map(|e| e.kind()),
            Some(std::io::ErrorKind::UnexpectedEof)
        );
        Ok(())
    }

    #[tokio::test]
    async fn overflow_kills_and_reaps_instead_of_waiting_for_timeout()
    -> Result<(), Box<dyn std::error::Error>> {
        for mode in ["overflow-hang", "stderr-overflow-hang"] {
            let (directory, config) = setup(mode)?;
            let listener = tokio::net::UnixListener::bind(directory.path().join("ready.sock"))?;
            let runner = SubprocessRunner::new(config);
            let running = runner.start(ProviderCommand::ProtonList {
                share_id: Identifier::new("share")?,
            })?;
            let (mut leader, _) = timeout(Duration::from_secs(20), listener.accept()).await??;
            let pid = timeout(Duration::from_secs(5), leader.read_u32()).await??;
            let (mut worker, _) = timeout(Duration::from_secs(20), listener.accept()).await??;
            timeout(Duration::from_secs(5), worker.read_u32()).await??;
            // Both cleanup observers are connected before triggering overflow.
            tokio::io::AsyncWriteExt::write_all(&mut leader, &[1]).await?;
            let result = timeout(Duration::from_secs(20), running.task).await??;
            assert!(matches!(result, Err(RunnerError::TooLarge)));
            // SAFETY: signal zero checks the fixture leader after awaited reaping.
            assert_eq!(unsafe { libc::kill(i32::try_from(pid)?, 0) }, -1);
            assert_eq!(
                timeout(Duration::from_secs(5), worker.read_u8())
                    .await?
                    .err()
                    .map(|e| e.kind()),
                Some(std::io::ErrorKind::UnexpectedEof)
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn exact_256k_boundaries() -> Result<(), Box<dyn std::error::Error>> {
        for (mode, expected) in [
            ("stdout-boundary", None),
            ("stderr-boundary", None),
            ("stdout-over-boundary", Some(RunnerError::TooLarge)),
            ("stderr-over-boundary", Some(RunnerError::TooLarge)),
        ] {
            let (_directory, config) = setup(mode)?;
            let result = SubprocessRunner::new(config)
                .run(ProviderCommand::ProtonList {
                    share_id: Identifier::new("share")?,
                })
                .await;
            assert_eq!(result.err(), expected, "{mode}");
        }
        Ok(())
    }

    #[tokio::test]
    async fn malformed_stdout_remains_private_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let (_directory, config) = setup("malformed")?;
        let output = SubprocessRunner::new(config)
            .run(ProviderCommand::ProtonList {
                share_id: Identifier::new("share")?,
            })
            .await?;
        assert!(output.as_slice().eq(b"\xffnot-json"));
        Ok(())
    }

    #[tokio::test]
    async fn fixed_commands_and_clean_environment_reach_real_child()
    -> Result<(), Box<dyn std::error::Error>> {
        let id = || Identifier::new("fixture");
        let cases = [
            (
                ProviderCommand::ProtonVaultList,
                vec!["vault", "list", "--output", "json"],
            ),
            (
                ProviderCommand::ProtonList { share_id: id()? },
                vec!["item", "list", "--share-id", "fixture", "--output", "json"],
            ),
            (
                ProviderCommand::ProtonField {
                    share_id: id()?,
                    item_id: id()?,
                    field: id()?,
                },
                vec![
                    "item",
                    "view",
                    "--share-id",
                    "fixture",
                    "--item-id",
                    "fixture",
                    "--field",
                    "fixture",
                    "--output",
                    "json",
                ],
            ),
            (
                ProviderCommand::OnePasswordVaultList,
                vec![
                    "vault",
                    "list",
                    "--format",
                    "json",
                    "--cache=false",
                    "--config",
                ],
            ),
            (
                ProviderCommand::OnePasswordList { vault_id: id()? },
                vec![
                    "item",
                    "list",
                    "--vault",
                    "fixture",
                    "--categories",
                    "Login",
                    "--format",
                    "json",
                    "--cache=false",
                    "--config",
                ],
            ),
            (
                ProviderCommand::OnePasswordRead {
                    vault_id: id()?,
                    item_id: id()?,
                    field: id()?,
                },
                vec![
                    "read",
                    "op://fixture/fixture/fixture",
                    "--no-newline",
                    "--cache=false",
                    "--config",
                ],
            ),
        ];
        for (command, mut args) in cases {
            let (directory, config) = setup("command")?;
            let session = config.session_dir.to_str().ok_or("fixture path")?;
            if args.last() == Some(&"--config") {
                args.push(session);
            }
            fs::write(directory.path().join("argv"), args.join("\n"))?;
            assert!(SubprocessRunner::new(config).run(command).await.is_ok());
        }
        Ok(())
    }

    #[tokio::test]
    async fn rejects_public_session_directory_before_spawn()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o755))?;
        assert!(
            SubprocessConfig::new(
                PathBuf::from("/bin/sh"),
                directory.path().to_owned(),
                directory.path().to_owned()
            )
            .is_err()
        );
        Ok(())
    }
}
