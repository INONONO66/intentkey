//! `intentkeyd` privileged local daemon entry point.

use std::{
    fs::{File, Metadata},
    io,
    os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use clap::Parser;
use color_eyre::eyre::{Context, Result, eyre};
use intentkey_core::{
    DaemonRequest, DaemonResponse, RefusalCode, default_socket_path,
    owner::{default_data_dir, owner_socket_path},
    read_wire_value, write_wire_value,
};
use tokio::{net::UnixListener, sync::Semaphore, task::JoinSet, time::timeout};
use tracing::{Level, warn};
use tracing_subscriber::EnvFilter;
use url::Url;

const CONNECTION_DEADLINE: Duration = Duration::from_secs(5);

#[derive(Debug, Parser)]
#[command(
    name = "intentkeyd",
    version,
    about = "Privileged local credential broker for agents"
)]
struct Cli {
    /// Unix socket that local clients connect to.
    /// Its storage directory is created as 0700; an existing directory must be
    /// owned by this user and already 0700. Existing directories are never chmodded.
    #[arg(long, env = "INTENTKEY_SOCKET", default_value_os_t = default_socket_path())]
    socket: PathBuf,

    /// Durable private native storage, independent of the runtime socket directory.
    #[arg(long, default_value_os_t = default_data_dir())]
    data_dir: PathBuf,

    /// Owner handoff UI base. It must be loopback HTTP.
    #[arg(
        long,
        env = "INTENTKEY_HANDOFF_BASE",
        default_value = "http://127.0.0.1:43117/setup"
    )]
    handoff_base: Url,

    /// Increase diagnostic verbosity.
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Test-only metadata catalog; unavailable unless the test-harness feature is enabled.
    #[cfg(feature = "test-harness")]
    #[arg(long, hide = true)]
    test_catalog: Option<PathBuf>,

    /// Test-only failing executor dispatch log; unavailable in production builds.
    #[cfg(feature = "test-harness")]
    #[arg(long, hide = true)]
    test_executor_log: Option<PathBuf>,

    /// Test-only startup recovery call log; unavailable in production builds.
    #[cfg(feature = "test-harness")]
    #[arg(long, hide = true)]
    test_recovery_log: Option<PathBuf>,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<()> {
    color_eyre::install()?;
    let cli = Cli::parse();
    init_tracing(cli.verbose);
    run(cli).await
}

async fn run(cli: Cli) -> Result<()> {
    // A socket pair obtains the OS-authenticated current UID without trusting environment data.
    let (identity, _peer) = tokio::net::UnixStream::pair()?;
    let uid = identity.peer_cred()?.uid();
    prepare_socket_parent(&cli.socket, uid)?;
    let database = cli
        .socket
        .parent()
        .map(|parent| parent.join("state.sqlite3"))
        .ok_or_else(|| eyre!("socket path has no parent"))?;
    let lock_path = database.with_extension("sqlite3.lock");
    let _database_lock = DatabaseLock::acquire(&lock_path, uid)?;
    let _database_file = open_private_file(&database, uid)?;
    validate_database_sidecars(&database, uid)?;
    prepare_socket(&cli.socket, uid)?;
    let listener = UnixListener::bind(&cli.socket)
        .wrap_err_with(|| format!("could not bind {}", cli.socket.display()))?;
    let _socket_guard = SocketGuard {
        path: cli.socket.clone(),
        metadata: std::fs::symlink_metadata(&cli.socket)?,
    };
    std::fs::set_permissions(&cli.socket, std::fs::Permissions::from_mode(0o600))
        .wrap_err("could not restrict socket permissions")?;
    let state = Arc::new(
        intentkeyd::DaemonState::open(&database)
            .map_err(|_| eyre!("could not open daemon state database"))?,
    );
    let now_ms = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .wrap_err("system clock is before unix epoch")?
            .as_millis(),
    )
    .wrap_err("system clock exceeds supported range")?;
    state
        .recover_after_restart(now_ms)
        .map_err(|_| eyre!("could not recover daemon state"))?;
    #[cfg(feature = "test-harness")]
    if let Some(path) = &cli.test_recovery_log {
        std::fs::write(path, b"recovered\n").wrap_err("could not write test recovery log")?;
    }
    #[cfg(feature = "test-harness")]
    if let Some(path) = &cli.test_catalog {
        let items: Vec<intentkey_core::ItemDescriptor> = serde_json::from_slice(
            &std::fs::read(path).wrap_err("could not read test metadata catalog")?,
        )
        .wrap_err("test metadata catalog was invalid")?;
        for item in items {
            state
                .register_item(item)
                .map_err(|_| eyre!("test metadata catalog item was invalid"))?;
        }
    }
    let native = Arc::new(intentkeyd::NativeService::open(cli.data_dir.clone()).await?);
    let owner_socket = owner_socket_path(&cli.socket);
    if owner_socket == cli.socket {
        return Err(eyre!("agent and owner socket paths must differ"));
    }
    prepare_socket(&owner_socket, uid)?;
    let owner_listener = UnixListener::bind(&owner_socket)?;
    let _owner_socket_guard = SocketGuard {
        metadata: std::fs::symlink_metadata(&owner_socket)?,
        path: owner_socket.clone(),
    };
    std::fs::set_permissions(&owner_socket, std::fs::Permissions::from_mode(0o600))?;
    accept_connections(&cli, uid, listener, owner_listener, native, state).await
}

async fn accept_connections(
    cli: &Cli,
    uid: u32,
    listener: UnixListener,
    owner_listener: UnixListener,
    native: Arc<intentkeyd::NativeService>,
    state: Arc<intentkeyd::DaemonState>,
) -> Result<()> {
    let owner_slots = Arc::new(Semaphore::new(4));
    let mut connections = JoinSet::new();
    // Subscribe before readiness so immediate shutdown cannot race registration.
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    tracing::info!(
        socket = %cli.socket.display(),
        "intentkeyd.ready"
    );

    loop {
        tokio::select! {
            biased;
            _ = interrupt.recv() => break,
            _ = terminate.recv() => break,
            accepted = owner_listener.accept() => {
                let (stream, _) = accepted.wrap_err("owner socket accept failed")?;
                // No unbounded queue of tasks or secret buffers waiting for admission.
                if let Ok(admission) = Arc::clone(&owner_slots).try_acquire_owned() {
                    let native = Arc::clone(&native);
                    let state = Arc::clone(&state);
                    connections.spawn(async move {
                        if let Err(code) = native.serve(stream, uid, state, admission).await {
                            warn!(%code, "owner.connection_failed");
                        }
                    });
                }
            }
            accepted = listener.accept() => {
                let (stream, _) = accepted.wrap_err("socket accept failed")?;
                let handoff_base = cli.handoff_base.clone();
                let state = Arc::clone(&state);
                #[cfg(feature = "test-harness")]
                let test_executor_log = cli.test_executor_log.clone();
                connections.spawn(async move {
                    match timeout(
                        CONNECTION_DEADLINE,
                        serve_connection(
                            stream,
                            &handoff_base,
                            &state,
                            #[cfg(feature = "test-harness")]
                            test_executor_log.as_deref(),
                        ),
                    ).await {
                        Err(error) => warn!(error = %error, "connection.timeout"),
                        Ok(Err(error)) => warn!(error = %error, "connection.failed"),
                        Ok(Ok(())) => {}
                    }
                });
            }
            completed = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = completed {
                    warn!(error = %error, "connection.join_failed");
                }
            }
        }
    }

    connections.abort_all();
    while connections.join_next().await.is_some() {}
    native.shutdown(&state).await?;
    Ok(())
}

async fn serve_connection(
    mut stream: tokio::net::UnixStream,
    handoff_base: &Url,
    state: &intentkeyd::DaemonState,
    #[cfg(feature = "test-harness")] test_executor_log: Option<&Path>,
) -> Result<()> {
    let response = match read_wire_value::<_, DaemonRequest>(&mut stream).await {
        Ok(request) => {
            let uid = match stream.peer_cred() {
                Ok(credentials) => credentials.uid(),
                Err(error) => {
                    warn!(error = %error, "connection.peer_credentials_failed");
                    return write_wire_value(
                        &mut stream,
                        &DaemonResponse::Rejected {
                            code: RefusalCode::Internal,
                            message: "daemon could not authenticate the local peer".to_owned(),
                        },
                    )
                    .await
                    .wrap_err("connection response failed");
                }
            };
            let response = state.handle_request_for_peer(request, handoff_base, uid);
            #[cfg(feature = "test-harness")]
            let response = if let (Some(path), DaemonResponse::OperationAccepted { receipt }) =
                (test_executor_log, &response)
            {
                if receipt.outcome == intentkey_core::OperationOutcome::Queued {
                    use std::io::Write as _;
                    let result = (|| -> Result<()> {
                        state.mark_dispatched(&receipt.operation_ref, unix_now()?)?;
                        let mut log = std::fs::OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open(path)
                            .wrap_err("could not open test executor log")?;
                        writeln!(log, "{}", receipt.operation_ref)
                            .wrap_err("could not write test executor log")?;
                        state.mark_failed_after_dispatch(&receipt.operation_ref, unix_now()?)?;
                        Ok(())
                    })();
                    match result {
                        Ok(()) => response,
                        Err(error) => DaemonResponse::Rejected {
                            code: RefusalCode::Internal,
                            message: error.to_string(),
                        },
                    }
                } else {
                    response
                }
            } else {
                response
            };
            response
        }
        Err(error) => DaemonResponse::Rejected {
            code: RefusalCode::InvalidRequest,
            message: error.to_string(),
        },
    };
    write_wire_value(&mut stream, &response)
        .await
        .wrap_err("connection response failed")?;
    Ok(())
}

#[cfg(feature = "test-harness")]
fn unix_now() -> Result<u64> {
    Ok(u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis(),
    )?)
}

fn prepare_socket_parent(socket: &Path, uid: u32) -> Result<()> {
    let parent = socket
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| eyre!("socket path must name a private storage directory"))?;
    let absolute = std::path::absolute(parent)?;
    if absolute
        .components()
        .any(|part| part == Component::ParentDir)
    {
        return Err(eyre!("storage path must not contain parent traversal"));
    }
    // Protect pathname lookups: no foreign-owned or freely replaceable ancestors.
    // Root-owned system symlinks (such as macOS /var) and sticky temp roots are safe.
    for ancestor in absolute.ancestors() {
        let metadata = match std::fs::symlink_metadata(ancestor) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).wrap_err("could not inspect storage ancestor"),
        };
        if metadata.file_type().is_symlink() && metadata.uid() == 0 && ancestor != absolute {
            continue;
        }
        if !metadata.is_dir()
            || (metadata.uid() != uid && metadata.uid() != 0)
            || (metadata.mode() & 0o022 != 0 && metadata.mode() & 0o1000 == 0)
        {
            return Err(eyre!("unsafe storage ancestor: {}", ancestor.display()));
        }
    }
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent)
        .wrap_err("could not create private socket directory")?;
    let metadata = std::fs::symlink_metadata(parent)?;
    if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o7777 != 0o700 {
        return Err(eyre!(
            "storage directory must be owned by the daemon user and already mode 0700: {}",
            parent.display()
        ));
    }
    Ok(())
}

fn validate_database_sidecars(database: &Path, uid: u32) -> Result<()> {
    // SQLite can also open or remove recovery sidecars during initialization.
    for suffix in ["-journal", "-wal", "-shm"] {
        let sidecar = database.with_file_name(format!("state.sqlite3{suffix}"));
        match std::fs::symlink_metadata(&sidecar) {
            Ok(metadata) => validate_private_file(&sidecar, &metadata, uid)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).wrap_err("could not inspect database sidecar"),
        }
    }
    Ok(())
}

fn validate_private_file(path: &Path, metadata: &Metadata, uid: u32) -> Result<()> {
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o600
    {
        return Err(eyre!(
            "storage file must be an owned, single-link regular file with mode 0600: {}",
            path.display()
        ));
    }
    Ok(())
}

fn open_private_file(path: &Path, uid: u32) -> Result<File> {
    // create_new rejects even dangling symlinks and applies 0600 at creation,
    // before any SQLite write. The verified private parent excludes foreign swaps.
    match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(file) => Ok(file),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let metadata = std::fs::symlink_metadata(path)?;
            validate_private_file(path, &metadata, uid)?;
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)?;
            if !same_file(&metadata, &file.metadata()?) {
                return Err(eyre!(
                    "storage file changed while opening: {}",
                    path.display()
                ));
            }
            Ok(file)
        }
        Err(error) => Err(error).wrap_err_with(|| format!("could not create {}", path.display())),
    }
}

fn same_file(left: &Metadata, right: &Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}

fn prepare_socket(socket: &Path, uid: u32) -> Result<()> {
    let metadata = match std::fs::symlink_metadata(socket) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).wrap_err("could not inspect existing socket"),
    };
    if !metadata.file_type().is_socket() || metadata.uid() != uid {
        return Err(eyre!("existing socket path is not an owned Unix socket"));
    }
    match std::os::unix::net::UnixStream::connect(socket) {
        Ok(_) => Err(eyre!("a daemon is already serving {}", socket.display())),
        Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
            if !same_file(&metadata, &std::fs::symlink_metadata(socket)?) {
                return Err(eyre!("existing socket changed during startup"));
            }
            std::fs::remove_file(socket).wrap_err("could not remove stale socket")
        }
        Err(error) => Err(eyre!("could not verify existing socket: {error}")),
    }
}

fn init_tracing(verbosity: u8) {
    let level = match verbosity {
        0 => Level::INFO,
        1 => Level::DEBUG,
        _ => Level::TRACE,
    };
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("intentkeyd={level}")));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .without_time()
        .compact()
        .with_writer(io::stderr)
        .init();
}

#[derive(Debug)]
struct SocketGuard {
    path: PathBuf,
    metadata: Metadata,
}

#[derive(Debug)]
struct DatabaseLock {
    _file: File,
}

impl DatabaseLock {
    fn acquire(path: &Path, uid: u32) -> Result<Self> {
        let file = open_private_file(path, uid).wrap_err("could not open daemon state lock")?;
        file.try_lock()
            .map_err(|error| eyre!("another daemon is using this state database: {error}"))?;
        Ok(Self { _file: file })
    }
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        let result = std::fs::symlink_metadata(&self.path).and_then(|metadata| {
            if same_file(&self.metadata, &metadata) {
                std::fs::remove_file(&self.path)
            } else {
                Err(io::Error::other(
                    "socket path changed; leaving replacement untouched",
                ))
            }
        });
        if let Err(error) = result
            && error.kind() != io::ErrorKind::NotFound
        {
            warn!(error = %error, "socket.cleanup_failed");
        }
    }
}
