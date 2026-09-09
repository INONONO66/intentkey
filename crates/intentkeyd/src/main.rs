//! `intentkeyd` privileged local daemon entry point.

use std::{
    fs::File,
    io,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use clap::Parser;
use color_eyre::eyre::{Context, Result, eyre};
use intentkey_core::{
    DaemonRequest, DaemonResponse, RefusalCode, default_socket_path, read_wire_value,
    write_wire_value,
};
use tokio::{net::UnixListener, task::JoinSet, time::timeout};
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
    #[arg(long, env = "INTENTKEY_SOCKET", default_value_os_t = default_socket_path())]
    socket: PathBuf,

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
    prepare_socket_parent(&cli.socket).await?;
    let listener = UnixListener::bind(&cli.socket)
        .wrap_err_with(|| format!("could not bind {}", cli.socket.display()))?;
    std::fs::set_permissions(&cli.socket, std::fs::Permissions::from_mode(0o600))
        .wrap_err("could not restrict socket permissions")?;
    let _socket_guard = SocketGuard(cli.socket.clone());
    let database = cli
        .socket
        .parent()
        .map(|parent| parent.join("state.sqlite3"))
        .ok_or_else(|| eyre!("socket path has no parent"))?;
    let lock_path = database.with_extension("sqlite3.lock");
    let _database_lock = DatabaseLock::acquire(&lock_path)?;
    if database.exists() {
        std::fs::set_permissions(&database, std::fs::Permissions::from_mode(0o600))
            .wrap_err("could not restrict database permissions")?;
    }
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
    let mut connections = JoinSet::new();

    tracing::info!(
        socket = %cli.socket.display(),
        "intentkeyd.ready"
    );

    loop {
        tokio::select! {
            biased;
            signal = tokio::signal::ctrl_c() => {
                signal.wrap_err("could not listen for shutdown signal")?;
                break;
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

fn unix_now() -> Result<u64> {
    Ok(u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis(),
    )?)
}

async fn prepare_socket_parent(socket: &Path) -> Result<()> {
    let parent = socket
        .parent()
        .ok_or_else(|| eyre!("socket path has no parent"))?;
    tokio::fs::create_dir_all(parent)
        .await
        .wrap_err("could not create socket directory")?;
    if socket.exists() {
        match std::os::unix::net::UnixStream::connect(socket) {
            Ok(_) => return Err(eyre!("a daemon is already serving {}", socket.display())),
            Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                std::fs::remove_file(socket).wrap_err("could not remove stale socket")?;
            }
            Err(error) => return Err(eyre!("could not verify existing socket: {error}")),
        }
    }
    Ok(())
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
struct SocketGuard(PathBuf);

#[derive(Debug)]
struct DatabaseLock {
    _file: File,
}

impl DatabaseLock {
    #[allow(clippy::incompatible_msrv)]
    fn acquire(path: &Path) -> Result<Self> {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .wrap_err("could not open daemon state lock")?;
        file.try_lock()
            .map_err(|error| eyre!("another daemon is using this state database: {error}"))?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .wrap_err("could not restrict database lock permissions")?;
        Ok(Self { _file: file })
    }
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_file(&self.0)
            && error.kind() != io::ErrorKind::NotFound
        {
            warn!(error = %error, "socket.cleanup_failed");
        }
    }
}
