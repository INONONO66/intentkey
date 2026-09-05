//! `intentkeyd` privileged local daemon entry point.

use std::{
    io,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
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
                connections.spawn(async move {
                    if let Err(error) = timeout(
                        CONNECTION_DEADLINE,
                        serve_connection(stream, &handoff_base),
                    ).await {
                        warn!(error = %error, "connection.timeout");
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

async fn serve_connection(mut stream: tokio::net::UnixStream, handoff_base: &Url) {
    let response = match read_wire_value::<_, DaemonRequest>(&mut stream).await {
        Ok(request) => intentkeyd::handle_request(request, handoff_base),
        Err(error) => DaemonResponse::Rejected {
            code: RefusalCode::InvalidRequest,
            message: error.to_string(),
        },
    };
    if let Err(error) = write_wire_value(&mut stream, &response).await {
        warn!(error = %error, "connection.response_failed");
    }
}

async fn prepare_socket_parent(socket: &Path) -> Result<()> {
    if socket.exists() {
        return Err(eyre!(
            "socket already exists at {}; stop the running daemon or remove a stale socket",
            socket.display()
        ));
    }
    let parent = socket
        .parent()
        .ok_or_else(|| eyre!("socket path has no parent"))?;
    tokio::fs::create_dir_all(parent)
        .await
        .wrap_err("could not create socket directory")?;
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
        .wrap_err("could not restrict socket directory permissions")?;
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

impl Drop for SocketGuard {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_file(&self.0)
            && error.kind() != io::ErrorKind::NotFound
        {
            warn!(error = %error, "socket.cleanup_failed");
        }
    }
}
