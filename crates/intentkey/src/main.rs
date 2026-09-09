//! `intentkey` owner and agent command-line client.

use std::{
    io::{self, Write},
    path::PathBuf,
    time::Duration,
};

use clap::{Parser, Subcommand, ValueEnum};
use color_eyre::eyre::{Context, Result, eyre};
use intentkey_core::{
    CredentialKind, DaemonRequest, DaemonResponse, Intent, SetupRequest, TargetOrigin,
    default_socket_path, read_wire_value, write_wire_value,
};
use tokio::{net::UnixStream, time::timeout};

const REQUEST_DEADLINE: Duration = Duration::from_secs(5);

#[derive(Debug, Parser)]
#[command(
    name = "intentkey",
    version,
    about = "Give agents permission to act, not secrets to hold",
    arg_required_else_help = true
)]
struct Cli {
    /// Unix socket exposed by intentkeyd.
    #[arg(long, env = "INTENTKEY_SOCKET", default_value_os_t = default_socket_path(), global = true)]
    socket: PathBuf,

    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Pretty, global = true)]
    format: OutputFormat,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Check whether the local broker is ready.
    Status,
    /// Create a secret-free owner setup handoff.
    Setup {
        /// Exact HTTP(S) origin at which the credential may be used.
        #[arg(long)]
        origin: String,
        /// Stable action requested by the agent.
        #[arg(long)]
        action: String,
        /// Credential class to collect or generate.
        #[arg(long, value_enum)]
        kind: CliCredentialKind,
        /// Claim lifetime in seconds.
        #[arg(long, default_value_t = 300)]
        ttl_seconds: u64,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliCredentialKind {
    Login,
    ApiToken,
    Oauth,
    Ssh,
}

impl From<CliCredentialKind> for CredentialKind {
    fn from(value: CliCredentialKind) -> Self {
        match value {
            CliCredentialKind::Login => Self::Login,
            CliCredentialKind::ApiToken => Self::ApiToken,
            CliCredentialKind::Oauth => Self::Oauth,
            CliCredentialKind::Ssh => Self::Ssh,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Pretty,
    Json,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    color_eyre::install()?;
    let cli = Cli::parse();
    let request = build_request(cli.command)?;
    let response = exchange(&cli.socket, &request).await?;
    render(response, cli.format)
}

fn build_request(command: Command) -> Result<DaemonRequest> {
    match command {
        Command::Status => Ok(DaemonRequest::Health),
        Command::Setup {
            origin,
            action,
            kind,
            ttl_seconds,
        } => {
            let ttl_ms = ttl_seconds
                .checked_mul(1_000)
                .ok_or_else(|| eyre!("ttl seconds exceed the supported range"))?;
            Ok(DaemonRequest::CreateSetup(SetupRequest {
                intent: Intent {
                    action,
                    target: TargetOrigin::parse(&origin)?,
                },
                kind: kind.into(),
                ttl_ms,
            }))
        }
    }
}

async fn exchange(socket: &PathBuf, request: &DaemonRequest) -> Result<DaemonResponse> {
    timeout(REQUEST_DEADLINE, async {
        let mut stream = UnixStream::connect(socket)
            .await
            .wrap_err_with(|| format!("could not connect to {}", socket.display()))?;
        write_wire_value(&mut stream, request)
            .await
            .wrap_err("could not send request")?;
        read_wire_value(&mut stream)
            .await
            .wrap_err("could not read response")
    })
    .await
    .wrap_err("intentkeyd request timed out")?
}

fn render(response: DaemonResponse, format: OutputFormat) -> Result<()> {
    if let DaemonResponse::Rejected { code, message } = response {
        return Err(eyre!("{code:?}: {message}"));
    }

    let stdout = io::stdout();
    let mut output = stdout.lock();
    match format {
        OutputFormat::Json => {
            serde_json::to_writer(&mut output, &response)?;
            writeln!(output)?;
        }
        OutputFormat::Pretty => match response {
            DaemonResponse::Healthy { protocol_version } => {
                writeln!(output, "intentkeyd ready (protocol {protocol_version})")?;
            }
            DaemonResponse::SetupCreated { grant } => {
                writeln!(output, "{}", grant.handoff_url)?;
            }
            DaemonResponse::Rejected { .. } => unreachable!("handled before rendering"),
            _ => writeln!(output, "unsupported response in compatibility CLI")?,
        },
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn command_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn rejects_non_origin_before_connecting() {
        let cli = Cli::try_parse_from([
            "intentkey",
            "setup",
            "--origin",
            "https://github.com/settings",
            "--action",
            "account_signup",
            "--kind",
            "login",
        ])
        .expect("valid command shape");

        assert!(build_request(cli.command).is_err());
    }

    #[test]
    fn builds_typed_setup_request() {
        let cli = Cli::try_parse_from([
            "intentkey",
            "setup",
            "--origin",
            "https://github.com",
            "--action",
            "account_signup",
            "--kind",
            "login",
            "--ttl-seconds",
            "60",
        ])
        .expect("valid command");

        let DaemonRequest::CreateSetup(request) =
            build_request(cli.command).expect("request built")
        else {
            panic!("expected setup request");
        };
        assert_eq!(request.ttl_ms, 60_000);
        assert_eq!(request.kind, CredentialKind::Login);
    }
}
