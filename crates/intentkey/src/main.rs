//! `intentkey` owner and agent command-line client.

pub mod owner;

use std::{
    io::{self, Write},
    path::PathBuf,
    time::Duration,
};

use clap::{Parser, Subcommand, ValueEnum};
use color_eyre::eyre::{Context, Result, eyre};
use intentkey_core::{
    CredentialKind, DaemonRequest, DaemonResponse, Intent, ItemId, SetupRequest, TargetOrigin,
    default_socket_path,
    owner::{
        NativeKind, OwnerRequest, OwnerResponse, ProviderConfig, ProviderImportRequest,
        ProviderKind, ProviderOwnerRequest,
    },
    read_wire_value, write_wire_value,
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
    /// Manage encrypted native custody through the private owner channel.
    Vault {
        /// Inherited pipe or Unix socket containing raw length-prefixed private inputs.
        #[arg(long, global = true)]
        secret_fd: Option<i32>,
        #[command(subcommand)]
        command: VaultCommand,
    },
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

#[derive(Debug, Subcommand)]
enum VaultCommand {
    /// Read-only external providers on the authenticated private owner channel.
    Provider {
        #[command(subcommand)]
        command: ProviderCommand,
    },
    /// Initialize a new encrypted vault; never overwrite an existing vault.
    Init,
    /// Unlock persisted custody after authentication.
    Unlock,
    /// Authenticate and drop decrypted custody.
    Lock,
    /// List opaque metadata from unlocked custody.
    List,
    /// Generate and store random bearer material without revealing it.
    Generate,
    /// Store the separately supplied private value.
    Store {
        #[arg(long, value_enum)]
        kind: VaultKind,
    },
    /// Replace a private value at its exact current revision.
    Update {
        #[arg(long)]
        item_id: String,
        #[arg(long)]
        revision: u64,
    },
    /// Remove an item at its exact current revision.
    Remove {
        #[arg(long)]
        item_id: String,
        #[arg(long)]
        revision: u64,
    },
}

#[derive(Debug, Subcommand)]
enum ProviderCommand {
    /// Validate an existing owner-authenticated vendor session and exact vault/share.
    Connect {
        #[arg(long, value_enum)]
        kind: ProviderFamily,
        #[arg(long)]
        executable: PathBuf,
        #[arg(long)]
        home: PathBuf,
        #[arg(long)]
        session_dir: PathBuf,
        #[arg(long)]
        vault_id: String,
        /// Owner-only file in session-dir; encrypt its op service-account token on connect.
        #[arg(long)]
        service_account_file: Option<PathBuf>,
    },
    /// List persisted opaque connections (not a live vendor health probe).
    Status,
    /// Refresh opaque importable Login password selections; invalidates prior selections.
    List {
        #[arg(long)]
        provider_id: String,
    },
    /// Import one exact stored password selection into native encrypted custody.
    Import {
        #[arg(long)]
        provider_id: String,
        #[arg(long)]
        item_id: String,
        #[arg(long)]
        revision: u64,
        #[arg(long, value_parser = parse_component)]
        component_id: intentkey_core::ComponentId,
    },
    /// Remove the local connection and mapping; does not delete imported native items.
    Disconnect {
        #[arg(long)]
        provider_id: String,
    },
}

fn parse_component(value: &str) -> Result<intentkey_core::ComponentId, String> {
    intentkey_core::ComponentId::new(value).map_err(|_| "InvalidInput".to_owned())
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ProviderFamily {
    ProtonPass,
    OnePassword,
}

impl From<ProviderCommand> for ProviderOwnerRequest {
    fn from(command: ProviderCommand) -> Self {
        match command {
            ProviderCommand::Connect {
                kind,
                executable,
                home,
                session_dir,
                vault_id,
                service_account_file,
            } => Self::Connect(ProviderConfig {
                kind: match kind {
                    ProviderFamily::ProtonPass => ProviderKind::ProtonPass,
                    ProviderFamily::OnePassword => ProviderKind::OnePassword,
                },
                executable,
                home,
                session_dir,
                vault_id,
                service_account_file,
            }),
            ProviderCommand::Status => Self::Connections,
            ProviderCommand::List { provider_id } => Self::List { provider_id },
            ProviderCommand::Disconnect { provider_id } => Self::Disconnect { provider_id },
            ProviderCommand::Import {
                provider_id,
                item_id,
                revision,
                component_id,
            } => Self::Import(ProviderImportRequest {
                provider_id,
                item_id: ItemId::new(item_id),
                revision,
                component_id,
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum VaultKind {
    Password,
    Bearer,
}

impl From<VaultCommand> for OwnerRequest {
    fn from(command: VaultCommand) -> Self {
        match command {
            VaultCommand::Provider { command } => Self::Provider(command.into()),
            VaultCommand::Init => Self::Init,
            VaultCommand::Unlock => Self::Unlock,
            VaultCommand::Lock => Self::Lock,
            VaultCommand::List => Self::List,
            VaultCommand::Generate => Self::Generate,
            VaultCommand::Store { kind } => Self::Store {
                kind: match kind {
                    VaultKind::Password => NativeKind::Password,
                    VaultKind::Bearer => NativeKind::Bearer,
                },
            },
            VaultCommand::Update { item_id, revision } => Self::Update {
                item_id: ItemId::new(item_id),
                revision,
            },
            VaultCommand::Remove { item_id, revision } => Self::Remove {
                item_id: ItemId::new(item_id),
                revision,
            },
        }
    }
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
async fn main() -> Result<std::process::ExitCode> {
    color_eyre::install()?;
    let cli = Cli::parse();
    if let Command::Vault { command, secret_fd } = cli.command {
        let response = owner::run(&cli.socket, command.into(), secret_fd)
            .await
            .unwrap_or_else(OwnerResponse::Error);
        let failed = matches!(response, OwnerResponse::Error(_));
        let mut output = io::stdout().lock();
        serde_json::to_writer(&mut output, &response)?;
        writeln!(output)?;
        return Ok(if failed {
            std::process::ExitCode::FAILURE
        } else {
            std::process::ExitCode::SUCCESS
        });
    }
    let request = build_request(cli.command)?;
    let response = exchange(&cli.socket, &request).await?;
    render(response, cli.format)?;
    Ok(std::process::ExitCode::SUCCESS)
}

fn build_request(command: Command) -> Result<DaemonRequest> {
    match command {
        Command::Status => Ok(DaemonRequest::Health),
        Command::Vault { .. } => Err(eyre!("owner commands require the dedicated owner channel")),
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
