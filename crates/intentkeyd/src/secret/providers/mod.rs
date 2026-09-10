//! Private, read-only vendor snapshots and authenticated native import.
mod onepassword;
mod proton_pass;

use super::{
    native::NativeVault,
    subprocess::{Identifier, ProviderCommand, RunnerError, SubprocessConfig, SubprocessRunner},
};
use intentkey_core::{
    ComponentId, ItemId,
    owner::{
        NativeKind, ProviderComponentKind, ProviderComponentMetadata, ProviderConfig,
        ProviderConnectionMetadata, ProviderItemMetadata, ProviderKind, ProviderOwnerRequest,
        ProviderOwnerResponse, SecretErrorCode as Error,
    },
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs::OpenOptions,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
};
use zeroize::{Zeroize, Zeroizing};

const MAX_SOURCE_ITEMS: usize = 32;

// No vendor labels, values, or hashes are returned over either socket.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Source {
    pub item_id: String,
    pub revision: String,
    pub fingerprint: [u8; 32],
}
impl Drop for Source {
    fn drop(&mut self) {
        self.fingerprint.zeroize();
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Mapping {
    pub metadata: ProviderItemMetadata,
    pub source: Source,
}

pub(super) fn id(value: &str) -> Result<Identifier, Error> {
    Identifier::new(value).map_err(runner_error)
}
pub(super) const fn runner_error(error: RunnerError) -> Error {
    match error {
        RunnerError::InvalidConfiguration => Error::InvalidInput,
        RunnerError::Timeout => Error::Timeout,
        RunnerError::TooLarge => Error::TooLarge,
        RunnerError::Spawn | RunnerError::Io | RunnerError::NonZero | RunnerError::Cancelled => {
            Error::Unavailable
        }
    }
}

pub(super) fn validate(config: &ProviderConfig) -> Result<SubprocessConfig, Error> {
    id(&config.vault_id)?;
    if config.kind != ProviderKind::OnePassword && config.service_account_file.is_some() {
        return Err(Error::Unsupported);
    }
    SubprocessConfig::new(
        config.executable.clone(),
        config.home.clone(),
        config.session_dir.clone(),
    )
    .map_err(runner_error)
}

fn token(config: &ProviderConfig) -> Result<Zeroizing<Vec<u8>>, Error> {
    let Some(path) = &config.service_account_file else {
        return Ok(Zeroizing::new(Vec::new()));
    };
    if !path.is_absolute() || path.parent() != Some(config.session_dir.as_path()) {
        return Err(Error::InvalidInput);
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| Error::Unavailable)?;
    let metadata = file.metadata().map_err(|_| Error::Unavailable)?;
    if !metadata.is_file()
        || metadata.uid() != nix::unistd::Uid::effective().as_raw()
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o600
        || metadata.len() > 8192
    {
        return Err(Error::InvalidInput);
    }
    let mut value = Zeroizing::new(vec![0; 8193]);
    let mut length = 0;
    loop {
        if length == value.len() {
            return Err(Error::TooLarge);
        }
        let n = file
            .read(&mut value[length..])
            .map_err(|_| Error::Unavailable)?;
        if n == 0 {
            break;
        }
        length += n;
    }
    value.truncate(length);
    if value.last() == Some(&b'\n') {
        value.pop();
    }
    if value.is_empty() || !value.iter().all(u8::is_ascii_graphic) {
        return Err(Error::InvalidInput);
    }
    Ok(value)
}

async fn list(runner: &SubprocessRunner, config: &ProviderConfig) -> Result<Vec<Source>, Error> {
    let items = match config.kind {
        ProviderKind::ProtonPass => proton_pass::list(runner, &config.vault_id).await?,
        ProviderKind::OnePassword => onepassword::list(runner, &config.vault_id).await?,
    };
    if items.len() > MAX_SOURCE_ITEMS {
        return Err(Error::TooLarge);
    }
    let mut unique = HashSet::new();
    for item in &items {
        id(&item.item_id)?;
        if item.revision.is_empty() || item.revision.len() > 256 || !unique.insert(&item.item_id) {
            return Err(Error::InvalidInput);
        }
    }
    Ok(items)
}

async fn field(
    runner: &SubprocessRunner,
    config: &ProviderConfig,
    item: &Source,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let field = id("password")?;
    let vault = id(&config.vault_id)?;
    let item_id = id(&item.item_id)?;
    let command = match config.kind {
        ProviderKind::ProtonPass => ProviderCommand::ProtonField {
            share_id: vault,
            item_id,
            field,
        },
        ProviderKind::OnePassword => ProviderCommand::OnePasswordRead {
            vault_id: vault,
            item_id,
            field,
        },
    };
    let output = runner.run(command).await.map_err(runner_error)?;
    // pass-cli 2.3.3 prints the raw field with println!, even with --output json.
    // Remove exactly its framing LF, never trim owner material or op's raw output.
    let bytes = if config.kind == ProviderKind::ProtonPass {
        output.strip_suffix(b"\n").ok_or(Error::InvalidInput)?
    } else {
        output.as_slice()
    };
    if bytes.is_empty() {
        return Err(Error::Unsupported);
    }
    if bytes.len() > 65_536 {
        return Err(Error::TooLarge);
    }
    Ok(Zeroizing::new(bytes.to_vec()))
}

async fn snapshot(
    runner: &SubprocessRunner,
    config: &ProviderConfig,
) -> Result<Vec<Source>, Error> {
    let mut before = list(runner, config).await?;
    for item in &mut before {
        let value = field(runner, config, item).await?;
        item.fingerprint.copy_from_slice(&Sha256::digest(&value));
    }
    let after = list(runner, config).await?;
    if before.len() != after.len()
        || before
            .iter()
            .zip(&after)
            .any(|(a, b)| a.item_id != b.item_id || a.revision != b.revision)
    {
        return Err(Error::RevisionMismatch);
    }
    Ok(before)
}

pub(super) fn mappings(
    provider_id: &str,
    revision: u64,
    source: Vec<Source>,
) -> Result<Vec<Mapping>, Error> {
    source
        .into_iter()
        .map(|source| {
            Ok(Mapping {
                metadata: ProviderItemMetadata {
                    provider_id: provider_id.to_owned(),
                    item_id: ItemId::new(format!("ext_{}", uuid::Uuid::new_v4().simple())),
                    revision,
                    components: vec![ProviderComponentMetadata {
                        component_id: ComponentId::new(format!(
                            "fld_{}",
                            uuid::Uuid::new_v4().simple()
                        ))
                        .map_err(|_| Error::InvalidInput)?,
                        kind: ProviderComponentKind::Password,
                        importable: true,
                    }],
                },
                source,
            })
        })
        .collect()
}

pub(super) async fn dispatch(
    vault: &mut NativeVault,
    request: ProviderOwnerRequest,
) -> Result<ProviderOwnerResponse, Error> {
    // Already passphrase-authenticated by owner dispatch; this rejects locked custody.
    vault.connections()?;
    match request {
        ProviderOwnerRequest::Connect(config) => {
            let process = validate(&config)?;
            let token = token(&config)?;
            let runner = SubprocessRunner::new(process).with_service_account(&token)?;
            match config.kind {
                ProviderKind::ProtonPass => proton_pass::connect(&runner, &config.vault_id).await?,
                ProviderKind::OnePassword => {
                    onepassword::connect(&runner, &config.vault_id).await?;
                }
            }
            Ok(ProviderOwnerResponse::Connected(
                vault.connect_provider(config, token)?,
            ))
        }
        ProviderOwnerRequest::Connections => {
            Ok(ProviderOwnerResponse::Connections(vault.connections()?))
        }
        ProviderOwnerRequest::Disconnect { provider_id } => {
            vault.disconnect_provider(&provider_id)?;
            Ok(ProviderOwnerResponse::Disconnected(provider_id))
        }
        ProviderOwnerRequest::List { provider_id } => {
            let (config, token) = vault.provider_config(&provider_id)?;
            let runner = SubprocessRunner::new(validate(config)?).with_service_account(token)?;
            let source = snapshot(&runner, config).await?;
            Ok(ProviderOwnerResponse::Items(
                vault.save_provider_mappings(&provider_id, source)?,
            ))
        }
        ProviderOwnerRequest::Import(request) => {
            let selected = vault.provider_mapping(&request)?;
            let (config, token) = vault.provider_config(&request.provider_id)?;
            let runner = SubprocessRunner::new(validate(config)?).with_service_account(token)?;
            let before = list(&runner, config).await?;
            let current = before
                .iter()
                .find(|s| s.item_id == selected.item_id)
                .ok_or(Error::RevisionMismatch)?;
            if current.revision != selected.revision {
                return Err(Error::RevisionMismatch);
            }
            let value = field(&runner, config, current).await?;
            if Sha256::digest(&value)[..] != selected.fingerprint {
                return Err(Error::RevisionMismatch);
            }
            let after = list(&runner, config).await?;
            if !after
                .iter()
                .any(|s| s.item_id == selected.item_id && s.revision == selected.revision)
            {
                return Err(Error::RevisionMismatch);
            }
            Ok(ProviderOwnerResponse::Imported(
                vault.store(NativeKind::Password, value)?,
            ))
        }
    }
}

pub(super) const fn connection(
    provider_id: String,
    kind: ProviderKind,
) -> ProviderConnectionMetadata {
    ProviderConnectionMetadata { provider_id, kind }
}
