//! Private credential custody; never exposed through the agent protocol.

mod native;
mod native_format;
mod providers;
mod subprocess;

use std::{
    fmt, fs,
    os::unix::fs::{DirBuilderExt, MetadataExt},
    path::{Component, PathBuf},
    sync::Arc,
    time::Duration,
};

use intentkey_core::owner::{
    NativeKind, OwnerRequest, OwnerResponse, SecretErrorCode as Error, VaultStatus,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    sync::{Mutex, OwnedSemaphorePermit},
    time::timeout,
};
use zeroize::Zeroizing;

use crate::DaemonState;
use native::NativeVault;

const METADATA_LIMIT: usize = 65_536;
const FRAME_DEADLINE: Duration = Duration::from_secs(30);
const WORK_DEADLINE: Duration = Duration::from_secs(120);

/// Owner-only transport and serialized native custody. No value accessor is exported.
pub struct NativeService {
    vault: Arc<Mutex<NativeVault>>,
}

impl fmt::Debug for NativeService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeService")
            .finish_non_exhaustive()
    }
}

impl NativeService {
    /// Opens the exclusive native writer on a blocking worker, initially locked.
    pub async fn open(directory: PathBuf) -> Result<Self, Error> {
        let vault = tokio::task::spawn_blocking(move || {
            let directory = std::path::absolute(directory).map_err(|_| Error::Unavailable)?;
            if directory
                .components()
                .any(|part| part == Component::ParentDir)
            {
                return Err(Error::InvalidInput);
            }
            let uid = nix::unistd::Uid::effective().as_raw();
            // Reject unsafe pathname ancestors before any creation; NativeVault
            // rechecks exact ownership, mode and inode identity when opening.
            for ancestor in directory.ancestors() {
                match fs::symlink_metadata(ancestor) {
                    Ok(metadata)
                        if !metadata.is_dir()
                            || (metadata.uid() != uid && metadata.uid() != 0)
                            || (metadata.mode() & 0o022 != 0 && metadata.mode() & 0o1000 == 0) =>
                    {
                        return Err(Error::Unavailable);
                    }
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_) => return Err(Error::Unavailable),
                }
            }
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&directory)
                .map_err(|_| Error::Unavailable)?;
            NativeVault::open(&directory)
        })
        .await
        .map_err(|_| Error::Unavailable)??;
        Ok(Self {
            vault: Arc::new(Mutex::new(vault)),
        })
    }

    /// Serves one same-UID request with bounded frames and owned worker admission.
    pub async fn serve(
        &self,
        mut stream: UnixStream,
        uid: u32,
        state: Arc<DaemonState>,
        admission: OwnedSemaphorePermit,
    ) -> Result<(), Error> {
        // Keep admission through response I/O as well as through actual worker exit.
        let admission = Arc::new(admission);
        if stream.peer_cred().map_err(|_| Error::Unavailable)?.uid() != uid {
            return Err(Error::Unavailable);
        }
        let result = match timeout(FRAME_DEADLINE, read_request(&mut stream)).await {
            Ok(Ok(input)) => self.execute(input, state, Arc::clone(&admission)).await,
            Ok(Err(error)) => Err(error),
            Err(_) => Err(Error::Timeout),
        };
        let response = result.unwrap_or_else(OwnerResponse::Error);
        timeout(FRAME_DEADLINE, write_response(&mut stream, &response))
            .await
            .map_err(|_| Error::Timeout)?
    }

    async fn execute(
        &self,
        input: PrivateRequest,
        state: Arc<DaemonState>,
        admission: Arc<OwnedSemaphorePermit>,
    ) -> Result<OwnerResponse, Error> {
        // Waiting for custody never blocks a Tokio worker. Both guards move into
        // spawn_blocking: cancellation/timeout cannot release real worker admission.
        let mut vault = timeout(WORK_DEADLINE, Arc::clone(&self.vault).lock_owned())
            .await
            .map_err(|_| Error::Timeout)?;
        let worker = tokio::task::spawn_blocking(move || {
            let _admission = admission;
            // Withdraw metadata before any authentication or custody change.
            if state.replace_native_catalog(Vec::new()).is_err() {
                vault.lock();
                return Err(Error::Unavailable);
            }
            let result = dispatch(&mut vault, input);
            if vault.status() == VaultStatus::Unlocked
                && let Err(error) = vault.list().and_then(|items| {
                    state
                        .replace_native_catalog(items)
                        .map_err(|_| Error::Unavailable)
                })
            {
                vault.lock();
                return Err(error);
            }
            result
        });
        timeout(WORK_DEADLINE, worker)
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|_| Error::Unavailable)?
    }

    /// Waits for real blocking work to finish, then drops custody before shutdown.
    pub async fn shutdown(&self, state: &DaemonState) -> Result<(), Error> {
        self.vault.lock().await.lock();
        state
            .replace_native_catalog(Vec::new())
            .map_err(|_| Error::Unavailable)
    }
}

// Deliberately no Debug, Clone or serialization for raw private input.
struct PrivateRequest {
    metadata: OwnerRequest,
    passphrase: Zeroizing<Vec<u8>>,
    value: Option<Zeroizing<Vec<u8>>>,
}

async fn read_frame(stream: &mut UnixStream, limit: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    let length = stream.read_u32().await.map_err(|_| Error::InvalidInput)? as usize;
    if length == 0 {
        return Err(Error::InvalidInput);
    }
    if length > limit {
        return Err(Error::TooLarge);
    }
    let mut bytes = Zeroizing::new(vec![0; length]);
    stream
        .read_exact(&mut bytes)
        .await
        .map_err(|_| Error::InvalidInput)?;
    Ok(bytes)
}

async fn read_request(stream: &mut UnixStream) -> Result<PrivateRequest, Error> {
    if stream.read_u16().await.map_err(|_| Error::InvalidInput)? != 1 {
        return Err(Error::InvalidInput);
    }
    let bytes = read_frame(stream, METADATA_LIMIT).await?;
    let metadata: OwnerRequest = serde_json::from_slice(&bytes).map_err(|_| Error::InvalidInput)?;
    let passphrase = read_frame(stream, 1024).await?;
    let value = if matches!(
        metadata,
        OwnerRequest::Store { .. } | OwnerRequest::Update { .. }
    ) {
        Some(read_frame(stream, 65_536).await?)
    } else {
        None
    };
    Ok(PrivateRequest {
        metadata,
        passphrase,
        value,
    })
}

async fn write_response(stream: &mut UnixStream, response: &OwnerResponse) -> Result<(), Error> {
    let mut bytes = serde_json::to_vec(response).map_err(|_| Error::Unavailable)?;
    if bytes.len() > METADATA_LIMIT {
        bytes = serde_json::to_vec(&OwnerResponse::Error(Error::TooLarge))
            .map_err(|_| Error::Unavailable)?;
    }
    stream
        .write_u32(u32::try_from(bytes.len()).map_err(|_| Error::TooLarge)?)
        .await
        .map_err(|_| Error::Unavailable)?;
    stream
        .write_all(&bytes)
        .await
        .map_err(|_| Error::Unavailable)
}

fn dispatch(vault: &mut NativeVault, input: PrivateRequest) -> Result<OwnerResponse, Error> {
    let PrivateRequest {
        metadata,
        passphrase,
        value,
    } = input;
    match metadata {
        OwnerRequest::Init => {
            vault.initialize(&passphrase)?;
            return Ok(OwnerResponse::State(vault.status()));
        }
        OwnerRequest::Unlock => {
            vault.unlock(&passphrase)?;
            return Ok(OwnerResponse::State(vault.status()));
        }
        _ => vault.authenticate(&passphrase)?,
    }
    match metadata {
        OwnerRequest::Lock => {
            vault.lock();
            Ok(OwnerResponse::State(vault.status()))
        }
        OwnerRequest::List => Ok(OwnerResponse::Items(vault.list()?)),
        OwnerRequest::Generate => {
            if vault.status() != VaultStatus::Unlocked {
                return Err(Error::Locked);
            }
            let mut value = Zeroizing::new(vec![0; 32]);
            getrandom::fill(&mut value).map_err(|_| Error::Unavailable)?;
            Ok(OwnerResponse::Item(vault.store(NativeKind::Bearer, value)?))
        }
        OwnerRequest::Store { kind } => Ok(OwnerResponse::Item(
            vault.store(kind, value.ok_or(Error::InvalidInput)?)?,
        )),
        OwnerRequest::Update { item_id, revision } => Ok(OwnerResponse::Item(vault.update(
            &item_id,
            revision,
            value.ok_or(Error::InvalidInput)?,
        )?)),
        OwnerRequest::Remove { item_id, revision } => {
            vault.remove(&item_id, revision)?;
            Ok(OwnerResponse::Removed(item_id))
        }
        OwnerRequest::Init | OwnerRequest::Unlock => Err(Error::InvalidInput),
        OwnerRequest::Provider(request) => Ok(OwnerResponse::Provider(
            tokio::runtime::Handle::current().block_on(async {
                timeout(Duration::from_secs(90), providers::dispatch(vault, request))
                    .await
                    .map_err(|_| Error::Timeout)?
            })?,
        )),
    }
}
