//! Metadata-only owner control plane. Raw secret frames are a separate trusted data plane.

use crate::{ItemDescriptor, ItemId};
use serde::{Deserialize, Serialize};
use std::{
    env,
    path::{Path, PathBuf},
};

/// Native storage class; neither class has a privileged consumer yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeKind {
    /// Password material.
    Password,
    /// Bearer material.
    Bearer,
}

/// Owner-only metadata request. Agent sessions never confer this role.
#[derive(Debug, Serialize, Deserialize)]
#[serde(
    tag = "op",
    content = "input",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum OwnerRequest {
    /// Initialize without overwriting any existing vault.
    Init,
    /// Authenticate and hydrate custody.
    Unlock,
    /// Authenticate and drop custody.
    Lock,
    /// List opaque metadata while unlocked.
    List,
    /// Generate and store random bearer material without revealing it.
    Generate,
    /// Store the separately framed value.
    Store {
        /// Storage class.
        kind: NativeKind,
    },
    /// Replace the separately framed value at an exact revision.
    Update {
        /// Opaque item identity.
        item_id: ItemId,
        /// Expected current revision.
        revision: u64,
    },
    /// Remove an item at an exact revision.
    Remove {
        /// Opaque item identity.
        item_id: ItemId,
        /// Expected current revision.
        revision: u64,
    },
}

/// Custody state, not an authorization capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultStatus {
    /// No vault has been initialized.
    Uninitialized,
    /// Persisted, with no decrypted custody.
    Locked,
    /// Decrypted private custody is available.
    Unlocked,
}

/// Fixed code-only errors; no secret-bearing source or context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum SecretErrorCode {
    /// Input failed bounded validation.
    #[error("InvalidInput")]
    InvalidInput,
    /// Wrong passphrase or failed authentication tag.
    #[error("AuthenticationFailed")]
    AuthenticationFailed,
    /// Operation requires already-unlocked custody.
    #[error("Locked")]
    Locked,
    /// Initialization refuses any existing file.
    #[error("AlreadyInitialized")]
    AlreadyInitialized,
    /// Item or vault was not found.
    #[error("NotFound")]
    NotFound,
    /// Stale item revision.
    #[error("RevisionMismatch")]
    RevisionMismatch,
    /// No consumer exists for this operation.
    #[error("Unsupported")]
    Unsupported,
    /// Admission limit reached.
    #[error("Busy")]
    Busy,
    /// Private storage or input unavailable.
    #[error("Unavailable")]
    Unavailable,
    /// Bounded input or output exceeded its limit.
    #[error("TooLarge")]
    TooLarge,
    /// Framing deadline expired.
    #[error("Timeout")]
    Timeout,
    /// Rename succeeded but durability could not be confirmed; custody is locked.
    #[error("StorageUncertain")]
    StorageUncertain,
}

/// Owner response contains only opaque metadata or a fixed error code.
#[derive(Debug, Serialize, Deserialize)]
#[serde(
    tag = "status",
    content = "output",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum OwnerResponse {
    /// Current custody state.
    State(VaultStatus),
    /// Created or updated metadata.
    Item(ItemDescriptor),
    /// Complete metadata catalog; oversized lists fail rather than truncate.
    Items(Vec<ItemDescriptor>),
    /// Removed opaque identity.
    Removed(ItemId),
    /// Fixed failure code.
    Error(SecretErrorCode),
}

/// Owner socket is separate from the model-facing agent socket.
pub fn owner_socket_path(agent_socket: &Path) -> PathBuf {
    agent_socket.with_file_name("owner.sock")
}

/// Durable storage is independent of the ephemeral socket runtime directory.
pub fn default_data_dir() -> PathBuf {
    env::var_os("XDG_DATA_HOME").map_or_else(
        || {
            env::var_os("HOME").map_or_else(
                || PathBuf::from(".local/share/intentkey"),
                |home| PathBuf::from(home).join(".local/share/intentkey"),
            )
        },
        |data| PathBuf::from(data).join("intentkey"),
    )
}
