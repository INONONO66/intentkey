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
    /// External provider control over the same authenticated owner channel.
    Provider(ProviderOwnerRequest),
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
    /// Safe external provider result.
    Provider(ProviderOwnerResponse),
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

/// External provider family. Authentication is established separately by the owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    /// Proton Pass CLI.
    ProtonPass,
    /// 1Password CLI.
    OnePassword,
}

/// Owner-approved provider process configuration. This contains no session tokens.
/// Store it encrypted; it is not part of the agent-facing catalog.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfig {
    /// Selected external provider.
    pub kind: ProviderKind,
    /// Absolute executable approved by the authenticated owner.
    pub executable: PathBuf,
    /// Owner-approved private HOME (not inherited from daemon environment).
    pub home: PathBuf,
    /// Owner-only session/configuration directory.
    pub session_dir: PathBuf,
    /// Optional owner-only token file, read once on connect into encrypted custody.
    /// Only 1Password service-account tokens are supported; never sent in argv.
    pub service_account_file: Option<PathBuf>,
    /// Exact 1Password vault or Proton share identifier.
    pub vault_id: String,
}

/// Opaque connection metadata, not an authentication capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderConnectionMetadata {
    /// Daemon-generated connection identifier (never an account/session token).
    pub provider_id: String,
    /// External provider family.
    pub kind: ProviderKind,
}

/// Field class; TOTP and passkeys can be described but cannot be imported or executed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderComponentKind {
    /// Password field, eligible for private import if revision is stable.
    Password,
    /// Bearer field, eligible for private import if revision is stable.
    Bearer,
    /// TOTP is unsupported, regardless of stored presence.
    Totp,
    /// Passkey is unsupported, regardless of stored presence.
    Passkey,
    /// Unknown or ambiguous field.
    Unsupported,
}

/// Safe selectable component; no label, vendor field text, or value fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderComponentMetadata {
    /// Daemon-generated opaque component identifier.
    pub component_id: crate::ComponentId,
    /// Normalized field class.
    pub kind: ProviderComponentKind,
    /// Whether an exact stable snapshot supports private import.
    pub importable: bool,
}

/// Safe item catalog entry backed by a separately encrypted vendor mapping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderItemMetadata {
    /// Connection identifier, scoped to the authenticated owner.
    pub provider_id: String,
    /// Daemon-generated opaque item identifier, not vendor JSON or title.
    pub item_id: ItemId,
    /// Local mapping revision; never a hash of secret bytes.
    pub revision: u64,
    /// Safe supported/unsupported component metadata.
    pub components: Vec<ProviderComponentMetadata>,
}

/// Exact owner-selected field to import into native encrypted custody.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderImportRequest {
    /// Owner-scoped connection identifier.
    pub provider_id: String,
    /// Opaque item selected from the provider metadata catalog.
    pub item_id: ItemId,
    /// Expected local mapping revision.
    pub revision: u64,
    /// Explicitly selected Password/Bearer component.
    pub component_id: crate::ComponentId,
}

/// Metadata-only provider control contract for the owner transport integration.
///
/// Every variant requires the existing separately framed passphrase. Defining
/// this DTO does not add an unauthenticated or agent-facing dispatch path.
#[derive(Debug, Serialize, Deserialize)]
#[serde(
    tag = "op",
    content = "input",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ProviderOwnerRequest {
    /// Authenticate and validate an owner-approved read-only connection.
    Connect(ProviderConfig),
    /// List opaque connections.
    Connections,
    /// List safe item/component metadata while unlocked.
    List {
        /// Owner-scoped connection identifier.
        provider_id: String,
    },
    /// Import one exact selected snapshot; never reveal its value.
    Import(ProviderImportRequest),
    /// Revoke a connection and its encrypted mappings.
    Disconnect {
        /// Owner-scoped connection identifier.
        provider_id: String,
    },
}

/// Metadata-only provider results; native import returns an ordinary item descriptor.
#[derive(Debug, Serialize, Deserialize)]
#[serde(
    tag = "status",
    content = "output",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ProviderOwnerResponse {
    /// Validated read-only connection metadata.
    Connected(ProviderConnectionMetadata),
    /// Opaque connection catalog.
    Connections(Vec<ProviderConnectionMetadata>),
    /// Safe provider item/component catalog.
    Items(Vec<ProviderItemMetadata>),
    /// Native custody metadata created by private import.
    Imported(ItemDescriptor),
    /// Revoked opaque connection identifier.
    Disconnected(String),
    /// Fixed error code without subprocess context.
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
