//! `IntentKey` protocol vocabulary and pure claim issuance.

use std::{env, fmt, io, path::PathBuf};

use serde::de::{DeserializeOwned, Error as DeserializeError};
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use url::Url;
use uuid::Uuid;

/// Maximum lifetime accepted for an owner handoff claim.
pub const MAX_SETUP_TTL_MS: u64 = 15 * 60 * 1_000;
/// Maximum lifetime accepted for a prepared use authorization.
pub const MAX_USE_TTL_MS: u64 = 5 * 60 * 1_000;

/// Maximum accepted request or response payload.
pub const MAX_WIRE_BYTES: u32 = 64 * 1_024;

/// Current local daemon protocol version.
pub const PROTOCOL_VERSION: u16 = 1;

/// A credential class requested by an agent intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CredentialKind {
    /// Username, password, passkey, or one-time-code login.
    Login,
    /// API bearer or application token.
    ApiToken,
    /// OAuth grant managed by a provider.
    Oauth,
    /// SSH credential or agent-backed identity.
    Ssh,
}

/// An exact HTTP(S) origin approved as a credential target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct TargetOrigin(Url);

impl<'de> Deserialize<'de> for TargetOrigin {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(D::Error::custom)
    }
}

impl TargetOrigin {
    /// Parses a URL and rejects everything except an exact HTTP(S) origin.
    pub fn parse(value: &str) -> Result<Self, ProtocolError> {
        let url = Url::parse(value).map_err(|_| ProtocolError::InvalidOrigin)?;
        let exact_origin = matches!(url.scheme(), "http" | "https")
            && url.username().is_empty()
            && url.password().is_none()
            && url.path() == "/"
            && url.query().is_none()
            && url.fragment().is_none();
        if !exact_origin {
            return Err(ProtocolError::InvalidOrigin);
        }
        Ok(Self(url))
    }

    /// Returns the normalized origin string.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Display for TargetOrigin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// The kind of non-secret login component described by an item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoginComponentKind {
    /// Username/password login.
    Password,
    /// Time-based one-time password login.
    Totp,
    /// `WebAuthn` or platform passkey login.
    Passkey,
}

/// Whether a provider has this component stored for the item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentPresence {
    /// The provider has the component stored.
    Stored,
    /// The provider does not have the component stored.
    Absent,
}

/// Whether the current operation path can use this component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationSupport {
    /// The operation path supports this component.
    Supported,
    /// The operation path does not support this component.
    Unsupported,
}

/// Stable opaque identifier for one component of an item.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct ComponentId(String);

impl<'de> Deserialize<'de> for ComponentId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(D::Error::custom)
    }
}

impl ComponentId {
    /// Creates a stable component identifier from the model-safe vocabulary.
    pub fn new(value: impl Into<String>) -> Result<Self, ProtocolError> {
        let value = value.into();
        if valid_opaque_id(&value) {
            Ok(Self(value))
        } else {
            Err(ProtocolError::InvalidComponentId)
        }
    }

    /// Returns the stable component identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Metadata for a login component. It never contains a secret value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginComponentMetadata {
    /// Stable identifier for this component.
    pub id: ComponentId,
    /// Component authentication shape.
    pub kind: LoginComponentKind,
    /// Provider-side stored presence, independent of operation support.
    pub provider_presence: ComponentPresence,
    /// Whether the selected operation can use this component.
    pub operation_support: OperationSupport,
}

impl LoginComponentMetadata {
    /// Creates metadata without accepting credential material.
    pub const fn new(
        id: ComponentId,
        kind: LoginComponentKind,
        provider_presence: ComponentPresence,
        operation_support: OperationSupport,
    ) -> Self {
        Self {
            id,
            kind,
            provider_presence,
            operation_support,
        }
    }
}

/// The typed item vocabulary understood by the daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "variant", rename_all = "snake_case")]
pub enum ItemKind {
    /// A login whose components are described by [`ItemDescriptor`].
    Login,
    /// A person or organization identity.
    Identity,
    /// An API credential.
    ApiCredential,
    /// A payment card.
    PaymentCard,
    /// An SSH key.
    SshKey,
    /// A secure note.
    SecureNote,
}

/// Validated metadata for one stored item, including its provider-specific revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ItemDescriptor {
    /// Opaque stable identity of the stored item.
    pub item_id: ItemId,
    /// Provider-specific revision for this item, not a universal catalog revision.
    pub revision: u64,
    /// Item class; login component metadata is present for [`ItemKind::Login`].
    pub kind: ItemKind,
    /// Non-secret metadata for all login components.
    pub login_components: Vec<LoginComponentMetadata>,
}

impl ItemDescriptor {
    /// Validates identity, revision metadata, and component identity uniqueness.
    pub fn new(
        item_id: ItemId,
        revision: u64,
        kind: ItemKind,
        login_components: Vec<LoginComponentMetadata>,
    ) -> Result<Self, ProtocolError> {
        if !valid_opaque_id(item_id.as_str()) {
            return Err(ProtocolError::InvalidItemId);
        }
        if kind != ItemKind::Login && !login_components.is_empty() {
            return Err(ProtocolError::NonLoginComponents);
        }
        let mut ids = std::collections::HashSet::with_capacity(login_components.len());
        for component in &login_components {
            if !ids.insert(&component.id) {
                return Err(ProtocolError::DuplicateComponentId);
            }
        }
        Ok(Self {
            item_id,
            revision,
            kind,
            login_components,
        })
    }
}

impl<'de> Deserialize<'de> for ItemDescriptor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct RawItemDescriptor {
            item_id: ItemId,
            revision: u64,
            kind: ItemKind,
            login_components: Vec<LoginComponentMetadata>,
        }
        let raw = RawItemDescriptor::deserialize(deserializer)?;
        Self::new(raw.item_id, raw.revision, raw.kind, raw.login_components)
            .map_err(D::Error::custom)
    }
}

fn valid_opaque_id(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

/// Opaque identifier for a stored item.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct ItemId(String);

impl<'de> Deserialize<'de> for ItemId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if valid_opaque_id(&value) {
            Ok(Self(value))
        } else {
            Err(D::Error::custom(ProtocolError::InvalidItemId))
        }
    }
}

impl ItemId {
    /// Creates an item identifier from an opaque daemon-issued value.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Returns the opaque item identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Login operation requested without exposing login fields or credential data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoginUse {
    /// Use the password login flow.
    Password,
    /// Use the TOTP login flow.
    Totp,
    /// Use the passkey login flow.
    Passkey,
}

/// Typed operation requested against an item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "operation",
    content = "variant",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum UseOperation {
    /// Use a login item.
    Login(LoginUse),
    /// Use an identity item.
    Identity,
    /// Use an API credential item.
    ApiCredential,
    /// Use a payment card item.
    PaymentCard,
    /// Use an SSH key item.
    SshKey,
    /// Read or apply a secure-note item through a privileged integration.
    SecureNote,
}

/// Agent intent requesting an authenticated action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Intent {
    /// Stable action vocabulary chosen by the caller.
    pub action: String,
    /// Exact target at which a credential may be used.
    pub target: TargetOrigin,
}

/// Request for an owner-facing credential setup handoff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetupRequest {
    /// Authenticated action the eventual credential enables.
    pub intent: Intent,
    /// Credential class to collect or generate.
    pub kind: CredentialKind,
    /// Requested claim lifetime in milliseconds.
    pub ttl_ms: u64,
}

/// Opaque identifier for a one-time owner handoff claim.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ClaimId(String);

impl ClaimId {
    /// Returns the opaque claim identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Safe result returned to an agent after claim issuance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetupGrant {
    /// Opaque single-use claim identifier.
    pub claim_id: ClaimId,
    /// Owner-facing loopback link. The claim appears only in the fragment.
    pub handoff_url: Url,
    /// Exact target bound to this claim.
    pub target: TargetOrigin,
    /// Absolute Unix epoch expiry in milliseconds.
    pub expires_at_ms: u64,
    /// Maximum successful redemptions.
    pub max_uses: u8,
}

/// Request to use one daemon-issued item reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UseRequest {
    /// Opaque reference to the item selected by the daemon.
    pub item_id: ItemId,
    /// Exact action and target authorized by the caller.
    pub intent: Intent,
    /// Typed operation; it never contains credential fields.
    pub operation: UseOperation,
    /// Provider-specific item revision admitted for this operation.
    pub revision: u64,
    /// Login component metadata admitted with this operation.
    pub login_components: Vec<LoginComponentMetadata>,
    /// Exact login component selected by the caller, if applicable.
    pub selected_component: Option<ComponentId>,
}

/// Capability bound to one local daemon session.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionCapability(String);
impl SessionCapability {
    /// Creates a daemon-generated capability.
    pub const fn new(value: String) -> Self {
        Self(value)
    }
    /// Returns the opaque capability string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Strict opaque prepared-use link.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct UseLink(String);
impl UseLink {
    /// Parses the exact daemon link syntax.
    pub fn parse(value: &str) -> Result<Self, ProtocolError> {
        let ticket = value
            .strip_prefix("intentkey://use/")
            .ok_or(ProtocolError::InvalidUseLink)?;
        if ticket.len() != 64
            || !ticket
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(ProtocolError::InvalidUseLink);
        }
        Ok(Self(value.to_owned()))
    }
    /// Creates a link from a lowercase hexadecimal ticket.
    pub fn from_ticket(ticket: &str) -> Result<Self, ProtocolError> {
        Self::parse(&format!("intentkey://use/{ticket}"))
    }
    /// Returns the opaque ticket.
    pub fn ticket(&self) -> &str {
        &self.0[16..]
    }
}
impl<'de> Deserialize<'de> for UseLink {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(&String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

/// Durable outcome vocabulary for one admitted operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationOutcome {
    /// Accepted and waiting to run.
    Queued,
    /// Sent to the provider or integration.
    Dispatched,
    /// Completed successfully.
    Completed,
    /// Failed before dispatch.
    FailedBeforeDispatch,
    /// Failed after dispatch.
    FailedAfterDispatch,
    /// The outcome cannot be determined.
    Indeterminate,
    /// The operation expired before completion.
    Expired,
    /// The operation was canceled.
    Canceled,
}
/// Metadata-only operation receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationReceipt {
    /// Stable operation reference.
    pub operation_ref: String,
    /// Caller-provided request reference.
    pub request_id: String,
    /// Opaque item identifier.
    pub item_id: ItemId,
    /// Typed operation that was requested.
    pub operation_kind: UseOperation,
    /// Provider-specific item revision admitted for this operation.
    pub revision: u64,
    /// Exact login component selected by the caller, if applicable.
    pub selected_component: Option<ComponentId>,
    /// Login component metadata admitted with this operation.
    pub login_components: Vec<LoginComponentMetadata>,
    /// Exact target of the operation.
    pub target: TargetOrigin,
    /// Durable operation outcome.
    pub outcome: OperationOutcome,
    /// Unix epoch start time in milliseconds.
    pub started_at_ms: u64,
    /// Unix epoch completion time in milliseconds, if completed.
    pub completed_at_ms: Option<u64>,
}

/// Request to prepare an exact item revision and operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareUseRequest {
    /// Opaque local session capability.
    pub session: SessionCapability,
    /// Opaque item identifier.
    pub item_id: ItemId,
    /// Provider-specific item revision to prepare.
    pub revision: u64,
    /// Action and target authorized by the caller.
    pub intent: Intent,
    /// Typed operation to prepare.
    pub operation: UseOperation,
    /// Exact login component selected by the caller.
    pub selected_component: Option<ComponentId>,
    /// Maximum preparation lifetime in milliseconds.
    pub ttl_ms: u64,
}
/// Request to execute a prepared link, with no replacement payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecuteUseRequest {
    /// Opaque local session capability.
    pub session: SessionCapability,
    /// Prepared-use link.
    pub link: UseLink,
}
/// Session-scoped operation action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationRequest {
    /// Opaque local session capability.
    pub session: SessionCapability,
    /// Stable operation reference.
    pub operation_ref: String,
}

/// Daemon wire request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "op",
    content = "input",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum DaemonRequest {
    /// Probes daemon readiness.
    Health,
    /// Issues an owner setup claim.
    CreateSetup(SetupRequest),
    /// Opens an opaque local session.
    OpenSession,
    /// Lists the session's metadata-only catalog.
    ListItems {
        /// Opaque local session capability.
        session: SessionCapability,
    },
    /// Prepares a fixed use authorization.
    PrepareUse(PrepareUseRequest),
    /// Consumes a prepared authorization.
    ExecuteUse(ExecuteUseRequest),
    /// Inspects a session-owned operation.
    InspectOperation(OperationRequest),
    /// Cancels a queued session-owned operation.
    CancelOperation(OperationRequest),
}

/// Daemon wire response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum DaemonResponse {
    /// Daemon is ready.
    Healthy {
        /// Daemon protocol version.
        protocol_version: u16,
    },
    /// Setup handoff claim was issued.
    SetupCreated {
        /// Safe setup grant.
        grant: SetupGrant,
    },
    /// Opaque local session capability.
    SessionOpened {
        /// Opaque local session capability.
        session: SessionCapability,
    },
    /// Metadata-only catalog.
    ItemsListed {
        /// Item descriptors without credential values.
        items: Vec<ItemDescriptor>,
    },
    /// Prepared authorization link.
    UsePrepared {
        /// Strict opaque prepared-use link.
        link: UseLink,
        /// Unix epoch expiry in milliseconds.
        expires_at_ms: u64,
    },
    /// Durable accepted operation.
    OperationAccepted {
        /// Metadata-only operation receipt.
        receipt: OperationReceipt,
    },
    /// Current operation receipt.
    OperationInspected {
        /// Metadata-only operation receipt.
        receipt: OperationReceipt,
    },
    /// Canceled operation receipt.
    OperationCanceled {
        /// Metadata-only operation receipt.
        receipt: OperationReceipt,
    },
    /// Request was refused at the boundary.
    Rejected {
        /// Stable machine-readable refusal kind.
        code: RefusalCode,
        /// Human-facing explanation containing no request payload.
        message: String,
    },
}

/// Stable daemon refusal vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RefusalCode {
    /// Request bytes did not match the protocol.
    InvalidRequest,
    /// Target was not an exact HTTP(S) origin.
    InvalidOrigin,
    /// Claim lifetime exceeded the configured limit.
    InvalidTtl,
    /// Daemon could not complete a valid request.
    Internal,
    /// Caller is not authorized for the resource.
    Unauthorized,
    /// Item or action is unsupported.
    Unsupported,
    /// Authorization has expired.
    Expired,
    /// Request conflicts with current state.
    Conflict,
}

/// Protocol validation failure.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProtocolError {
    /// Target was not an exact HTTP(S) origin.
    #[error("target must be an exact HTTP(S) origin")]
    InvalidOrigin,
    /// Claim lifetime was zero or exceeded the maximum.
    #[error("setup claim ttl must be between 1 and 900000 milliseconds")]
    InvalidTtl,
    /// Handoff base URL was invalid.
    #[error("handoff base must be a loopback HTTP URL without query or fragment")]
    InvalidHandoffBase,
    /// Intent action did not use the stable machine vocabulary.
    #[error("action must contain 1-64 lowercase ASCII letters, digits, or underscores")]
    InvalidAction,
    /// Item identity was empty or outside the opaque identifier vocabulary.
    #[error("item identity must contain 1-128 ASCII letters, digits, underscores, or hyphens")]
    InvalidItemId,
    /// Component identity was empty or outside the opaque identifier vocabulary.
    #[error("component identity must contain 1-128 ASCII letters, digits, underscores, or hyphens")]
    InvalidComponentId,
    /// A login component identity occurred more than once.
    #[error("login component identities must be unique")]
    DuplicateComponentId,
    /// Only login items may carry login component metadata.
    #[error("non-login items cannot carry login component metadata")]
    NonLoginComponents,
    /// Expiry calculation exceeded the supported clock range.
    #[error("claim expiry exceeds the supported clock range")]
    InvalidExpiry,
    /// Prepared use link syntax is invalid.
    #[error("use link is invalid")]
    InvalidUseLink,
}

/// Issues a safe setup claim without handling credential plaintext.
pub fn issue_setup_claim(
    request: SetupRequest,
    now_ms: u64,
    handoff_base: &Url,
) -> Result<SetupGrant, ProtocolError> {
    if request.ttl_ms == 0 || request.ttl_ms > MAX_SETUP_TTL_MS {
        return Err(ProtocolError::InvalidTtl);
    }
    if !valid_action(&request.intent.action) {
        return Err(ProtocolError::InvalidAction);
    }
    if !valid_handoff_base(handoff_base) {
        return Err(ProtocolError::InvalidHandoffBase);
    }

    let expires_at_ms = now_ms
        .checked_add(request.ttl_ms)
        .ok_or(ProtocolError::InvalidExpiry)?;
    let claim_id = ClaimId(format!("clm_{}", Uuid::new_v4().simple()));
    let mut handoff_url = handoff_base.clone();
    handoff_url.set_fragment(Some(&format!("claim={}", claim_id.as_str())));

    Ok(SetupGrant {
        claim_id,
        handoff_url,
        target: request.intent.target,
        expires_at_ms,
        max_uses: 1,
    })
}

/// Resolves the default per-user Unix socket path.
pub fn default_socket_path() -> PathBuf {
    env::var_os("INTENTKEY_SOCKET").map_or_else(
        || {
            env::var_os("XDG_RUNTIME_DIR").map_or_else(
                || {
                    env::var_os("HOME").map_or_else(
                        || PathBuf::from(".intentkey/intentkeyd.sock"),
                        |home| PathBuf::from(home).join(".intentkey/intentkeyd.sock"),
                    )
                },
                |runtime| PathBuf::from(runtime).join("intentkey/intentkeyd.sock"),
            )
        },
        PathBuf::from,
    )
}

/// Reads one length-prefixed JSON value from a local transport.
pub async fn read_wire_value<R, T>(reader: &mut R) -> Result<T, WireError>
where
    R: AsyncRead + Send + Unpin,
    T: DeserializeOwned,
{
    let length = reader.read_u32().await?;
    if length > MAX_WIRE_BYTES {
        return Err(WireError::PayloadTooLarge { length });
    }
    let mut payload = vec![0_u8; length as usize];
    reader.read_exact(&mut payload).await?;
    Ok(serde_json::from_slice(&payload)?)
}

/// Writes one length-prefixed JSON value to a local transport.
pub async fn write_wire_value<W, T>(writer: &mut W, value: &T) -> Result<(), WireError>
where
    W: AsyncWrite + Send + Unpin,
    T: Serialize + Sync,
{
    let payload = serde_json::to_vec(value)?;
    let length = u32::try_from(payload.len())
        .map_err(|_| WireError::PayloadTooLarge { length: u32::MAX })?;
    if length > MAX_WIRE_BYTES {
        return Err(WireError::PayloadTooLarge { length });
    }
    writer.write_u32(length).await?;
    writer.write_all(&payload).await?;
    writer.flush().await?;
    Ok(())
}

/// Local wire framing failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum WireError {
    /// Local transport failed.
    #[error("local transport failed")]
    Io(#[from] io::Error),
    /// JSON payload did not satisfy the typed wire contract.
    #[error("wire payload was invalid")]
    Json(#[from] serde_json::Error),
    /// Declared or encoded payload exceeded the protocol limit.
    #[error("wire payload exceeds {MAX_WIRE_BYTES} bytes")]
    PayloadTooLarge {
        /// Declared payload length.
        length: u32,
    },
}

fn valid_action(action: &str) -> bool {
    (1..=64).contains(&action.len())
        && action
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn valid_handoff_base(url: &Url) -> bool {
    let loopback_host = match url.host() {
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        Some(url::Host::Domain(domain)) => domain == "localhost",
        None => false,
    };
    url.scheme() == "http"
        && loopback_host
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> SetupRequest {
        SetupRequest {
            intent: Intent {
                action: "account_signup".to_owned(),
                target: TargetOrigin::parse("https://github.com").expect("valid origin"),
            },
            kind: CredentialKind::Login,
            ttl_ms: 60_000,
        }
    }

    #[test]
    fn issues_single_use_claim_in_url_fragment() {
        let base = Url::parse("http://127.0.0.1:43117/setup").expect("valid base");
        let grant = issue_setup_claim(request(), 1_000, &base).expect("claim issued");

        assert_eq!(grant.expires_at_ms, 61_000);
        assert_eq!(grant.max_uses, 1);
        assert!(grant.handoff_url.query().is_none());
        assert_eq!(
            grant.handoff_url.fragment(),
            Some(format!("claim={}", grant.claim_id.as_str()).as_str())
        );
    }

    #[test]
    fn rejects_non_origin_targets() {
        assert_eq!(
            TargetOrigin::parse("https://github.com/settings"),
            Err(ProtocolError::InvalidOrigin)
        );
        assert_eq!(
            TargetOrigin::parse("file:///tmp/secret"),
            Err(ProtocolError::InvalidOrigin)
        );
    }

    #[test]
    fn raw_wire_origin_is_validated_instead_of_constructing_url_directly() {
        let invalid = serde_json::from_str::<TargetOrigin>("\"https://github.com/settings\"");
        assert!(invalid.is_err());
    }

    #[test]
    fn item_vocabulary_is_typed_and_serializes_without_secret_fields() {
        let items = [
            ItemKind::Login,
            ItemKind::Identity,
            ItemKind::ApiCredential,
            ItemKind::PaymentCard,
            ItemKind::SshKey,
            ItemKind::SecureNote,
        ];

        for item in items {
            let json = serde_json::to_value(item).expect("item serializable");
            assert!(json.as_object().is_some());
            assert!(!json.to_string().contains("plaintext"));
            assert!(!json.to_string().contains("value"));
        }
    }

    #[test]
    fn composite_login_descriptor_round_trips_all_component_metadata() {
        let descriptor = ItemDescriptor::new(
            ItemId::new("itm_composite"),
            7,
            ItemKind::Login,
            vec![
                LoginComponentMetadata::new(
                    ComponentId::new("cmp_password").expect("valid component id"),
                    LoginComponentKind::Password,
                    ComponentPresence::Stored,
                    OperationSupport::Supported,
                ),
                LoginComponentMetadata::new(
                    ComponentId::new("cmp_totp").expect("valid component id"),
                    LoginComponentKind::Totp,
                    ComponentPresence::Stored,
                    OperationSupport::Supported,
                ),
                LoginComponentMetadata::new(
                    ComponentId::new("cmp_passkey").expect("valid component id"),
                    LoginComponentKind::Passkey,
                    ComponentPresence::Absent,
                    OperationSupport::Supported,
                ),
            ],
        )
        .expect("valid descriptor");

        let encoded = serde_json::to_vec(&descriptor).expect("descriptor serializes");
        let decoded: ItemDescriptor = serde_json::from_slice(&encoded).expect("descriptor parses");
        assert_eq!(decoded, descriptor);
        assert_eq!(decoded.revision, 7);
        assert_eq!(decoded.login_components.len(), 3);
        assert_eq!(
            decoded.login_components[2].provider_presence,
            ComponentPresence::Absent
        );
        assert_eq!(
            decoded.login_components[2].operation_support,
            OperationSupport::Supported
        );
    }

    #[test]
    fn login_metadata_rejects_unknown_fields() {
        let raw = r#"{"id":"cmp_password","kind":"password","provider_presence":"stored","operation_support":"supported","unexpected":true}"#;
        assert!(serde_json::from_str::<LoginComponentMetadata>(raw).is_err());
    }

    #[test]
    fn item_descriptor_rejects_unknown_fields() {
        let raw = r#"{"item_id":"itm_example","revision":1,"kind":"identity","login_components":[],"unexpected":true}"#;
        assert!(serde_json::from_str::<ItemDescriptor>(raw).is_err());
    }

    #[test]
    fn item_id_rejects_malformed_input_during_decode() {
        assert!(serde_json::from_str::<ItemId>(r#""""#).is_err());
        assert!(serde_json::from_str::<ItemId>(r#""bad id""#).is_err());
    }

    #[test]
    fn descriptor_rejects_duplicate_component_ids_during_construction_and_decode() {
        let duplicate = || {
            ItemDescriptor::new(
                ItemId::new("itm_duplicate"),
                1,
                ItemKind::Login,
                vec![
                    LoginComponentMetadata::new(
                        ComponentId::new("cmp_same").expect("valid component id"),
                        LoginComponentKind::Password,
                        ComponentPresence::Stored,
                        OperationSupport::Supported,
                    ),
                    LoginComponentMetadata::new(
                        ComponentId::new("cmp_same").expect("valid component id"),
                        LoginComponentKind::Totp,
                        ComponentPresence::Stored,
                        OperationSupport::Supported,
                    ),
                ],
            )
        };
        assert_eq!(duplicate(), Err(ProtocolError::DuplicateComponentId));

        let raw = r#"{
            "item_id":"itm_duplicate",
            "revision":1,
            "kind":"login",
            "login_components":[
                {"id":"cmp_same","kind":"password","provider_presence":"stored","operation_support":"supported"},
                {"id":"cmp_same","kind":"passkey","provider_presence":"absent","operation_support":"unsupported"}
            ]
        }"#;
        assert!(serde_json::from_str::<ItemDescriptor>(raw).is_err());
    }

    #[test]
    fn use_request_contains_only_opaque_item_and_operation_metadata() {
        let request = UseRequest {
            item_id: ItemId::new("itm_example"),
            operation: UseOperation::Login(LoginUse::Password),
            intent: Intent {
                action: "sign_in".to_owned(),
                target: TargetOrigin::parse("https://github.com").expect("valid origin"),
            },
            revision: 1,
            login_components: Vec::new(),
            selected_component: None,
        };
        let value = serde_json::to_value(request).expect("request serializable");
        let text = value.to_string();
        assert!(text.contains("itm_example"));
        assert!(!text.contains("plaintext"));
        assert!(!text.contains("credential_value"));
    }

    #[test]
    fn rejects_unbounded_claim_lifetime() {
        let base = Url::parse("http://127.0.0.1:43117/setup").expect("valid base");
        let mut input = request();
        input.ttl_ms = MAX_SETUP_TTL_MS + 1;

        assert_eq!(
            issue_setup_claim(input, 1_000, &base),
            Err(ProtocolError::InvalidTtl)
        );
    }

    #[test]
    fn serialized_grant_contains_no_secret_material() {
        let base = Url::parse("http://127.0.0.1:43117/setup").expect("valid base");
        let grant = issue_setup_claim(request(), 1_000, &base).expect("claim issued");
        let value = serde_json::to_value(grant).expect("serializable grant");
        let object = value.as_object().expect("object grant");

        assert_eq!(
            object.keys().collect::<Vec<_>>(),
            [
                "claim_id",
                "expires_at_ms",
                "handoff_url",
                "max_uses",
                "target"
            ]
        );
    }

    #[test]
    fn rejects_non_loopback_handoff_base() {
        let base = Url::parse("https://intentkey.example/setup").expect("valid URL");

        assert_eq!(
            issue_setup_claim(request(), 1_000, &base),
            Err(ProtocolError::InvalidHandoffBase)
        );
    }

    #[test]
    fn rejects_unstable_action_vocabulary() {
        let base = Url::parse("http://127.0.0.1:43117/setup").expect("valid base");
        let mut input = request();
        input.intent.action = "Sign in".to_owned();

        assert_eq!(
            issue_setup_claim(input, 1_000, &base),
            Err(ProtocolError::InvalidAction)
        );
    }

    #[tokio::test]
    async fn round_trips_length_prefixed_wire_value() {
        let request = DaemonRequest::Health;
        let mut bytes = Vec::new();
        write_wire_value(&mut bytes, &request)
            .await
            .expect("frame written");

        let decoded: DaemonRequest = read_wire_value(&mut bytes.as_slice())
            .await
            .expect("frame read");

        assert_eq!(decoded, request);
    }

    #[test]
    fn daemon_request_rejects_nested_operation_target() {
        let raw = r#"{
            "op":"prepare_use",
            "input":{
                "session":"ses_test",
                "item_id":"itm_test",
                "revision":0,
                "intent":{"action":"sign_in","target":"https://github.com/"},
                "operation":{
                    "operation":"login",
                    "variant":"password",
                    "target":"https://other.example/"
                },
                "selected_component":"cmp_password",
                "ttl_ms":1000
            }
        }"#;
        let mut valid: serde_json::Value = serde_json::from_str(raw).expect("valid JSON");
        valid["input"]["operation"]
            .as_object_mut()
            .expect("operation object")
            .remove("target");
        assert!(matches!(
            serde_json::from_value::<DaemonRequest>(valid),
            Ok(DaemonRequest::PrepareUse(PrepareUseRequest {
                operation: UseOperation::Login(LoginUse::Password),
                revision: 0,
                ..
            }))
        ));
        assert!(serde_json::from_str::<DaemonRequest>(raw).is_err());
    }

    #[test]
    fn daemon_request_rejects_unknown_envelope_fields() {
        let raw = r#"{"op":"health","unexpected":true}"#;
        assert!(serde_json::from_str::<DaemonRequest>(raw).is_err());
    }
}
