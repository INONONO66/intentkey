//! `IntentKey` protocol vocabulary and pure claim issuance.

use std::{env, fmt, io, path::PathBuf};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use url::Url;
use uuid::Uuid;

/// Maximum lifetime accepted for an owner handoff claim.
pub const MAX_SETUP_TTL_MS: u64 = 15 * 60 * 1_000;

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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TargetOrigin(Url);

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

/// Agent intent requesting an authenticated action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Intent {
    /// Stable action vocabulary chosen by the caller.
    pub action: String,
    /// Exact target at which a credential may be used.
    pub target: TargetOrigin,
}

/// Request for an owner-facing credential setup handoff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

/// Daemon wire request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", content = "input", rename_all = "snake_case")]
pub enum DaemonRequest {
    /// Probes daemon readiness.
    Health,
    /// Issues an owner setup claim.
    CreateSetup(SetupRequest),
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
    /// Expiry calculation exceeded the supported clock range.
    #[error("claim expiry exceeds the supported clock range")]
    InvalidExpiry,
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
}
