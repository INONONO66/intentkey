//! `IntentKey` daemon request admission.

use std::time::{SystemTime, UNIX_EPOCH};

use intentkey_core::{
    DaemonRequest, DaemonResponse, ProtocolError, RefusalCode, SetupRequest, issue_setup_claim,
};
use url::Url;

/// Handles one already-decoded daemon request.
pub fn handle_request(request: DaemonRequest, handoff_base: &Url) -> DaemonResponse {
    match request {
        DaemonRequest::Health => DaemonResponse::Healthy {
            protocol_version: intentkey_core::PROTOCOL_VERSION,
        },
        DaemonRequest::CreateSetup(input) => create_setup(input, handoff_base),
    }
}

fn create_setup(input: SetupRequest, handoff_base: &Url) -> DaemonResponse {
    match unix_epoch_ms().and_then(|now_ms| issue_setup_claim(input, now_ms, handoff_base)) {
        Ok(grant) => DaemonResponse::SetupCreated { grant },
        Err(error) => rejected(error),
    }
}

fn unix_epoch_ms() -> Result<u64, ProtocolError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ProtocolError::InvalidExpiry)?;
    u64::try_from(elapsed.as_millis()).map_err(|_| ProtocolError::InvalidExpiry)
}

fn rejected(error: ProtocolError) -> DaemonResponse {
    let code = match error {
        ProtocolError::InvalidOrigin => RefusalCode::InvalidOrigin,
        ProtocolError::InvalidTtl | ProtocolError::InvalidExpiry => RefusalCode::InvalidTtl,
        ProtocolError::InvalidAction | ProtocolError::InvalidHandoffBase => {
            RefusalCode::InvalidRequest
        }
        _ => RefusalCode::Internal,
    };
    DaemonResponse::Rejected {
        code,
        message: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use intentkey_core::{CredentialKind, Intent, TargetOrigin};

    use super::*;

    #[test]
    fn health_reports_current_protocol() {
        assert_eq!(
            handle_request(
                DaemonRequest::Health,
                &Url::parse("http://127.0.0.1:43117/setup").expect("valid base")
            ),
            DaemonResponse::Healthy {
                protocol_version: intentkey_core::PROTOCOL_VERSION
            }
        );
    }

    #[test]
    fn setup_returns_safe_claim() {
        let response = handle_request(
            DaemonRequest::CreateSetup(SetupRequest {
                intent: Intent {
                    action: "account_signup".to_owned(),
                    target: TargetOrigin::parse("https://github.com").expect("valid origin"),
                },
                kind: CredentialKind::Login,
                ttl_ms: 60_000,
            }),
            &Url::parse("http://127.0.0.1:43117/setup").expect("valid base"),
        );

        let DaemonResponse::SetupCreated { grant } = response else {
            panic!("expected setup grant");
        };
        assert_eq!(grant.max_uses, 1);
        assert!(grant.handoff_url.query().is_none());
        assert!(grant.handoff_url.fragment().is_some());
    }
}
