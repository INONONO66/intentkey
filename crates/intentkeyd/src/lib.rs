//! `IntentKey` daemon request admission.
use std::{
    collections::HashMap,
    fmt,
    path::Path,
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use intentkey_core::{
    CredentialKind, DaemonRequest, DaemonResponse, ExecuteUseRequest, Intent, ItemDescriptor,
    MAX_USE_TTL_MS, OperationOutcome, OperationReceipt, PrepareUseRequest, ProtocolError,
    RefusalCode, SessionCapability, SetupGrant, SetupRequest, TargetOrigin, UseLink, UseOperation,
    UseRequest, issue_setup_claim,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;
use uuid::Uuid;

type PreparedLinkRow = (String, i64, i64, Option<String>, i64);

/// Operation types are re-exported from the wire protocol.
pub use intentkey_core::{
    OperationOutcome as CoreOperationOutcome, OperationReceipt as CoreOperationReceipt,
};
/// Metadata made available after a setup ticket is consumed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetupAdmission {
    /// Exact action and target bound to the ticket.
    pub intent: Intent,
    /// Credential class requested by the owner flow.
    pub kind: CredentialKind,
}

/// State-machine admission or transition failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateError {
    /// Protocol-level input validation failed.
    Protocol(ProtocolError),
    /// An opaque ticket did not identify a link.
    InvalidTicket,
    /// The link or operation authorization expired.
    Expired,
    /// A setup ticket was already consumed.
    TicketConsumed,
    /// A request ID was reused with different input.
    IdempotencyConflict,
    /// A request identifier was malformed.
    InvalidRequestId,
    /// An operation reference was unknown.
    OperationNotFound,
    /// The requested state transition was not allowed.
    InvalidTransition,
    /// Session or resource is not authorized for this caller.
    Unauthorized,
    /// Item revision or operation is unavailable.
    Unsupported,
    /// SQLite state could not be initialized, locked, read, or written.
    StateUnavailable,
}

impl From<ProtocolError> for StateError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

impl fmt::Display for StateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Protocol(_) => "request failed protocol validation",
            Self::InvalidTicket => "setup ticket is invalid",
            Self::Expired => "authorization expired",
            Self::TicketConsumed => "setup ticket was already consumed",
            Self::IdempotencyConflict => "request id was reused with different input",
            Self::InvalidRequestId => "request id is invalid",
            Self::OperationNotFound => "operation was not found",
            Self::InvalidTransition => "operation transition is invalid",
            Self::Unauthorized => "request is not authorized",
            Self::Unsupported => "item or operation is unsupported",
            Self::StateUnavailable => "daemon state is unavailable",
        })
    }
}

impl std::error::Error for StateError {}

/// Concurrency-safe SQLite-backed daemon persistence boundary.
#[derive(Debug)]
pub struct DaemonState {
    db: Mutex<Connection>,
    catalog: Mutex<HashMap<String, ItemDescriptor>>,
}

impl DaemonState {
    /// Creates an empty in-memory daemon state store.
    pub fn new() -> Result<Self, StateError> {
        let db = Connection::open_in_memory().map_err(|_| StateError::StateUnavailable)?;
        Self::from_connection(db)
    }
    /// Opens or creates a durable SQLite state database.
    ///
    /// Opening a handle never performs restart recovery. The daemon process must call
    /// [`Self::recover_after_restart`] exactly once before accepting work.
    pub fn open(path: &Path) -> Result<Self, StateError> {
        let db = Connection::open(path).map_err(|_| StateError::StateUnavailable)?;
        Self::from_connection(db)
    }
    fn from_connection(db: Connection) -> Result<Self, StateError> {
        db.busy_timeout(Duration::from_secs(5))
            .map_err(|_| StateError::StateUnavailable)?;
        db.execute_batch("PRAGMA foreign_keys=ON;")
            .map_err(|_| StateError::StateUnavailable)?;
        init_schema(&db)?;
        Ok(Self {
            db: Mutex::new(db),
            catalog: Mutex::new(HashMap::new()),
        })
    }
    /// Registers metadata from a trusted internal provider/catalog harness.
    pub fn register_item(&self, descriptor: ItemDescriptor) -> Result<(), StateError> {
        let checked = ItemDescriptor::new(
            descriptor.item_id,
            descriptor.revision,
            descriptor.kind,
            descriptor.login_components,
        )?;
        let mut catalog = self
            .catalog
            .lock()
            .map_err(|_| StateError::StateUnavailable)?;
        if let Some(old) = catalog.get(checked.item_id.as_str()) {
            if old.revision == checked.revision && old != &checked {
                return Err(StateError::Unsupported);
            }
        }
        catalog.insert(checked.item_id.as_str().to_owned(), checked);
        drop(catalog);
        Ok(())
    }
    /// Opens a capability for a peer. Socket permissions provide the same-UID boundary in M0.
    pub fn open_session(&self, uid: u32) -> Result<SessionCapability, StateError> {
        let value = format!("ses_{}", Uuid::new_v4().simple());
        let db = self.db.lock().map_err(|_| StateError::StateUnavailable)?;
        db.execute(
            "INSERT INTO sessions(capability_digest,uid) VALUES (?1,?2)",
            params![session_digest(&value).as_slice(), i64::from(uid)],
        )
        .map_err(|_| StateError::StateUnavailable)?;
        drop(db);
        Ok(SessionCapability::new(value))
    }
    fn authorize(&self, session: &SessionCapability) -> Result<(), StateError> {
        self.authorize_for_peer(session, None)
    }
    fn authorize_for_peer(
        &self,
        session: &SessionCapability,
        uid: Option<u32>,
    ) -> Result<(), StateError> {
        let db = self.db.lock().map_err(|_| StateError::StateUnavailable)?;
        let stored: Option<i64> = db
            .query_row(
                "SELECT uid FROM sessions WHERE capability_digest=?1",
                params![session_digest(session.as_str()).as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| StateError::StateUnavailable)?;
        drop(db);
        match (stored, uid) {
            (Some(stored), Some(uid)) if stored == i64::from(uid) => Ok(()),
            (Some(_), None) => Ok(()),
            _ => Err(StateError::Unauthorized),
        }
    }
    /// Handles one decoded wire request and persists setup links.
    pub fn handle_request(&self, request: DaemonRequest, handoff_base: &Url) -> DaemonResponse {
        self.handle_request_for_peer_inner(request, handoff_base, None)
    }
    /// Handles a request bound to the UID of its Unix socket peer.
    pub fn handle_request_for_peer(
        &self,
        request: DaemonRequest,
        handoff_base: &Url,
        uid: u32,
    ) -> DaemonResponse {
        self.handle_request_for_peer_inner(request, handoff_base, Some(uid))
    }
    fn handle_request_for_peer_inner(
        &self,
        request: DaemonRequest,
        handoff_base: &Url,
        peer_uid: Option<u32>,
    ) -> DaemonResponse {
        match request {
            DaemonRequest::Health => DaemonResponse::Healthy {
                protocol_version: intentkey_core::PROTOCOL_VERSION,
            },
            DaemonRequest::OpenSession => match self.open_session(peer_uid.unwrap_or(0)) {
                Ok(session) => DaemonResponse::SessionOpened { session },
                Err(error) => rejected_state(error),
            },
            DaemonRequest::ListItems { session } => {
                match self.authorize_for_peer(&session, peer_uid).and_then(|()| {
                    self.catalog
                        .lock()
                        .map(|c| c.values().cloned().collect())
                        .map_err(|_| StateError::StateUnavailable)
                }) {
                    Ok(items) => DaemonResponse::ItemsListed { items },
                    Err(error) => rejected_state(error),
                }
            }
            DaemonRequest::PrepareUse(input) => match self
                .authorize_for_peer(&input.session, peer_uid)
                .and_then(|()| unix_epoch_ms().map_err(StateError::Protocol))
                .and_then(|now| self.prepare_use(input, now))
            {
                Ok((link, expires_at_ms)) => DaemonResponse::UsePrepared {
                    link,
                    expires_at_ms,
                },
                Err(error) => rejected_state(error),
            },
            DaemonRequest::ExecuteUse(input) => match self
                .authorize_for_peer(&input.session, peer_uid)
                .and_then(|()| unix_epoch_ms().map_err(StateError::Protocol))
                .and_then(|now| self.execute_use(input, now))
            {
                Ok(receipt) => DaemonResponse::OperationAccepted { receipt },
                Err(error) => rejected_state(error),
            },
            DaemonRequest::InspectOperation(input) => match self
                .authorize_for_peer(&input.session, peer_uid)
                .and_then(|()| self.receipt_for_session(&input.operation_ref, &input.session))
            {
                Ok(receipt) => DaemonResponse::OperationInspected { receipt },
                Err(error) => rejected_state(error),
            },
            DaemonRequest::CancelOperation(input) => match self
                .authorize_for_peer(&input.session, peer_uid)
                .and_then(|()| unix_epoch_ms().map_err(StateError::Protocol))
                .and_then(|now| self.cancel_for_session(&input.operation_ref, &input.session, now))
            {
                Ok(receipt) => DaemonResponse::OperationCanceled { receipt },
                Err(error) => rejected_state(error),
            },
            DaemonRequest::CreateSetup(input) => match unix_epoch_ms()
                .map_err(StateError::Protocol)
                .and_then(|now| self.issue_setup(input, now, handoff_base))
            {
                Ok(grant) => DaemonResponse::SetupCreated { grant },
                Err(error) => rejected_state(error),
            },
        }
    }
    /// Issues and stores a setup link while retaining only its ticket digest.
    pub fn issue_setup(
        &self,
        input: SetupRequest,
        now_ms: u64,
        handoff_base: &Url,
    ) -> Result<SetupGrant, StateError> {
        validate_target(&input.intent.target)?;
        let admission = SetupAdmission {
            intent: input.intent.clone(),
            kind: input.kind,
        };
        let grant = issue_setup_claim(input, now_ms, handoff_base)?;
        let data = serde_json::to_string(&admission).map_err(|_| StateError::StateUnavailable)?;
        let db = self.db.lock().map_err(|_| StateError::StateUnavailable)?;
        let tx = immediate_transaction(&db)?;
        tx.execute(
            "INSERT INTO setup_links VALUES (?1,?2,?3,0)",
            params![
                ticket_digest(grant.claim_id.as_str()).as_slice(),
                data,
                i64::try_from(grant.expires_at_ms).map_err(|_| StateError::StateUnavailable)?
            ],
        )
        .map_err(|_| StateError::StateUnavailable)?;
        tx.commit().map_err(|_| StateError::StateUnavailable)?;
        drop(db);
        Ok(grant)
    }
    /// Prepares a fixed item authorization and stores only its ticket digest and metadata.
    pub fn prepare_use(
        &self,
        input: PrepareUseRequest,
        now_ms: u64,
    ) -> Result<(UseLink, u64), StateError> {
        self.authorize(&input.session)?;
        if input.ttl_ms == 0 || input.ttl_ms > MAX_USE_TTL_MS {
            return Err(StateError::Protocol(ProtocolError::InvalidTtl));
        }
        validate_target(&input.intent.target)?;
        let item = self
            .catalog
            .lock()
            .map_err(|_| StateError::StateUnavailable)?
            .get(input.item_id.as_str())
            .cloned()
            .ok_or(StateError::Unsupported)?;
        if item.revision != input.revision || item.kind != operation_kind(input.operation) {
            return Err(StateError::Unsupported);
        }
        if expected_action(input.operation) != input.intent.action {
            return Err(StateError::Unsupported);
        }
        match (input.operation, input.selected_component.as_ref()) {
            (UseOperation::Login(login), Some(selected)) => {
                let component = item
                    .login_components
                    .iter()
                    .find(|c| &c.id == selected)
                    .ok_or(StateError::Unsupported)?;
                if component.provider_presence != intentkey_core::ComponentPresence::Stored
                    || component.operation_support != intentkey_core::OperationSupport::Supported
                    || !component_matches(component.kind, login)
                {
                    return Err(StateError::Unsupported);
                }
            }
            (UseOperation::Login(_), None) | (_, Some(_)) => return Err(StateError::Unsupported),
            (_, None) => {}
        }
        let expires = now_ms
            .checked_add(input.ttl_ms)
            .ok_or(StateError::StateUnavailable)?;
        let ticket = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let link = UseLink::from_ticket(&ticket)?;
        let data = serde_json::to_string(&UseRequest {
            item_id: input.item_id,
            intent: input.intent,
            operation: input.operation,
            revision: item.revision,
            login_components: item.login_components,
            selected_component: input.selected_component,
        })
        .map_err(|_| StateError::StateUnavailable)?;
        let db = self.db.lock().map_err(|_| StateError::StateUnavailable)?;
        db.execute("INSERT INTO use_links(ticket_digest,session_digest,request,revision,expires_at_ms,operation_ref,consumed) VALUES(?1,?2,?3,?4,?5,NULL,0)", params![ticket_digest(&ticket).as_slice(), session_digest(input.session.as_str()).as_slice(), data, i64::try_from(input.revision).map_err(|_| StateError::StateUnavailable)?, i64::try_from(expires).map_err(|_| StateError::StateUnavailable)?]).map_err(|_| StateError::StateUnavailable)?;
        drop(db);
        Ok((link, expires))
    }
    /// Consumes a prepared link once and atomically queues its exact operation.
    pub fn execute_use(
        &self,
        input: ExecuteUseRequest,
        now_ms: u64,
    ) -> Result<OperationReceipt, StateError> {
        let ExecuteUseRequest { session, link } = input;
        self.authorize(&session)?;
        let db = self.db.lock().map_err(|_| StateError::StateUnavailable)?;
        let tx = immediate_transaction(&db)?;
        let digest = ticket_digest(link.ticket());
        let row: Option<PreparedLinkRow> = tx
            .query_row(
                "SELECT request,expires_at_ms,consumed,operation_ref,revision FROM use_links WHERE ticket_digest=?1 AND session_digest=?2",
                params![digest.as_slice(), session_digest(session.as_str()).as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .optional()
            .map_err(|_| StateError::StateUnavailable)?;
        let (data, expiry, consumed, operation, revision) = row.ok_or(StateError::Unauthorized)?;
        if let Some(reference) = operation {
            return load_tx(&tx, &reference);
        }
        if consumed != 0 {
            return Err(StateError::TicketConsumed);
        }
        if expiry < 0
            || now_ms >= u64::try_from(expiry).map_err(|_| StateError::StateUnavailable)?
        {
            return Err(StateError::Expired);
        }
        let request: UseRequest =
            serde_json::from_str(&data).map_err(|_| StateError::StateUnavailable)?;
        validate_target(&request.intent.target)?;
        let current_revision = self
            .catalog
            .lock()
            .map_err(|_| StateError::StateUnavailable)?
            .get(request.item_id.as_str())
            .map(|item| item.revision)
            .ok_or(StateError::Unsupported)?;
        if i64::try_from(current_revision).map_err(|_| StateError::StateUnavailable)? != revision {
            return Err(StateError::Unsupported);
        }
        if let Some(item) = self
            .catalog
            .lock()
            .map_err(|_| StateError::StateUnavailable)?
            .get(request.item_id.as_str())
        {
            if item.revision != request.revision
                || item.login_components != request.login_components
                || item.kind != operation_kind(request.operation)
            {
                return Err(StateError::Unsupported);
            }
        }
        let request_id = format!("req_{}", Uuid::new_v4().simple());
        let reference = format!("op_{}", Uuid::new_v4().simple());
        let receipt = OperationReceipt {
            operation_ref: reference.clone(),
            request_id: request_id.clone(),
            item_id: request.item_id.clone(),
            operation_kind: request.operation,
            revision: request.revision,
            selected_component: request.selected_component.clone(),
            login_components: request.login_components.clone(),
            target: request.intent.target,
            outcome: OperationOutcome::Queued,
            started_at_ms: now_ms,
            completed_at_ms: None,
        };
        let receipt_data =
            serde_json::to_string(&receipt).map_err(|_| StateError::StateUnavailable)?;
        tx.execute(
            "INSERT INTO requests VALUES (?1,?2,?3,?4)",
            params![request_id, data, expiry, reference],
        )
        .map_err(|_| StateError::StateUnavailable)?;
        tx.execute(
            "INSERT INTO operations VALUES (?1,?2)",
            params![receipt.operation_ref, receipt_data],
        )
        .map_err(|_| StateError::StateUnavailable)?;
        tx.execute(
            "INSERT INTO dispatch_outbox(operation_ref,state) VALUES (?1,'pending')",
            params![receipt.operation_ref],
        )
        .map_err(|_| StateError::StateUnavailable)?;
        let consumed_rows = tx
            .execute(
                "UPDATE use_links SET consumed=1,operation_ref=?1 WHERE ticket_digest=?2 AND session_digest=?3 AND consumed=0",
                params![receipt.operation_ref, digest.as_slice(), session_digest(session.as_str()).as_slice()],
            )
            .map_err(|_| StateError::StateUnavailable)?;
        if consumed_rows != 1 {
            return Err(StateError::TicketConsumed);
        }
        tx.commit().map_err(|_| StateError::StateUnavailable)?;
        drop(db);
        Ok(receipt)
    }
    /// Cancels queued work without invoking an executor.
    pub fn cancel(&self, reference: &str, now_ms: u64) -> Result<OperationReceipt, StateError> {
        let db = self.db.lock().map_err(|_| StateError::StateUnavailable)?;
        let tx = immediate_transaction(&db)?;
        let mut receipt = load_tx(&tx, reference)?;
        if receipt.outcome != OperationOutcome::Queued {
            return Err(StateError::InvalidTransition);
        }
        remove_outbox_tx(&tx, reference, "pending")?;
        receipt.outcome = OperationOutcome::Canceled;
        receipt.completed_at_ms = Some(now_ms);
        save_tx(&tx, &receipt)?;
        tx.commit().map_err(|_| StateError::StateUnavailable)?;
        drop(db);
        Ok(receipt)
    }

    /// Atomically consumes a setup ticket exactly once.
    pub fn consume_setup_ticket(
        &self,
        ticket: &str,
        now_ms: u64,
    ) -> Result<SetupAdmission, StateError> {
        let db = self.db.lock().map_err(|_| StateError::StateUnavailable)?;
        let tx = immediate_transaction(&db)?;
        let digest = ticket_digest(ticket);
        let row: Option<(String, i64, i64)> = tx
            .query_row(
                "SELECT admission,expires_at_ms,consumed FROM setup_links WHERE ticket_digest=?1",
                params![digest.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(|_| StateError::StateUnavailable)?;
        let (data, expires, consumed) = row.ok_or(StateError::InvalidTicket)?;
        if expires < 0
            || now_ms >= u64::try_from(expires).map_err(|_| StateError::StateUnavailable)?
        {
            return Err(StateError::Expired);
        }
        if consumed != 0 {
            return Err(StateError::TicketConsumed);
        }
        let admission: SetupAdmission =
            serde_json::from_str(&data).map_err(|_| StateError::StateUnavailable)?;
        let consumed_rows = tx
            .execute(
                "UPDATE setup_links SET consumed=1 WHERE ticket_digest=?1 AND consumed=0",
                params![digest.as_slice()],
            )
            .map_err(|_| StateError::StateUnavailable)?;
        if consumed_rows != 1 {
            return Err(StateError::TicketConsumed);
        }
        tx.commit().map_err(|_| StateError::StateUnavailable)?;
        drop(db);
        Ok(admission)
    }
    /// Admits a use request or returns the existing operation for an identical request ID.
    pub fn queue_use(
        &self,
        request_id: &str,
        request: &UseRequest,
        expires_at_ms: u64,
        now_ms: u64,
    ) -> Result<OperationReceipt, StateError> {
        validate_request_id(request_id)?;
        validate_target(&request.intent.target)?;
        if expires_at_ms <= now_ms {
            return Err(StateError::Expired);
        }
        let db = self.db.lock().map_err(|_| StateError::StateUnavailable)?;
        let tx = immediate_transaction(&db)?;
        if let Some((data, expiry, reference)) = tx
            .query_row(
                "SELECT request,expires_at_ms,operation_ref FROM requests WHERE request_id=?1",
                params![request_id],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| StateError::StateUnavailable)?
        {
            let old: UseRequest =
                serde_json::from_str(&data).map_err(|_| StateError::StateUnavailable)?;
            if old != *request
                || expiry < 0
                || u64::try_from(expiry).map_err(|_| StateError::StateUnavailable)? != expires_at_ms
            {
                return Err(StateError::IdempotencyConflict);
            }
            return load_tx(&tx, &reference);
        }
        let reference = format!("op_{}", Uuid::new_v4().simple());
        let receipt = OperationReceipt {
            operation_ref: reference.clone(),
            request_id: request_id.to_owned(),
            item_id: request.item_id.clone(),
            operation_kind: request.operation,
            revision: request.revision,
            selected_component: request.selected_component.clone(),
            login_components: request.login_components.clone(),
            target: request.intent.target.clone(),
            outcome: OperationOutcome::Queued,
            started_at_ms: now_ms,
            completed_at_ms: None,
        };
        let request_data =
            serde_json::to_string(&request).map_err(|_| StateError::StateUnavailable)?;
        let receipt_data =
            serde_json::to_string(&receipt).map_err(|_| StateError::StateUnavailable)?;
        tx.execute(
            "INSERT INTO requests VALUES (?1,?2,?3,?4)",
            params![
                request_id,
                request_data,
                i64::try_from(expires_at_ms).map_err(|_| StateError::StateUnavailable)?,
                reference
            ],
        )
        .map_err(|_| StateError::StateUnavailable)?;
        tx.execute(
            "INSERT INTO operations VALUES (?1,?2)",
            params![receipt.operation_ref, receipt_data],
        )
        .map_err(|_| StateError::StateUnavailable)?;
        tx.execute(
            "INSERT INTO dispatch_outbox(operation_ref,state) VALUES (?1,'pending')",
            params![receipt.operation_ref],
        )
        .map_err(|_| StateError::StateUnavailable)?;
        tx.commit().map_err(|_| StateError::StateUnavailable)?;
        drop(db);
        Ok(receipt)
    }
    /// Atomically claims queued outbox work before invoking a side-effecting worker.
    pub fn mark_dispatched(
        &self,
        operation_ref: &str,
        now_ms: u64,
    ) -> Result<OperationReceipt, StateError> {
        let db = self.db.lock().map_err(|_| StateError::StateUnavailable)?;
        let tx = immediate_transaction(&db)?;
        let mut receipt = load_tx(&tx, operation_ref)?;
        if receipt.outcome != OperationOutcome::Queued {
            return Err(StateError::InvalidTransition);
        }
        let expires_at_ms: i64 = tx
            .query_row(
                "SELECT expires_at_ms FROM requests WHERE operation_ref=?1",
                params![operation_ref],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| StateError::StateUnavailable)?
            .ok_or(StateError::OperationNotFound)?;
        if expires_at_ms < 0
            || now_ms >= u64::try_from(expires_at_ms).map_err(|_| StateError::StateUnavailable)?
        {
            receipt.outcome = OperationOutcome::Expired;
            receipt.completed_at_ms = Some(now_ms);
            remove_outbox_tx(&tx, operation_ref, "pending")?;
            save_tx(&tx, &receipt)?;
            tx.commit().map_err(|_| StateError::StateUnavailable)?;
            drop(db);
            return Err(StateError::Expired);
        }
        let request_data: String = tx
            .query_row(
                "SELECT request FROM requests WHERE operation_ref=?1",
                params![operation_ref],
                |row| row.get(0),
            )
            .map_err(|_| StateError::StateUnavailable)?;
        let admitted: UseRequest =
            serde_json::from_str(&request_data).map_err(|_| StateError::StateUnavailable)?;
        let item = self
            .catalog
            .lock()
            .map_err(|_| StateError::StateUnavailable)?
            .get(admitted.item_id.as_str())
            .cloned()
            .ok_or(StateError::Unsupported)?;
        if item.revision != admitted.revision
            || item.login_components != admitted.login_components
            || item.kind != operation_kind(admitted.operation)
        {
            return Err(StateError::Unsupported);
        }
        let claimed = tx
            .execute(
                "UPDATE dispatch_outbox SET state='claimed',claimed_at_ms=?1 \
                 WHERE operation_ref=?2 AND state='pending'",
                params![
                    i64::try_from(now_ms).map_err(|_| StateError::StateUnavailable)?,
                    operation_ref
                ],
            )
            .map_err(|_| StateError::StateUnavailable)?;
        if claimed != 1 {
            return Err(StateError::InvalidTransition);
        }
        receipt.outcome = OperationOutcome::Dispatched;
        save_tx(&tx, &receipt)?;
        tx.commit().map_err(|_| StateError::StateUnavailable)?;
        drop(db);
        Ok(receipt)
    }
    /// Marks a dispatched operation completed.
    pub fn mark_completed(&self, r: &str, now: u64) -> Result<OperationReceipt, StateError> {
        self.finish(
            r,
            now,
            OperationOutcome::Completed,
            OperationOutcome::Dispatched,
        )
    }
    /// Marks queued work failed before dispatch.
    pub fn mark_failed_before_dispatch(
        &self,
        r: &str,
        now: u64,
    ) -> Result<OperationReceipt, StateError> {
        self.finish(
            r,
            now,
            OperationOutcome::FailedBeforeDispatch,
            OperationOutcome::Queued,
        )
    }
    /// Marks dispatched work failed after side effects could have begun.
    pub fn mark_failed_after_dispatch(
        &self,
        r: &str,
        now: u64,
    ) -> Result<OperationReceipt, StateError> {
        self.finish(
            r,
            now,
            OperationOutcome::FailedAfterDispatch,
            OperationOutcome::Dispatched,
        )
    }
    /// Marks dispatched work with an unknowable result.
    pub fn mark_indeterminate(&self, r: &str, now: u64) -> Result<OperationReceipt, StateError> {
        self.finish(
            r,
            now,
            OperationOutcome::Indeterminate,
            OperationOutcome::Dispatched,
        )
    }
    fn cancel_for_session(
        &self,
        reference: &str,
        session: &SessionCapability,
        now_ms: u64,
    ) -> Result<OperationReceipt, StateError> {
        let db = self.db.lock().map_err(|_| StateError::StateUnavailable)?;
        let tx = immediate_transaction(&db)?;
        let mut receipt = load_tx_for_session(&tx, reference, session)?;
        if receipt.outcome != OperationOutcome::Queued {
            return Err(StateError::InvalidTransition);
        }
        remove_outbox_tx(&tx, reference, "pending")?;
        receipt.outcome = OperationOutcome::Canceled;
        receipt.completed_at_ms = Some(now_ms);
        save_tx(&tx, &receipt)?;
        tx.commit().map_err(|_| StateError::StateUnavailable)?;
        drop(db);
        Ok(receipt)
    }
    /// Returns a metadata-only operation receipt.
    pub fn receipt(&self, r: &str) -> Result<OperationReceipt, StateError> {
        let db = self.db.lock().map_err(|_| StateError::StateUnavailable)?;
        db.query_row(
            "SELECT receipt FROM operations WHERE operation_ref=?1",
            params![r],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|_| StateError::StateUnavailable)?
        .ok_or(StateError::OperationNotFound)
        .and_then(|s| serde_json::from_str(&s).map_err(|_| StateError::StateUnavailable))
    }
    fn receipt_for_session(
        &self,
        reference: &str,
        session: &SessionCapability,
    ) -> Result<OperationReceipt, StateError> {
        let db = self.db.lock().map_err(|_| StateError::StateUnavailable)?;
        load_receipt_db_for_session(&db, reference, session)
    }
    /// Reconciles dispatches interrupted by a daemon restart without retrying side effects.
    ///
    /// Call this exactly once after opening the process-owned database and before accepting
    /// requests. It is deliberately not run by [`Self::open`], because opening another database
    /// handle must not terminate dispatches that are still live in this process.
    pub fn recover_after_restart(&self, now: u64) -> Result<usize, StateError> {
        let db = self.db.lock().map_err(|_| StateError::StateUnavailable)?;
        let tx = immediate_transaction(&db)?;
        let mut stmt = tx
            .prepare(
                "SELECT operations.operation_ref,operations.receipt FROM operations \
                 JOIN dispatch_outbox USING(operation_ref) \
                 WHERE dispatch_outbox.state='claimed'",
            )
            .map_err(|_| StateError::StateUnavailable)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|_| StateError::StateUnavailable)?;
        let mut updates = Vec::new();
        for row in rows {
            let (operation_ref, data) = row.map_err(|_| StateError::StateUnavailable)?;
            let mut receipt: OperationReceipt =
                serde_json::from_str(&data).map_err(|_| StateError::StateUnavailable)?;
            if receipt.outcome != OperationOutcome::Dispatched {
                return Err(StateError::StateUnavailable);
            }
            receipt.outcome = OperationOutcome::Indeterminate;
            receipt.completed_at_ms = Some(now);
            updates.push((operation_ref, receipt));
        }
        drop(stmt);
        for (operation_ref, receipt) in &updates {
            remove_outbox_tx(&tx, operation_ref, "claimed")?;
            save_tx(&tx, receipt)?;
        }
        tx.commit().map_err(|_| StateError::StateUnavailable)?;
        drop(db);
        Ok(updates.len())
    }
    /// Compatibility alias for restart recovery.
    pub fn recover_interrupted(&self, now: u64) -> Result<usize, StateError> {
        self.recover_after_restart(now)
    }
    fn finish(
        &self,
        r: &str,
        now: u64,
        outcome: OperationOutcome,
        expected: OperationOutcome,
    ) -> Result<OperationReceipt, StateError> {
        let db = self.db.lock().map_err(|_| StateError::StateUnavailable)?;
        let tx = immediate_transaction(&db)?;
        let mut rec = load_tx(&tx, r)?;
        if rec.outcome != expected {
            return Err(StateError::InvalidTransition);
        }
        rec.outcome = outcome;
        rec.completed_at_ms = Some(now);
        let outbox_state = if expected == OperationOutcome::Queued {
            "pending"
        } else {
            "claimed"
        };
        remove_outbox_tx(&tx, r, outbox_state)?;
        save_tx(&tx, &rec)?;
        tx.commit().map_err(|_| StateError::StateUnavailable)?;
        drop(db);
        Ok(rec)
    }
    #[cfg(test)]
    fn persisted_state(&self) -> String {
        let db = self.db.lock().unwrap_or_else(|_| unreachable!());
        let mut statement = db
            .prepare("SELECT hex(ticket_digest) FROM setup_links")
            .unwrap_or_else(|_| unreachable!());
        let result = statement
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap_or_else(|_| unreachable!())
            .collect::<Result<Vec<_>, _>>()
            .unwrap_or_else(|_| unreachable!())
            .join(" ");
        drop(statement);
        drop(db);
        result
    }
}
const SCHEMA_VERSION: u32 = 2;

fn init_schema(db: &Connection) -> Result<(), StateError> {
    let version: u32 = db
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|_| StateError::StateUnavailable)?;
    if version > SCHEMA_VERSION {
        return Err(StateError::StateUnavailable);
    }

    let tx = immediate_transaction(db)?;
    if version == 0 {
        tx.execute_batch(
            "CREATE TABLE IF NOT EXISTS setup_links(\
                 ticket_digest BLOB PRIMARY KEY,admission TEXT NOT NULL,\
                 expires_at_ms INTEGER NOT NULL,consumed INTEGER NOT NULL\
             );\
             CREATE TABLE IF NOT EXISTS requests(\
                 request_id TEXT PRIMARY KEY,request TEXT NOT NULL,\
                 expires_at_ms INTEGER NOT NULL,operation_ref TEXT NOT NULL UNIQUE\
             );\
             CREATE TABLE IF NOT EXISTS operations(\
                 operation_ref TEXT PRIMARY KEY,receipt TEXT NOT NULL\
             );\
             CREATE TABLE IF NOT EXISTS sessions(\
                 capability_digest BLOB PRIMARY KEY,uid INTEGER NOT NULL\
             );\
             CREATE TABLE IF NOT EXISTS use_links(\
                 ticket_digest BLOB PRIMARY KEY,session_digest BLOB NOT NULL,request TEXT NOT NULL,revision INTEGER NOT NULL,expires_at_ms INTEGER NOT NULL,operation_ref TEXT,consumed INTEGER NOT NULL\
             );\
             CREATE TABLE IF NOT EXISTS dispatch_outbox(\
                 operation_ref TEXT PRIMARY KEY REFERENCES operations(operation_ref) ON DELETE CASCADE,\
                 state TEXT NOT NULL CHECK(state IN ('pending','claimed')),\
                 claimed_at_ms INTEGER,\
                 CHECK((state='pending' AND claimed_at_ms IS NULL) OR \
                       (state='claimed' AND claimed_at_ms IS NOT NULL))\
             );",
        )
        .map_err(|_| StateError::StateUnavailable)?;
        validate_schema(&tx)?;

        let existing = {
            let mut statement = tx
                .prepare("SELECT operation_ref,receipt FROM operations")
                .map_err(|_| StateError::StateUnavailable)?;
            let rows = statement
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(|_| StateError::StateUnavailable)?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .map_err(|_| StateError::StateUnavailable)?
        };
        for (operation_ref, data) in existing {
            let receipt: OperationReceipt =
                serde_json::from_str(&data).map_err(|_| StateError::StateUnavailable)?;
            let (state, claimed_at_ms) = match receipt.outcome {
                OperationOutcome::Queued => ("pending", None),
                OperationOutcome::Dispatched => (
                    "claimed",
                    Some(
                        i64::try_from(receipt.started_at_ms)
                            .map_err(|_| StateError::StateUnavailable)?,
                    ),
                ),
                _ => continue,
            };
            tx.execute(
                "INSERT OR IGNORE INTO dispatch_outbox(operation_ref,state,claimed_at_ms) \
                 VALUES (?1,?2,?3)",
                params![operation_ref, state, claimed_at_ms],
            )
            .map_err(|_| StateError::StateUnavailable)?;
        }
        tx.pragma_update(None, "user_version", SCHEMA_VERSION)
            .map_err(|_| StateError::StateUnavailable)?;
    } else {
        validate_schema(&tx)?;
    }
    tx.commit().map_err(|_| StateError::StateUnavailable)
}

fn validate_schema(tx: &Transaction<'_>) -> Result<(), StateError> {
    for query in [
        "SELECT ticket_digest,admission,expires_at_ms,consumed FROM setup_links LIMIT 0",
        "SELECT request_id,request,expires_at_ms,operation_ref FROM requests LIMIT 0",
        "SELECT operation_ref,receipt FROM operations LIMIT 0",
        "SELECT operation_ref,state,claimed_at_ms FROM dispatch_outbox LIMIT 0",
        "SELECT ticket_digest,session_digest,request,revision,expires_at_ms,operation_ref,consumed FROM use_links LIMIT 0",
        "SELECT capability_digest,uid FROM sessions LIMIT 0",
    ] {
        tx.prepare(query)
            .map_err(|_| StateError::StateUnavailable)?;
    }
    Ok(())
}

fn immediate_transaction(db: &Connection) -> Result<Transaction<'_>, StateError> {
    Transaction::new_unchecked(db, TransactionBehavior::Immediate)
        .map_err(|_| StateError::StateUnavailable)
}

fn load_tx_for_session(
    tx: &Transaction<'_>,
    r: &str,
    session: &SessionCapability,
) -> Result<OperationReceipt, StateError> {
    let allowed: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM use_links WHERE operation_ref=?1 AND session_digest=?2)",
            params![r, session_digest(session.as_str()).as_slice()],
            |row| row.get(0),
        )
        .map_err(|_| StateError::StateUnavailable)?;
    if !allowed {
        return Err(StateError::Unauthorized);
    }
    load_tx(tx, r)
}

fn load_tx(tx: &Transaction<'_>, r: &str) -> Result<OperationReceipt, StateError> {
    tx.query_row(
        "SELECT receipt FROM operations WHERE operation_ref=?1",
        params![r],
        |row| row.get::<_, String>(0),
    )
    .optional()
    .map_err(|_| StateError::StateUnavailable)?
    .ok_or(StateError::OperationNotFound)
    .and_then(|s| serde_json::from_str(&s).map_err(|_| StateError::StateUnavailable))
}

fn save_tx(tx: &Transaction<'_>, receipt: &OperationReceipt) -> Result<(), StateError> {
    let data = serde_json::to_string(receipt).map_err(|_| StateError::StateUnavailable)?;
    let updated = tx
        .execute(
            "UPDATE operations SET receipt=?1 WHERE operation_ref=?2",
            params![data, receipt.operation_ref],
        )
        .map_err(|_| StateError::StateUnavailable)?;
    if updated != 1 {
        return Err(StateError::OperationNotFound);
    }
    Ok(())
}

fn remove_outbox_tx(
    tx: &Transaction<'_>,
    operation_ref: &str,
    expected_state: &str,
) -> Result<(), StateError> {
    let removed = tx
        .execute(
            "DELETE FROM dispatch_outbox WHERE operation_ref=?1 AND state=?2",
            params![operation_ref, expected_state],
        )
        .map_err(|_| StateError::StateUnavailable)?;
    if removed != 1 {
        return Err(StateError::InvalidTransition);
    }
    Ok(())
}

/// Handles one already-decoded daemon request with an ephemeral compatibility store.
pub fn handle_request(request: DaemonRequest, handoff_base: &Url) -> DaemonResponse {
    match DaemonState::new() {
        Ok(state) => state.handle_request(request, handoff_base),
        Err(error) => rejected_state(error),
    }
}

const fn operation_kind(operation: UseOperation) -> intentkey_core::ItemKind {
    match operation {
        UseOperation::Login(_) => intentkey_core::ItemKind::Login,
        UseOperation::Identity => intentkey_core::ItemKind::Identity,
        UseOperation::ApiCredential => intentkey_core::ItemKind::ApiCredential,
        UseOperation::PaymentCard => intentkey_core::ItemKind::PaymentCard,
        UseOperation::SshKey => intentkey_core::ItemKind::SshKey,
        UseOperation::SecureNote => intentkey_core::ItemKind::SecureNote,
    }
}
const fn component_matches(
    kind: intentkey_core::LoginComponentKind,
    login: intentkey_core::LoginUse,
) -> bool {
    matches!(
        (kind, login),
        (
            intentkey_core::LoginComponentKind::Password,
            intentkey_core::LoginUse::Password
        ) | (
            intentkey_core::LoginComponentKind::Totp,
            intentkey_core::LoginUse::Totp
        ) | (
            intentkey_core::LoginComponentKind::Passkey,
            intentkey_core::LoginUse::Passkey
        )
    )
}

const fn expected_action(operation: UseOperation) -> &'static str {
    match operation {
        UseOperation::Login(_) => "sign_in",
        UseOperation::Identity => "identity",
        UseOperation::ApiCredential => "api_credential",
        UseOperation::PaymentCard => "payment_card",
        UseOperation::SshKey => "ssh_key",
        UseOperation::SecureNote => "secure_note",
    }
}

fn load_receipt_db_for_session(
    db: &Connection,
    reference: &str,
    session: &SessionCapability,
) -> Result<OperationReceipt, StateError> {
    let allowed: bool = db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM use_links WHERE operation_ref=?1 AND session_digest=?2)",
            params![reference, session_digest(session.as_str()).as_slice()],
            |row| row.get(0),
        )
        .map_err(|_| StateError::StateUnavailable)?;
    if !allowed {
        return Err(StateError::Unauthorized);
    }
    load_receipt_db(db, reference)
}

fn load_receipt_db(db: &Connection, reference: &str) -> Result<OperationReceipt, StateError> {
    db.query_row(
        "SELECT receipt FROM operations WHERE operation_ref=?1",
        params![reference],
        |r| r.get::<_, String>(0),
    )
    .optional()
    .map_err(|_| StateError::StateUnavailable)?
    .ok_or(StateError::OperationNotFound)
    .and_then(|s| serde_json::from_str(&s).map_err(|_| StateError::StateUnavailable))
}

fn validate_target(target: &TargetOrigin) -> Result<(), StateError> {
    TargetOrigin::parse(target.as_str())?;
    Ok(())
}

fn validate_request_id(request_id: &str) -> Result<(), StateError> {
    let valid = (1..=128).contains(&request_id.len())
        && request_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'));
    if valid {
        Ok(())
    } else {
        Err(StateError::InvalidRequestId)
    }
}

fn session_digest(session: &str) -> [u8; 32] {
    Sha256::digest(session.as_bytes()).into()
}

fn ticket_digest(ticket: &str) -> [u8; 32] {
    Sha256::digest(ticket.as_bytes()).into()
}

fn unix_epoch_ms() -> Result<u64, ProtocolError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ProtocolError::InvalidExpiry)?;
    u64::try_from(elapsed.as_millis()).map_err(|_| ProtocolError::InvalidExpiry)
}

fn rejected_state(error: StateError) -> DaemonResponse {
    match error {
        StateError::Protocol(error) => rejected(error),
        other => DaemonResponse::Rejected {
            code: match other {
                StateError::Unauthorized => RefusalCode::Unauthorized,
                StateError::Unsupported => RefusalCode::Unsupported,
                StateError::Expired => RefusalCode::Expired,
                StateError::IdempotencyConflict
                | StateError::InvalidTransition
                | StateError::TicketConsumed => RefusalCode::Conflict,
                _ => RefusalCode::Internal,
            },
            message: other.to_string(),
        },
    }
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
    use std::sync::{Arc, Barrier};

    use intentkey_core::{
        ComponentId, ComponentPresence, CredentialKind, ExecuteUseRequest, Intent, ItemDescriptor,
        ItemId, ItemKind, LoginComponentKind, LoginComponentMetadata, LoginUse, OperationRequest,
        OperationSupport, PrepareUseRequest, TargetOrigin, UseOperation, UseRequest,
        read_wire_value, write_wire_value,
    };

    use super::*;

    async fn unix_round_trip(state: &DaemonState, request: DaemonRequest) -> DaemonResponse {
        let (mut client, mut server) = tokio::net::UnixStream::pair().expect("stream pair");
        write_wire_value(&mut client, &request)
            .await
            .expect("request");
        let decoded: DaemonRequest = read_wire_value(&mut server).await.expect("decode");
        let response = state.handle_request(
            decoded,
            &Url::parse("http://127.0.0.1:43117/setup").expect("base"),
        );
        write_wire_value(&mut server, &response)
            .await
            .expect("response");
        read_wire_value(&mut client).await.expect("read response")
    }

    fn catalog_item() -> ItemDescriptor {
        ItemDescriptor::new(
            ItemId::new("itm_test"),
            7,
            ItemKind::Login,
            vec![
                LoginComponentMetadata::new(
                    ComponentId::new("cmp_password").expect("component"),
                    LoginComponentKind::Password,
                    ComponentPresence::Stored,
                    OperationSupport::Supported,
                ),
                LoginComponentMetadata::new(
                    ComponentId::new("cmp_totp").expect("component"),
                    LoginComponentKind::Totp,
                    ComponentPresence::Stored,
                    OperationSupport::Supported,
                ),
                LoginComponentMetadata::new(
                    ComponentId::new("cmp_passkey").expect("component"),
                    LoginComponentKind::Passkey,
                    ComponentPresence::Absent,
                    OperationSupport::Supported,
                ),
            ],
        )
        .expect("catalog item")
    }

    #[tokio::test]
    async fn unix_stream_exercises_list_prepare_execute_inspect() {
        let state = DaemonState::new().expect("state");
        state.register_item(catalog_item()).expect("catalog");
        let DaemonResponse::SessionOpened { session } =
            unix_round_trip(&state, DaemonRequest::OpenSession).await
        else {
            panic!("session")
        };
        let DaemonResponse::ItemsListed { items } = unix_round_trip(
            &state,
            DaemonRequest::ListItems {
                session: session.clone(),
            },
        )
        .await
        else {
            panic!("list")
        };
        assert_eq!(items.len(), 1);
        let DaemonResponse::UsePrepared { link, .. } = unix_round_trip(
            &state,
            DaemonRequest::PrepareUse(PrepareUseRequest {
                session: session.clone(),
                item_id: ItemId::new("itm_test"),
                revision: 7,
                intent: use_request().intent,
                operation: UseOperation::Login(LoginUse::Password),
                selected_component: Some(ComponentId::new("cmp_password").expect("component")),
                ttl_ms: 60_000,
            }),
        )
        .await
        else {
            panic!("prepare")
        };
        let DaemonResponse::OperationAccepted { receipt } = unix_round_trip(
            &state,
            DaemonRequest::ExecuteUse(ExecuteUseRequest {
                session: session.clone(),
                link,
            }),
        )
        .await
        else {
            panic!("execute")
        };
        let inspected = unix_round_trip(
            &state,
            DaemonRequest::InspectOperation(OperationRequest {
                session,
                operation_ref: receipt.operation_ref,
            }),
        )
        .await;
        assert!(matches!(
            inspected,
            DaemonResponse::OperationInspected { .. }
        ));
    }

    #[test]
    fn malformed_origin_and_nested_unknown_field_are_rejected() {
        assert!(serde_json::from_str::<DaemonRequest>(r#"{"op":"create_setup","input":{"intent":{"action":"sign_in","target":"file:///tmp/x"},"kind":"login","ttl_ms":1}}"#).is_err());
        assert!(serde_json::from_str::<DaemonRequest>(r#"{"op":"create_setup","input":{"intent":{"action":"sign_in","target":"https://example.com/","extra":true},"kind":"login","ttl_ms":1}}"#).is_err());
    }

    #[test]
    fn other_session_cannot_retarget_or_inspect_operation() {
        let state = DaemonState::new().expect("state");
        state.register_item(catalog_item()).expect("catalog");
        let owner = state.open_session(0).expect("owner");
        let other = state.open_session(0).expect("other");
        let (link, _) = state
            .prepare_use(
                PrepareUseRequest {
                    session: owner.clone(),
                    item_id: ItemId::new("itm_test"),
                    revision: 7,
                    intent: use_request().intent,
                    operation: UseOperation::Login(LoginUse::Password),
                    selected_component: Some(ComponentId::new("cmp_password").expect("component")),
                    ttl_ms: 1_000,
                },
                1_000,
            )
            .expect("prepare");
        assert_eq!(
            state.execute_use(
                ExecuteUseRequest {
                    session: other.clone(),
                    link: link.clone()
                },
                1_001
            ),
            Err(StateError::Unauthorized)
        );
        let receipt = state
            .execute_use(
                ExecuteUseRequest {
                    session: owner,
                    link,
                },
                1_001,
            )
            .expect("execute");
        assert_eq!(
            state.receipt_for_session(&receipt.operation_ref, &other),
            Err(StateError::Unauthorized)
        );
    }

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
            DaemonRequest::CreateSetup(setup_request()),
            &Url::parse("http://127.0.0.1:43117/setup").expect("valid base"),
        );

        let DaemonResponse::SetupCreated { grant } = response else {
            panic!("expected setup grant");
        };
        assert_eq!(grant.max_uses, 1);
        assert!(grant.handoff_url.query().is_none());
        assert!(grant.handoff_url.fragment().is_some());
    }

    fn setup_request() -> SetupRequest {
        SetupRequest {
            intent: Intent {
                action: "account_signup".to_owned(),
                target: TargetOrigin::parse("https://github.com").expect("valid origin"),
            },
            kind: CredentialKind::Login,
            ttl_ms: 60_000,
        }
    }

    fn use_request() -> UseRequest {
        let item = catalog_item();
        UseRequest {
            item_id: item.item_id,
            intent: Intent {
                action: "sign_in".to_owned(),
                target: TargetOrigin::parse("https://github.com").expect("valid origin"),
            },
            operation: UseOperation::Login(LoginUse::Password),
            revision: item.revision,
            login_components: item.login_components,
            selected_component: Some(ComponentId::new("cmp_password").expect("component")),
        }
    }

    #[test]
    fn setup_ticket_is_stored_only_as_a_digest_and_consumed_once() {
        let daemon = DaemonState::new().expect("in-memory database initializes");
        let grant = daemon
            .issue_setup(
                setup_request(),
                1_000,
                &Url::parse("http://127.0.0.1:43117/setup").expect("valid base"),
            )
            .expect("setup issued");

        assert!(!daemon.persisted_state().contains(grant.claim_id.as_str()));
        let admission = daemon
            .consume_setup_ticket(grant.claim_id.as_str(), 1_001)
            .expect("first consume succeeds");
        assert_eq!(admission.intent.target.as_str(), "https://github.com/");
        assert_eq!(
            daemon.consume_setup_ticket(grant.claim_id.as_str(), 1_002),
            Err(StateError::TicketConsumed)
        );
    }

    #[test]
    fn expired_setup_ticket_cannot_be_consumed() {
        let daemon = DaemonState::new().expect("in-memory database initializes");
        let mut request = setup_request();
        request.ttl_ms = 10;
        let grant = daemon
            .issue_setup(
                request,
                1_000,
                &Url::parse("http://127.0.0.1:43117/setup").expect("valid base"),
            )
            .expect("setup issued");

        assert_eq!(
            daemon.consume_setup_ticket(grant.claim_id.as_str(), 1_010),
            Err(StateError::Expired)
        );
    }

    #[test]
    fn concurrent_ticket_consumption_has_exactly_one_winner() {
        let daemon = Arc::new(DaemonState::new().expect("in-memory database initializes"));
        let grant = daemon
            .issue_setup(
                setup_request(),
                1_000,
                &Url::parse("http://127.0.0.1:43117/setup").expect("valid base"),
            )
            .expect("setup issued");
        let ticket = Arc::new(grant.claim_id.as_str().to_owned());
        let barrier = Arc::new(Barrier::new(9));
        let mut threads = Vec::new();
        for _ in 0..8 {
            let daemon = Arc::clone(&daemon);
            let ticket = Arc::clone(&ticket);
            let barrier = Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                daemon.consume_setup_ticket(&ticket, 1_001).is_ok()
            }));
        }
        barrier.wait();

        let winners = threads
            .into_iter()
            .map(|thread| thread.join().expect("consumer did not panic"))
            .filter(|won| *won)
            .count();
        assert_eq!(winners, 1);
    }

    #[test]
    fn request_id_is_idempotent_and_cannot_change_payload() {
        let daemon = DaemonState::new().expect("in-memory database initializes");
        daemon.register_item(catalog_item()).expect("catalog");
        let first = daemon
            .queue_use("req_1", &use_request(), 2_000, 1_000)
            .expect("request queued");
        let duplicate = daemon
            .queue_use("req_1", &use_request(), 2_000, 1_100)
            .expect("duplicate returns original operation");
        assert_eq!(duplicate, first);

        let mut changed = use_request();
        changed.item_id = ItemId::new("itm_other");
        assert_eq!(
            daemon.queue_use("req_1", &changed, 2_000, 1_100),
            Err(StateError::IdempotencyConflict)
        );
    }

    #[test]
    fn dispatched_work_is_not_requeued_and_recovers_as_indeterminate() {
        let daemon = DaemonState::new().expect("in-memory database initializes");
        daemon.register_item(catalog_item()).expect("catalog");
        let queued = daemon
            .queue_use("req_1", &use_request(), 2_000, 1_000)
            .expect("request queued");
        assert_eq!(queued.outcome, OperationOutcome::Queued);

        let dispatched = daemon
            .mark_dispatched(&queued.operation_ref, 1_010)
            .expect("operation dispatched");
        assert_eq!(dispatched.outcome, OperationOutcome::Dispatched);
        assert_eq!(
            daemon.queue_use("req_1", &use_request(), 2_000, 1_020),
            Ok(dispatched)
        );

        assert_eq!(daemon.recover_interrupted(1_030), Ok(1));
        let recovered = daemon
            .receipt(&queued.operation_ref)
            .expect("receipt retained");
        assert_eq!(recovered.outcome, OperationOutcome::Indeterminate);
        assert_eq!(recovered.completed_at_ms, Some(1_030));
    }

    #[test]
    fn durable_state_survives_sqlite_reopen_and_recovers_dispatch() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let database = directory.path().join("daemon.sqlite3");
        let handoff_base = Url::parse("http://127.0.0.1:43117/setup").expect("valid base");

        let daemon = DaemonState::open(&database).expect("database opens");
        daemon.register_item(catalog_item()).expect("catalog");
        let prepared = daemon
            .issue_setup(setup_request(), 1_000, &handoff_base)
            .expect("prepared ticket persisted");
        let consumed = daemon
            .issue_setup(setup_request(), 1_000, &handoff_base)
            .expect("consumed ticket persisted");
        daemon
            .consume_setup_ticket(consumed.claim_id.as_str(), 1_001)
            .expect("ticket consumed");

        let queued = daemon
            .queue_use("req_queued", &use_request(), 2_000, 1_000)
            .expect("operation queued");
        let dispatched = daemon
            .queue_use("req_dispatched", &use_request(), 2_000, 1_000)
            .expect("operation queued");
        daemon
            .mark_dispatched(&dispatched.operation_ref, 1_010)
            .expect("dispatch recorded before side effect");
        drop(daemon);

        let reopened = DaemonState::open(&database).expect("database reopens");
        reopened
            .consume_setup_ticket(prepared.claim_id.as_str(), 1_020)
            .expect("prepared ticket survives reopen");
        assert_eq!(
            reopened.consume_setup_ticket(consumed.claim_id.as_str(), 1_020),
            Err(StateError::TicketConsumed)
        );
        assert_eq!(
            reopened
                .receipt(&queued.operation_ref)
                .expect("queued operation survives")
                .outcome,
            OperationOutcome::Queued
        );
        assert_eq!(
            reopened
                .receipt(&dispatched.operation_ref)
                .expect("dispatch state survives")
                .outcome,
            OperationOutcome::Dispatched
        );

        assert_eq!(reopened.recover_interrupted(1_030), Ok(1));
        let recovered = reopened
            .receipt(&dispatched.operation_ref)
            .expect("recovered receipt survives");
        assert_eq!(recovered.outcome, OperationOutcome::Indeterminate);
        assert_eq!(recovered.completed_at_ms, Some(1_030));
        assert_eq!(
            reopened.queue_use("req_dispatched", &use_request(), 2_000, 1_040),
            Ok(recovered)
        );
    }

    #[test]
    fn receipts_serialize_as_metadata_only() {
        let daemon = DaemonState::new().expect("in-memory database initializes");
        daemon.register_item(catalog_item()).expect("catalog");
        let receipt = daemon
            .queue_use("req_1", &use_request(), 2_000, 1_000)
            .expect("request queued");
        let value = serde_json::to_value(receipt).expect("receipt serializes");
        assert_eq!(
            value
                .as_object()
                .expect("receipt object")
                .keys()
                .collect::<Vec<_>>(),
            [
                "completed_at_ms",
                "item_id",
                "login_components",
                "operation_kind",
                "operation_ref",
                "outcome",
                "request_id",
                "revision",
                "selected_component",
                "started_at_ms",
                "target"
            ]
        );
    }

    #[test]
    fn raw_wire_target_is_rejected_before_daemon_admission() {
        let raw = r#"{"op":"create_setup","input":{"intent":{"action":"account_signup","target":"file:///tmp/probe"},"kind":"login","ttl_ms":1000}}"#;
        assert!(serde_json::from_str::<DaemonRequest>(raw).is_err());
    }

    #[test]
    fn initialization_errors_are_returned_and_schema_is_versioned() {
        let incompatible = Connection::open_in_memory().expect("database opens");
        incompatible
            .execute_batch("CREATE TABLE setup_links(unexpected INTEGER);")
            .expect("incompatible table created");
        assert!(matches!(
            DaemonState::from_connection(incompatible),
            Err(StateError::StateUnavailable)
        ));

        let daemon = DaemonState::new().expect("schema initializes");
        let version: u32 = daemon
            .db
            .lock()
            .expect("database lock")
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("schema version readable");
        assert_eq!(version, SCHEMA_VERSION);
    }

    #[test]
    fn dispatch_is_claimed_once_across_independent_database_handles() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let database = directory.path().join("daemon.sqlite3");
        let first = DaemonState::open(&database).expect("first handle opens");
        let second = DaemonState::open(&database).expect("second handle opens");
        first.register_item(catalog_item()).expect("first catalog");
        second
            .register_item(catalog_item())
            .expect("second catalog");
        let queued = first
            .queue_use("req_concurrent", &use_request(), 2_000, 1_000)
            .expect("request queued");
        let operation_ref = Arc::new(queued.operation_ref);
        let barrier = Arc::new(Barrier::new(3));

        let threads = [first, second].map(|daemon| {
            let operation_ref = Arc::clone(&operation_ref);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                daemon.mark_dispatched(&operation_ref, 1_010)
            })
        });
        barrier.wait();
        let results = threads.map(|thread| thread.join().expect("dispatcher did not panic"));

        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| **result == Err(StateError::InvalidTransition))
                .count(),
            1
        );
    }

    #[test]
    fn terminal_results_are_immutable_even_after_authorization_expiry() {
        let daemon = DaemonState::new().expect("in-memory database initializes");
        daemon.register_item(catalog_item()).expect("catalog");
        let queued = daemon
            .queue_use("req_terminal", &use_request(), 1_020, 1_000)
            .expect("request queued");
        daemon
            .mark_dispatched(&queued.operation_ref, 1_010)
            .expect("first dispatch wins");
        assert_eq!(
            daemon.mark_dispatched(&queued.operation_ref, 1_011),
            Err(StateError::InvalidTransition)
        );
        let completed = daemon
            .mark_completed(&queued.operation_ref, 1_012)
            .expect("operation completes");

        assert_eq!(
            daemon.mark_dispatched(&queued.operation_ref, 1_020),
            Err(StateError::InvalidTransition)
        );
        assert_eq!(daemon.receipt(&queued.operation_ref), Ok(completed));
    }

    #[test]
    fn dispatch_claim_and_receipt_update_roll_back_together() {
        let daemon = DaemonState::new().expect("in-memory database initializes");
        daemon.register_item(catalog_item()).expect("catalog");
        let queued = daemon
            .queue_use("req_rollback", &use_request(), 2_000, 1_000)
            .expect("request queued");
        {
            let db = daemon.db.lock().expect("database lock");
            db.execute_batch(
                "CREATE TRIGGER reject_receipt_update BEFORE UPDATE ON operations \
                 BEGIN SELECT RAISE(ABORT, 'injected update failure'); END;",
            )
            .expect("failure trigger installed");
        }

        assert_eq!(
            daemon.mark_dispatched(&queued.operation_ref, 1_010),
            Err(StateError::StateUnavailable)
        );
        {
            let db = daemon.db.lock().expect("database lock");
            let state: String = db
                .query_row(
                    "SELECT state FROM dispatch_outbox WHERE operation_ref=?1",
                    params![queued.operation_ref],
                    |row| row.get(0),
                )
                .expect("outbox row retained");
            assert_eq!(state, "pending");
            db.execute_batch("DROP TRIGGER reject_receipt_update;")
                .expect("failure trigger removed");
        }
        assert_eq!(
            daemon
                .mark_dispatched(&queued.operation_ref, 1_011)
                .expect("rolled-back claim remains available")
                .outcome,
            OperationOutcome::Dispatched
        );
    }

    #[test]
    fn execute_transaction_rolls_back_link_operation_and_outbox_together() {
        let daemon = DaemonState::new().expect("database initializes");
        let session = daemon.open_session(0).expect("session opens");
        daemon
            .register_item(
                ItemDescriptor::new(
                    ItemId::new("itm_test"),
                    1,
                    ItemKind::Login,
                    vec![LoginComponentMetadata::new(
                        ComponentId::new("cmp_password").expect("component id"),
                        LoginComponentKind::Password,
                        ComponentPresence::Stored,
                        OperationSupport::Supported,
                    )],
                )
                .expect("descriptor valid"),
            )
            .expect("catalog item registers");
        let (link, _) = daemon
            .prepare_use(
                PrepareUseRequest {
                    session: session.clone(),
                    item_id: ItemId::new("itm_test"),
                    revision: 1,
                    intent: use_request().intent,
                    operation: UseOperation::Login(LoginUse::Password),
                    selected_component: Some(ComponentId::new("cmp_password").expect("component")),
                    ttl_ms: 1_000,
                },
                1_000,
            )
            .expect("use prepares");
        {
            let db = daemon.db.lock().expect("database lock");
            db.execute_batch("CREATE TRIGGER reject_outbox BEFORE INSERT ON dispatch_outbox BEGIN SELECT RAISE(ABORT, 'injected'); END;").expect("trigger installs");
        }
        assert_eq!(
            daemon.execute_use(
                ExecuteUseRequest {
                    session: session.clone(),
                    link: link.clone()
                },
                1_001
            ),
            Err(StateError::StateUnavailable)
        );
        {
            let db = daemon.db.lock().expect("database lock");
            let counts: (i64, i64, i64) = (
                db.query_row("SELECT COUNT(*) FROM requests", [], |r| r.get(0))
                    .expect("requests count"),
                db.query_row("SELECT COUNT(*) FROM operations", [], |r| r.get(0))
                    .expect("operations count"),
                db.query_row("SELECT consumed FROM use_links", [], |r| r.get(0))
                    .expect("link state"),
            );
            assert_eq!(counts, (0, 0, 0));
            db.execute_batch("DROP TRIGGER reject_outbox")
                .expect("trigger drops");
        }
        assert!(
            daemon
                .execute_use(ExecuteUseRequest { session, link }, 1_002)
                .is_ok()
        );
    }

    #[test]
    fn operation_actions_are_bound_to_the_preparing_session() {
        let daemon = DaemonState::new().expect("database initializes");
        let owner = daemon.open_session(0).expect("owner session");
        let other = daemon.open_session(0).expect("other session");
        daemon
            .register_item(
                ItemDescriptor::new(
                    ItemId::new("itm_test"),
                    1,
                    ItemKind::Login,
                    vec![LoginComponentMetadata::new(
                        ComponentId::new("cmp_password").expect("id"),
                        LoginComponentKind::Password,
                        ComponentPresence::Stored,
                        OperationSupport::Supported,
                    )],
                )
                .expect("descriptor"),
            )
            .expect("registers");
        let (link, _) = daemon
            .prepare_use(
                PrepareUseRequest {
                    session: owner.clone(),
                    item_id: ItemId::new("itm_test"),
                    revision: 1,
                    intent: use_request().intent,
                    operation: UseOperation::Login(LoginUse::Password),
                    selected_component: Some(ComponentId::new("cmp_password").expect("component")),
                    ttl_ms: 1_000,
                },
                1_000,
            )
            .expect("prepares");
        let receipt = daemon
            .execute_use(
                ExecuteUseRequest {
                    session: owner.clone(),
                    link,
                },
                1_001,
            )
            .expect("executes");
        let handoff = Url::parse("http://127.0.0.1/setup").expect("url");
        for request in [
            DaemonRequest::InspectOperation(OperationRequest {
                session: other.clone(),
                operation_ref: receipt.operation_ref.clone(),
            }),
            DaemonRequest::CancelOperation(OperationRequest {
                session: other,
                operation_ref: receipt.operation_ref.clone(),
            }),
        ] {
            assert!(matches!(
                daemon.handle_request(request, &handoff),
                DaemonResponse::Rejected {
                    code: RefusalCode::Unauthorized,
                    ..
                }
            ));
        }
        assert!(matches!(
            daemon.handle_request(
                DaemonRequest::InspectOperation(OperationRequest {
                    session: owner,
                    operation_ref: receipt.operation_ref
                }),
                &handoff
            ),
            DaemonResponse::OperationInspected { .. }
        ));
    }

    #[test]
    fn selected_component_and_catalog_snapshot_are_strictly_bound() {
        let daemon = DaemonState::new().expect("database initializes");
        let session = daemon.open_session(0).expect("session");
        daemon.register_item(catalog_item()).expect("catalog");
        let make = |selected: Option<&str>, operation, action: &str| PrepareUseRequest {
            session: session.clone(),
            item_id: ItemId::new("itm_test"),
            revision: 7,
            intent: Intent {
                action: action.to_owned(),
                target: TargetOrigin::parse("https://github.com").expect("origin"),
            },
            operation,
            selected_component: selected.map(|id| ComponentId::new(id).expect("id")),
            ttl_ms: 1_000,
        };
        for bad in [
            make(None, UseOperation::Login(LoginUse::Passkey), "sign_in"),
            make(
                Some("missing"),
                UseOperation::Login(LoginUse::Passkey),
                "sign_in",
            ),
            make(
                Some("cmp_passkey"),
                UseOperation::Login(LoginUse::Passkey),
                "sign_in",
            ),
            make(
                Some("cmp_password"),
                UseOperation::Login(LoginUse::Passkey),
                "sign_in",
            ),
            make(
                Some("cmp_passkey"),
                UseOperation::Login(LoginUse::Passkey),
                "arbitrary",
            ),
        ] {
            assert_eq!(daemon.prepare_use(bad, 1_000), Err(StateError::Unsupported));
        }
        let (link, _) = daemon
            .prepare_use(
                make(
                    Some("cmp_password"),
                    UseOperation::Login(LoginUse::Password),
                    "sign_in",
                ),
                1_000,
            )
            .expect("prepare");
        let mut changed = catalog_item();
        changed.revision = 8;
        daemon.register_item(changed).expect("new revision");
        assert_eq!(
            daemon.execute_use(
                ExecuteUseRequest {
                    session: session.clone(),
                    link
                },
                1_001
            ),
            Err(StateError::Unsupported)
        );
        daemon.register_item(catalog_item()).expect("restore");
        let (link, _) = daemon
            .prepare_use(
                make(
                    Some("cmp_password"),
                    UseOperation::Login(LoginUse::Password),
                    "sign_in",
                ),
                1_010,
            )
            .expect("prepare");
        let receipt = daemon
            .execute_use(ExecuteUseRequest { session, link }, 1_011)
            .expect("execute");
        assert_eq!(receipt.revision, 7);
        assert_eq!(
            receipt.selected_component.as_ref().map(ComponentId::as_str),
            Some("cmp_password")
        );
    }

    #[test]
    fn revision_zero_dispatch_rechecks_catalog_snapshot() {
        for change_catalog in [false, true] {
            let daemon = DaemonState::new().expect("database initializes");
            let session = daemon.open_session(0).expect("session");
            let mut item = catalog_item();
            item.revision = 0;
            daemon
                .register_item(item.clone())
                .expect("revision zero catalog");
            let (link, _) = daemon
                .prepare_use(
                    PrepareUseRequest {
                        session: session.clone(),
                        item_id: item.item_id.clone(),
                        revision: 0,
                        intent: use_request().intent,
                        operation: UseOperation::Login(LoginUse::Password),
                        selected_component: Some(ComponentId::new("cmp_password").expect("id")),
                        ttl_ms: 1_000,
                    },
                    1_000,
                )
                .expect("revision zero prepares");
            let queued = daemon
                .execute_use(ExecuteUseRequest { session, link }, 1_001)
                .expect("revision zero executes");
            assert_eq!(queued.revision, 0);
            assert_eq!(queued.outcome, OperationOutcome::Queued);
            if change_catalog {
                item.revision = 1;
                item.login_components[0].provider_presence = ComponentPresence::Absent;
                daemon
                    .register_item(item)
                    .expect("new revision without password");
                assert_eq!(
                    daemon.mark_dispatched(&queued.operation_ref, 1_002),
                    Err(StateError::Unsupported)
                );
                assert_eq!(daemon.receipt(&queued.operation_ref), Ok(queued.clone()));
                let outbox: (String, Option<i64>) = daemon
                    .db
                    .lock()
                    .expect("database lock")
                    .query_row(
                        "SELECT state,claimed_at_ms FROM dispatch_outbox WHERE operation_ref=?1",
                        params![queued.operation_ref],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .expect("outbox retained");
                assert_eq!(outbox, ("pending".to_owned(), None));
            } else {
                assert_eq!(
                    daemon
                        .mark_dispatched(&queued.operation_ref, 1_002)
                        .expect("unchanged revision zero dispatches")
                        .outcome,
                    OperationOutcome::Dispatched
                );
            }
        }
    }

    #[test]
    fn raw_session_and_use_ticket_are_not_persisted_in_logical_tables() {
        let daemon = DaemonState::new().expect("database initializes");
        daemon.register_item(catalog_item()).expect("catalog");
        let session = daemon.open_session(0).expect("session");
        let (link, _) = daemon
            .prepare_use(
                PrepareUseRequest {
                    session: session.clone(),
                    item_id: ItemId::new("itm_test"),
                    revision: 7,
                    intent: use_request().intent,
                    operation: UseOperation::Login(LoginUse::Password),
                    selected_component: Some(ComponentId::new("cmp_password").expect("id")),
                    ttl_ms: 1_000,
                },
                1_000,
            )
            .expect("prepare");
        let raw_ticket = link.ticket().to_owned();
        let receipt = daemon
            .execute_use(
                ExecuteUseRequest {
                    session: session.clone(),
                    link,
                },
                1_001,
            )
            .expect("execute");
        assert!(!receipt.request_id.contains(&raw_ticket));
        for query in [
            "SELECT request_id || request || operation_ref FROM requests",
            "SELECT operation_ref || receipt FROM operations",
            "SELECT request || COALESCE(operation_ref,'') FROM use_links",
        ] {
            let text: String = daemon
                .db
                .lock()
                .expect("database")
                .query_row(query, [], |row| row.get(0))
                .expect("logical row");
            assert!(!text.contains(&raw_ticket));
            assert!(!text.contains(session.as_str()));
        }
    }

    #[test]
    fn outbox_is_durable_and_open_does_not_recover_live_dispatches() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let database = directory.path().join("daemon.sqlite3");
        let daemon = DaemonState::open(&database).expect("database opens");
        daemon.register_item(catalog_item()).expect("catalog");
        let queued = daemon
            .queue_use("req_outbox", &use_request(), 2_000, 1_000)
            .expect("request queued");
        drop(daemon);

        let reopened = DaemonState::open(&database).expect("database reopens");
        reopened
            .register_item(catalog_item())
            .expect("reloaded catalog");
        let pending: String = reopened
            .db
            .lock()
            .expect("database lock")
            .query_row(
                "SELECT state FROM dispatch_outbox WHERE operation_ref=?1",
                params![queued.operation_ref],
                |row| row.get(0),
            )
            .expect("durable outbox row");
        assert_eq!(pending, "pending");
        reopened
            .mark_dispatched(&queued.operation_ref, 1_010)
            .expect("outbox item claimed");
        drop(reopened);

        let live_handle = DaemonState::open(&database).expect("another handle opens");
        assert_eq!(
            live_handle
                .receipt(&queued.operation_ref)
                .expect("dispatch remains live")
                .outcome,
            OperationOutcome::Dispatched
        );
        assert_eq!(live_handle.recover_after_restart(1_020), Ok(1));
        assert_eq!(live_handle.recover_after_restart(1_021), Ok(0));
    }
}
