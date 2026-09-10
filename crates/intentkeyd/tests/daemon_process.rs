//! Real-process integration coverage for the intentkey daemon wire boundary.

use std::{
    error::Error,
    fs,
    io::{BufRead, BufReader},
    os::unix::fs::PermissionsExt,
    os::unix::process::ExitStatusExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::mpsc::{self, Receiver},
    time::Duration,
};

use intentkey_core::{
    ComponentId, ComponentPresence, DaemonRequest, DaemonResponse, ExecuteUseRequest, Intent,
    ItemDescriptor, ItemId, ItemKind, LoginComponentKind, LoginComponentMetadata, LoginUse,
    OperationOutcome, OperationReceipt, OperationRequest, OperationSupport, PrepareUseRequest,
    RefusalCode, TargetOrigin, UseOperation, read_wire_value, write_wire_value,
};
use tokio::{io::AsyncWriteExt, net::UnixStream, time::timeout};

const IO_TIMEOUT: Duration = Duration::from_secs(5);
type TestResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

fn private_tempdir() -> TestResult<tempfile::TempDir> {
    Ok(tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()?)
}

struct Daemon {
    child: Option<Child>,
    socket: PathBuf,
    ready: Receiver<Result<(), String>>,
}

impl Daemon {
    fn start(
        dir: &Path,
        catalog: &Path,
        executor_log: Option<&Path>,
        recovery_log: &Path,
    ) -> TestResult<Self> {
        let socket = dir.join("intentkeyd.sock");
        let mut command = Command::new(env!("CARGO_BIN_EXE_intentkeyd"));
        command
            .arg("--socket")
            .arg(&socket)
            .arg("--test-catalog")
            .arg(catalog)
            .arg("--test-recovery-log")
            .arg(recovery_log)
            .env("HOME", fs::canonicalize(dir)?)
            .env("XDG_DATA_HOME", fs::canonicalize(dir)?.join("data"))
            .env("XDG_RUNTIME_DIR", dir)
            .env("RUST_LOG", "intentkeyd=info")
            .stderr(Stdio::piped())
            .stdout(Stdio::null());
        if let Some(path) = executor_log {
            command.arg("--test-executor-log").arg(path);
        }
        let (sender, ready) = mpsc::channel();
        let mut daemon = Self {
            child: Some(command.spawn()?),
            socket,
            ready,
        };
        let stderr = daemon
            .child
            .as_mut()
            .and_then(|child| child.stderr.take())
            .ok_or("daemon stderr is not piped")?;
        std::thread::spawn(move || {
            let mut ready_sent = false;
            let mut startup_output = String::new();
            for line in BufReader::new(stderr).lines() {
                let line = match line {
                    Ok(line) => line,
                    Err(error) => {
                        if !ready_sent {
                            let _ = sender.send(Err(format!(
                                "reading daemon startup stderr failed: {error}\n{startup_output}"
                            )));
                        }
                        return;
                    }
                };
                if !ready_sent {
                    startup_output.push_str(&line);
                    startup_output.push('\n');
                    if line.contains("intentkeyd.ready") {
                        let _ = sender.send(Ok(()));
                        ready_sent = true;
                        startup_output.clear();
                    }
                }
            }
            if !ready_sent {
                let _ = sender.send(Err(format!(
                    "daemon exited before readiness:\n{startup_output}"
                )));
            }
        });
        Ok(daemon)
    }

    fn await_ready(&self) -> TestResult<()> {
        self.ready.recv_timeout(IO_TIMEOUT)??;
        Ok(())
    }

    fn kill_and_reap(&mut self) -> TestResult<()> {
        let child = self.child.as_mut().ok_or("daemon is not running")?;
        child.kill()?;
        let status = child.wait()?;
        assert_eq!(status.signal(), Some(9), "expected SIGKILL: {status}");
        self.child.take();
        Ok(())
    }

    fn stop_gracefully(&mut self) -> TestResult<()> {
        let child = self.child.as_mut().ok_or("daemon is running")?;
        let status = Command::new("kill")
            .args(["-INT", &child.id().to_string()])
            .status()?;
        assert!(status.success(), "kill -INT failed: {status}");
        let status = child.wait()?;
        assert!(status.success(), "daemon exited unsuccessfully: {status}");
        self.child.take();
        Ok(())
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

async fn request(socket: &Path, value: DaemonRequest) -> TestResult<DaemonResponse> {
    let mut stream = timeout(IO_TIMEOUT, UnixStream::connect(socket)).await??;
    timeout(IO_TIMEOUT, write_wire_value(&mut stream, &value)).await??;
    Ok(timeout(IO_TIMEOUT, read_wire_value(&mut stream)).await??)
}

async fn raw_request(socket: &Path, json: &str) -> TestResult<DaemonResponse> {
    let mut stream = timeout(IO_TIMEOUT, UnixStream::connect(socket)).await??;
    let bytes = json.as_bytes();
    let frame_length = u32::try_from(bytes.len())?;
    timeout(IO_TIMEOUT, async {
        stream.write_u32(frame_length).await?;
        stream.write_all(bytes).await?;
        stream.flush().await
    })
    .await??;
    Ok(timeout(IO_TIMEOUT, read_wire_value(&mut stream)).await??)
}

fn catalog() -> TestResult<ItemDescriptor> {
    Ok(ItemDescriptor::new(
        ItemId::new("itm_process"),
        7,
        ItemKind::Login,
        vec![LoginComponentMetadata::new(
            ComponentId::new("cmp_password")?,
            LoginComponentKind::Password,
            ComponentPresence::Stored,
            OperationSupport::Supported,
        )],
    )?)
}

fn intent(target: &str) -> TestResult<Intent> {
    Ok(Intent {
        action: "sign_in".to_owned(),
        target: TargetOrigin::parse(target)?,
    })
}

fn rejected(response: &DaemonResponse, code: RefusalCode) {
    assert!(matches!(response, DaemonResponse::Rejected { code: actual, .. } if *actual == code));
}

async fn test_session_and_catalog(
    socket: &Path,
) -> TestResult<(
    intentkey_core::SessionCapability,
    intentkey_core::SessionCapability,
)> {
    let DaemonResponse::SessionOpened { session } =
        request(socket, DaemonRequest::OpenSession).await?
    else {
        return Err("expected session response".into());
    };
    let DaemonResponse::SessionOpened {
        session: other_session,
    } = request(socket, DaemonRequest::OpenSession).await?
    else {
        return Err("expected second session response".into());
    };
    match request(
        socket,
        DaemonRequest::ListItems {
            session: session.clone(),
        },
    )
    .await?
    {
        DaemonResponse::ItemsListed { items } => {
            assert_eq!(items, vec![catalog()?]);
        }
        _ => return Err("expected catalog response".into()),
    }
    Ok((session, other_session))
}

async fn test_prepare_and_execute(
    socket: &Path,
    session: &intentkey_core::SessionCapability,
    other_session: &intentkey_core::SessionCapability,
) -> TestResult<OperationReceipt> {
    let DaemonResponse::UsePrepared { link, .. } = request(
        socket,
        DaemonRequest::PrepareUse(PrepareUseRequest {
            session: session.clone(),
            item_id: ItemId::new("itm_process"),
            revision: 7,
            intent: intent("https://example.com")?,
            operation: UseOperation::Login(LoginUse::Password),
            selected_component: Some(ComponentId::new("cmp_password")?),
            ttl_ms: 60_000,
        }),
    )
    .await?
    else {
        return Err("expected prepared link response".into());
    };
    rejected(
        &request(
            socket,
            DaemonRequest::ExecuteUse(ExecuteUseRequest {
                session: other_session.clone(),
                link: link.clone(),
            }),
        )
        .await?,
        RefusalCode::Unauthorized,
    );
    let DaemonResponse::OperationAccepted { receipt } = request(
        socket,
        DaemonRequest::ExecuteUse(ExecuteUseRequest {
            session: session.clone(),
            link: link.clone(),
        }),
    )
    .await?
    else {
        return Err("expected accepted operation response".into());
    };
    let duplicate = request(
        socket,
        DaemonRequest::ExecuteUse(ExecuteUseRequest {
            session: session.clone(),
            link,
        }),
    )
    .await?;
    match duplicate {
        DaemonResponse::OperationAccepted { receipt: copy } => {
            assert_eq!(copy.operation_ref, receipt.operation_ref);
            assert_eq!(copy.outcome, OperationOutcome::FailedAfterDispatch);
        }
        _ => return Err("duplicate execute was not idempotent".into()),
    }
    Ok(receipt)
}

async fn test_inspect_operations(
    socket: &Path,
    session: &intentkey_core::SessionCapability,
    other_session: &intentkey_core::SessionCapability,
    operation_ref: &str,
) -> TestResult<()> {
    match request(
        socket,
        DaemonRequest::InspectOperation(OperationRequest {
            session: session.clone(),
            operation_ref: operation_ref.to_owned(),
        }),
    )
    .await?
    {
        DaemonResponse::OperationInspected { receipt: inspected } => {
            assert_eq!(inspected.operation_ref, operation_ref);
            assert_eq!(inspected.outcome, OperationOutcome::FailedAfterDispatch);
        }
        _ => return Err("expected inspected operation response".into()),
    }
    rejected(
        &request(
            socket,
            DaemonRequest::InspectOperation(OperationRequest {
                session: other_session.clone(),
                operation_ref: operation_ref.to_owned(),
            }),
        )
        .await?,
        RefusalCode::Unauthorized,
    );
    Ok(())
}

async fn test_invalid_targets(
    socket: &Path,
    session: &intentkey_core::SessionCapability,
) -> TestResult<()> {
    for target in [
        "file:///tmp/secret",
        "https://example.com/path",
        "https://example.com/?query=1",
        "https://user:pass@example.com/",
    ] {
        let json = format!(
            r#"{{"op":"prepare_use","input":{{"session":"{}","item_id":"itm_process","revision":7,"intent":{{"action":"sign_in","target":"{}"}},"operation":{{"operation":"login","variant":"password"}},"selected_component":"cmp_password","ttl_ms":60000}}}}"#,
            session.as_str(),
            target
        );
        rejected(
            &raw_request(socket, &json).await?,
            RefusalCode::InvalidRequest,
        );
    }
    rejected(
        &raw_request(
            socket,
            &format!(
                r#"{{"op":"prepare_use","input":{{"session":"{}","item_id":"itm_process","revision":7,"intent":{{"action":"sign_in","target":"https://example.com/","unknown":true}},"operation":{{"operation":"login","variant":"password"}},"selected_component":"cmp_password","ttl_ms":60000}}}}"#,
                session.as_str()
            ),
        )
        .await?,
        RefusalCode::InvalidRequest,
    );
    Ok(())
}

async fn test_persistence(
    dir: &Path,
    catalog_path: &Path,
    executor_log: &Path,
    recovery_log: &Path,
    session: &intentkey_core::SessionCapability,
    operation_ref: &str,
) -> TestResult<()> {
    let mut restarted = Daemon::start(dir, catalog_path, Some(executor_log), recovery_log)?;
    restarted.await_ready()?;
    match request(
        &restarted.socket,
        DaemonRequest::InspectOperation(OperationRequest {
            session: session.clone(),
            operation_ref: operation_ref.to_owned(),
        }),
    )
    .await?
    {
        DaemonResponse::OperationInspected { receipt } => {
            assert_eq!(receipt.outcome, OperationOutcome::FailedAfterDispatch);
        }
        _ => return Err("expected persisted operation after restart".into()),
    }
    restarted.stop_gracefully()?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_daemon_process_covers_protocol_authorization_dispatch_and_restart() -> TestResult<()>
{
    let directory = private_tempdir()?;
    let catalog_path = directory.path().join("catalog.json");
    let executor_log = directory.path().join("executor.log");
    let recovery_log = directory.path().join("recovery.log");

    let cat = catalog()?;
    fs::write(&catalog_path, serde_json::to_vec(&vec![cat])?)?;

    let mut daemon = Daemon::start(
        directory.path(),
        &catalog_path,
        Some(&executor_log),
        &recovery_log,
    )?;
    daemon.await_ready()?;

    let (session, other_session) = test_session_and_catalog(&daemon.socket).await?;

    let receipt = test_prepare_and_execute(&daemon.socket, &session, &other_session).await?;

    test_inspect_operations(
        &daemon.socket,
        &session,
        &other_session,
        &receipt.operation_ref,
    )
    .await?;

    test_invalid_targets(&daemon.socket, &session).await?;

    assert_eq!(fs::read_to_string(&executor_log)?.lines().count(), 1);
    daemon.stop_gracefully()?;
    assert_eq!(fs::read_to_string(&recovery_log)?, "recovered\n");

    test_persistence(
        directory.path(),
        &catalog_path,
        &executor_log,
        &recovery_log,
        &session,
        &receipt.operation_ref,
    )
    .await?;

    drop(directory);
    Ok(())
}

async fn execute_operation(
    socket: &Path,
    input: &ExecuteUseRequest,
) -> TestResult<OperationReceipt> {
    match request(socket, DaemonRequest::ExecuteUse(input.clone())).await? {
        DaemonResponse::OperationAccepted { receipt } => Ok(receipt),
        response => Err(format!("expected accepted operation, got {response:?}").into()),
    }
}

async fn queue_operation(
    socket: &Path,
    session: &intentkey_core::SessionCapability,
) -> TestResult<(ExecuteUseRequest, OperationReceipt)> {
    let DaemonResponse::UsePrepared { link, .. } = request(
        socket,
        DaemonRequest::PrepareUse(PrepareUseRequest {
            session: session.clone(),
            item_id: ItemId::new("itm_process"),
            revision: 7,
            intent: intent("https://example.com")?,
            operation: UseOperation::Login(LoginUse::Password),
            selected_component: Some(ComponentId::new("cmp_password")?),
            ttl_ms: 60_000,
        }),
    )
    .await?
    else {
        return Err("expected prepared link response".into());
    };
    let input = ExecuteUseRequest {
        session: session.clone(),
        link,
    };
    let receipt = execute_operation(socket, &input).await?;
    assert_eq!(receipt.outcome, OperationOutcome::Queued);
    assert_eq!(execute_operation(socket, &input).await?, receipt);
    Ok((input, receipt))
}

async fn inspect_operation(
    socket: &Path,
    input: &ExecuteUseRequest,
    receipt: &OperationReceipt,
) -> TestResult<OperationReceipt> {
    match request(
        socket,
        DaemonRequest::InspectOperation(OperationRequest {
            session: input.session.clone(),
            operation_ref: receipt.operation_ref.clone(),
        }),
    )
    .await?
    {
        DaemonResponse::OperationInspected { receipt } => Ok(receipt),
        response => Err(format!("expected inspected operation, got {response:?}").into()),
    }
}

fn assert_only_queued_outbox(database: &Path, queued: &OperationReceipt) -> TestResult<()> {
    let db = rusqlite::Connection::open_with_flags(
        database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let operation_count: i64 =
        db.query_row("SELECT COUNT(*) FROM operations", [], |row| row.get(0))?;
    assert_eq!(
        operation_count, 2,
        "replay must not create duplicate operations"
    );
    let mut statement = db.prepare("SELECT operation_ref,state FROM dispatch_outbox")?;
    let outbox = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        outbox,
        vec![(queued.operation_ref.clone(), "pending".to_owned())]
    );
    Ok(())
}

/// SIGKILL exercises queued durability and stale socket/lock recovery. Dispatched state is
/// seeded through the public API only after reaping the child; this is not a crash inside
/// a real executor between side effects and completion.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sigkill_restart_recovers_seeded_dispatch_and_preserves_queued_work() -> TestResult<()> {
    let directory = private_tempdir()?;
    let catalog_path = directory.path().join("catalog.json");
    let executor_log = directory.path().join("executor.log");
    let recovery_log = directory.path().join("recovery.log");
    let database = directory.path().join("state.sqlite3");
    fs::write(&catalog_path, serde_json::to_vec(&vec![catalog()?])?)?;
    fs::write(&executor_log, b"")?;

    let mut daemon = Daemon::start(directory.path(), &catalog_path, None, &recovery_log)?;
    daemon.await_ready()?;
    let (session, _) = test_session_and_catalog(&daemon.socket).await?;
    let (dispatch_input, mut dispatched) = queue_operation(&daemon.socket, &session).await?;
    let (queued_input, queued) = queue_operation(&daemon.socket, &session).await?;
    assert_ne!(dispatched.operation_ref, queued.operation_ref);
    daemon.kill_and_reap()?;
    assert!(
        daemon.socket.exists(),
        "SIGKILL must leave the stale socket"
    );
    assert!(database.with_extension("sqlite3.lock").exists());

    // Set up the interrupted-dispatch fixture while no daemon owns the database.
    // Its logical timestamp is admission time, so fixture setup cannot race TTL expiry.
    {
        let state = intentkeyd::DaemonState::open(&database)?;
        assert_eq!(state.receipt(&dispatched.operation_ref)?, dispatched);
        assert_eq!(state.receipt(&queued.operation_ref)?, queued);
        state.register_item(catalog()?)?;
        dispatched = state.mark_dispatched(&dispatched.operation_ref, dispatched.started_at_ms)?;
        assert_eq!(dispatched.outcome, OperationOutcome::Dispatched);
        assert_eq!(dispatched.completed_at_ms, None);
    }
    {
        let reopened = intentkeyd::DaemonState::open(&database)?;
        assert_eq!(reopened.receipt(&dispatched.operation_ref)?, dispatched);
        assert_eq!(reopened.receipt(&queued.operation_ref)?, queued);
    }
    fs::remove_file(&recovery_log)?;
    let mut restarted = Daemon::start(
        directory.path(),
        &catalog_path,
        Some(&executor_log),
        &recovery_log,
    )?;
    restarted.await_ready()?;
    assert_eq!(restarted.socket, daemon.socket);
    let recovered = inspect_operation(&restarted.socket, &dispatch_input, &dispatched).await?;
    assert_eq!(recovered.outcome, OperationOutcome::Indeterminate);
    assert!(recovered.completed_at_ms.is_some());
    dispatched.outcome = OperationOutcome::Indeterminate;
    dispatched.completed_at_ms = recovered.completed_at_ms;
    assert_eq!(
        recovered, dispatched,
        "recovery must preserve operation identity and metadata"
    );
    assert_eq!(
        execute_operation(&restarted.socket, &dispatch_input).await?,
        recovered
    );
    assert_eq!(
        inspect_operation(&restarted.socket, &queued_input, &queued).await?,
        queued
    );
    assert_only_queued_outbox(&database, &queued)?;
    assert_eq!(fs::read_to_string(&executor_log)?.lines().count(), 0);
    restarted.stop_gracefully()?;
    assert_eq!(fs::read_to_string(&recovery_log)?, "recovered\n");
    assert!(!restarted.socket.exists());

    // Replaying queued work with the failing executor enabled intentionally dispatches it.
    // Disable that harness only for this replay check; production admission still runs.
    let mut replay = Daemon::start(directory.path(), &catalog_path, None, &recovery_log)?;
    replay.await_ready()?;
    assert_eq!(
        execute_operation(&replay.socket, &queued_input).await?,
        queued
    );
    assert_eq!(
        execute_operation(&replay.socket, &dispatch_input).await?,
        recovered
    );
    assert_only_queued_outbox(&database, &queued)?;
    assert_eq!(fs::read_to_string(&executor_log)?.lines().count(), 0);
    replay.stop_gracefully()?;
    assert!(!replay.socket.exists());
    directory.close()?;
    Ok(())
}
