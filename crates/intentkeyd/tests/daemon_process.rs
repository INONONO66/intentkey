//! Real-process integration coverage for the intentkey daemon wire boundary.

use std::{
    error::Error,
    fs,
    io::{BufRead, BufReader},
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

struct Daemon {
    child: Option<Child>,
    socket: PathBuf,
    ready: Receiver<()>,
}

impl Daemon {
    fn start(
        dir: &Path,
        catalog: &Path,
        executor_log: &Path,
        recovery_log: &Path,
    ) -> TestResult<Self> {
        let socket = dir.join("intentkeyd.sock");
        let mut child = Command::new(env!("CARGO_BIN_EXE_intentkeyd"))
            .args([
                "--socket",
                socket.to_str().ok_or("socket path is not UTF-8")?,
                "--test-catalog",
                catalog.to_str().ok_or("catalog path is not UTF-8")?,
                "--test-executor-log",
                executor_log
                    .to_str()
                    .ok_or("executor log path is not UTF-8")?,
                "--test-recovery-log",
                recovery_log
                    .to_str()
                    .ok_or("recovery log path is not UTF-8")?,
            ])
            .stderr(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()?;
        let stderr = child.stderr.take().ok_or("daemon stderr is not piped")?;
        let (sender, ready) = mpsc::channel();
        std::thread::spawn(move || {
            let mut ready_sent = false;
            for line in BufReader::new(stderr).lines() {
                if !ready_sent
                    && line
                        .as_deref()
                        .is_ok_and(|line| line.contains("intentkeyd.ready"))
                {
                    let _ = sender.send(());
                    ready_sent = true;
                }
            }
        });
        Ok(Self {
            child: Some(child),
            socket,
            ready,
        })
    }

    fn await_ready(&self) -> TestResult<()> {
        self.ready.recv_timeout(IO_TIMEOUT)?;
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
    let mut restarted = Daemon::start(dir, catalog_path, executor_log, recovery_log)?;
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
    let directory = tempfile::tempdir()?;
    let catalog_path = directory.path().join("catalog.json");
    let executor_log = directory.path().join("executor.log");
    let recovery_log = directory.path().join("recovery.log");

    let cat = catalog()?;
    fs::write(&catalog_path, serde_json::to_vec(&vec![cat])?)?;

    let mut daemon = Daemon::start(
        directory.path(),
        &catalog_path,
        &executor_log,
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
