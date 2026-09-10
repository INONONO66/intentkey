// Included in native_process so both fixtures use the exact same real CLI/daemon harness.
fn provider_fixture() -> TestResult<PathBuf> {
    static EXECUTABLE: std::sync::OnceLock<Result<PathBuf, String>> = std::sync::OnceLock::new();
    EXECUTABLE
        .get_or_init(|| {
            let directory = tempfile::tempdir().map_err(|_| "fixture directory")?.keep();
            let source = directory.join("provider.rs");
            fs::write(&source, include_str!("provider_fixture.rs.inc"))
                .map_err(|_| "fixture source")?;
            let executable = directory.join("provider");
            let output = Command::new("rustc")
                .args(["--edition=2024", "--crate-name", "provider_fixture"])
                .arg(&source)
                .arg("-o")
                .arg(&executable)
                .output()
                .map_err(|_| "rustc spawn")?;
            if !output.status.success() {
                return Err("fixture compilation failed".to_owned());
            }
            executable
                .canonicalize()
                .map_err(|_| "fixture path".to_owned())
        })
        .clone()
        .map_err(Into::into)
}

fn ascii_marker() -> TestResult<Zeroizing<Vec<u8>>> {
    let mut value = marker(64)?;
    for byte in &mut *value {
        *byte = b'a' + *byte % 26;
    }
    Ok(value)
}

fn provider_response(
    response: OwnerResponse,
) -> TestResult<intentkey_core::owner::ProviderOwnerResponse> {
    match response {
        OwnerResponse::Provider(response) => Ok(response),
        OwnerResponse::Error(code) => Err(code.into()),
        _ => Err("expected provider metadata".into()),
    }
}

#[test]
fn actual_proton_cli_daemon_connect_list_import() -> TestResult<()> {
    provider_lifecycle("proton-pass")
}
#[test]
fn actual_onepassword_cli_daemon_connect_list_import() -> TestResult<()> {
    provider_lifecycle("one-password")
}

fn provider_lifecycle(family: &str) -> TestResult<()> {
    use intentkey_core::owner::ProviderOwnerResponse as P;
    let temp = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()?;
    let root = temp.path().canonicalize()?;
    let external = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()?;
    let home = external.path().canonicalize()?;
    let pass = marker(32)?;
    let wrong = marker(32)?;
    let random = ascii_marker()?;
    let mut value = Zeroizing::new(Vec::with_capacity(100));
    value.extend_from_slice(b" \n");
    let character = char::from_u32(0x400 + u32::from(random[0])).ok_or("unicode")?;
    let mut utf8 = [0; 4];
    value.extend_from_slice(character.encode_utf8(&mut utf8).as_bytes());
    value.extend_from_slice(&random);
    value.extend_from_slice(b"\r\n\t ");
    let replacement = ascii_marker()?;
    let token = ascii_marker()?;
    let markers = [
        &pass[..],
        &wrong[..],
        &value[..],
        &replacement[..],
        &token[..],
    ];
    fs::write(home.join("family"), family)?;
    fs::write(home.join("value"), &value)?;
    fs::write(home.join("expected-token"), &token)?;
    fs::write(home.join("mode"), "ok")?;
    fs::write(home.join("token"), &token)?;
    fs::set_permissions(home.join("token"), fs::Permissions::from_mode(0o600))?;
    let daemon = Daemon::start(&root)?;
    assert!(matches!(
        owner(&root, &["init"], &pass, None, &markers)?,
        OwnerResponse::State(VaultStatus::Unlocked)
    ));
    let executable = provider_fixture()?;
    let mut args = vec![
        "provider",
        "connect",
        "--kind",
        family,
        "--executable",
        executable.to_str().ok_or("path")?,
        "--home",
        home.to_str().ok_or("path")?,
        "--session-dir",
        home.to_str().ok_or("path")?,
        "--vault-id",
        "vault1",
    ];
    let token_path = home.join("token");
    if family == "one-password" {
        args.extend(["--service-account-file", token_path.to_str().ok_or("path")?]);
    }
    error(
        &owner(&root, &args, &wrong, None, &markers)?,
        SecretErrorCode::AuthenticationFailed,
    );
    error(
        &owner(&root, &args, &pass, None, &markers)?,
        SecretErrorCode::Locked,
    );
    owner(&root, &["unlock"], &pass, None, &markers)?;
    let P::Connected(connection) = provider_response(owner(&root, &args, &pass, None, &markers)?)?
    else {
        return Err("connect".into());
    };
    fs::remove_file(token_path)?; // Token must now survive only in encrypted daemon custody.
    provider_import_lifecycle(&root, &home, daemon, &connection, &markers, family)
}

fn provider_import_lifecycle(
    root: &Path,
    home: &Path,
    mut daemon: Daemon,
    connection: &intentkey_core::owner::ProviderConnectionMetadata,
    markers: &[&[u8]; 5],
    family: &str,
) -> TestResult<()> {
    use intentkey_core::owner::ProviderOwnerResponse as P;
    let pass = markers[0];
    let value = markers[2];
    let provider = connection.provider_id.as_str();
    let list = ["provider", "list", "--provider-id", provider];
    let P::Items(items) = provider_response(owner(root, &list, pass, None, markers)?)? else {
        return Err("list".into());
    };
    assert_eq!(items.len(), 1);
    let item = &items[0];
    assert_eq!(item.components.len(), 1);
    let revision = item.revision.to_string();
    let import = [
        "provider",
        "import",
        "--provider-id",
        provider,
        "--item-id",
        item.item_id.as_str(),
        "--revision",
        &revision,
        "--component-id",
        item.components[0].component_id.as_str(),
    ];
    no_marker(&daemon.stop()?, markers);
    daemon = Daemon::start(root)?;
    error(
        &owner(root, &import, pass, None, markers)?,
        SecretErrorCode::Locked,
    );
    owner(root, &["unlock"], pass, None, markers)?;
    assert!(
        matches!(provider_response(owner(root, &["provider", "status"], pass, None, markers)?)?, P::Connections(c) if c == std::slice::from_ref(connection))
    );
    provider_failures(root, home, &import, &list, markers, family)?;
    let DaemonResponse::SessionOpened { session } =
        agent(root, &DaemonRequest::OpenSession, markers)?
    else {
        return Err("agent session".into());
    };
    catalog(root, &session, &[], markers)?;
    let P::Imported(native) = provider_response(owner(root, &import, pass, None, markers)?)? else {
        return Err("import".into());
    };
    assert_eq!(native.kind, ItemKind::Login);
    assert!(
        matches!(owner(root, &["list"], pass, None, markers)?, OwnerResponse::Items(items) if items == std::slice::from_ref(&native))
    );
    catalog(root, &session, std::slice::from_ref(&native), markers)?;
    assert_native_contains(root, pass, value)?;
    no_plaintext_files(root, markers)?;
    let disconnect = ["provider", "disconnect", "--provider-id", provider];
    assert!(
        matches!(provider_response(owner(root, &disconnect, pass, None, markers)?)?, P::Disconnected(id) if id == provider)
    );
    error(
        &owner(root, &import, pass, None, markers)?,
        SecretErrorCode::NotFound,
    );
    assert!(
        matches!(owner(root, &["list"], pass, None, markers)?, OwnerResponse::Items(items) if items == [native])
    );
    no_marker(&daemon.stop()?, markers);
    no_plaintext_files(root, markers)?;
    Ok(())
}

fn provider_failures(
    root: &Path,
    home: &Path,
    import: &[&str],
    list: &[&str],
    markers: &[&[u8]; 5],
    family: &str,
) -> TestResult<()> {
    let pass = markers[0];
    for (mode, expected) in [
        ("revision", SecretErrorCode::RevisionMismatch),
        ("race", SecretErrorCode::RevisionMismatch),
        ("wrong-scope", SecretErrorCode::InvalidInput),
        ("error", SecretErrorCode::Unavailable),
        ("large", SecretErrorCode::TooLarge),
        ("timeout", SecretErrorCode::Timeout),
        ("malformed", SecretErrorCode::InvalidInput),
        ("duplicate", SecretErrorCode::InvalidInput),
    ] {
        fs::write(home.join("mode"), mode)?;
        error(&owner(root, import, pass, None, markers)?, expected);
        assert!(
            matches!(owner(root, &["list"], pass, None, markers)?, OwnerResponse::Items(items) if items.is_empty())
        );
    }
    if family == "one-password" {
        fs::write(home.join("mode"), "unsupported")?;
        error(
            &owner(root, list, pass, None, markers)?,
            SecretErrorCode::Unsupported,
        );
    }
    fs::write(home.join("mode"), "ok")?;
    fs::write(home.join("value"), markers[3])?;
    error(
        &owner(root, import, pass, None, markers)?,
        SecretErrorCode::RevisionMismatch,
    );
    fs::write(home.join("value"), markers[2])?;
    let mut stale = import.to_vec();
    stale[7] = "0";
    error(
        &owner(root, &stale, pass, None, markers)?,
        SecretErrorCode::RevisionMismatch,
    );
    let mut unsupported = import.to_vec();
    unsupported[9] = "wrong_field";
    error(
        &owner(root, &unsupported, pass, None, markers)?,
        SecretErrorCode::Unsupported,
    );
    error(
        &owner(root, import, markers[1], None, markers)?,
        SecretErrorCode::AuthenticationFailed,
    );
    error(
        &owner(root, import, pass, None, markers)?,
        SecretErrorCode::Locked,
    );
    owner(root, &["unlock"], pass, None, markers)?;
    Ok(())
}

// Offline test-only envelope decryption proves the actual imported bytes, not merely
// that some native item was created. There is no production value accessor.
fn assert_native_contains(root: &Path, pass: &[u8], value: &[u8]) -> TestResult<()> {
    use argon2::{Algorithm, Argon2, Params, Version};
    use chacha20poly1305::{
        XChaCha20Poly1305, XNonce,
        aead::{Aead, KeyInit, Payload},
    };
    let bytes = fs::read(root.join("data/intentkey/native.vault"))?;
    let mut wrapping = Zeroizing::new([0u8; 32]);
    let params = Params::new(65_536, 3, 1, Some(32)).map_err(|_| "params")?;
    let mut workspace = Zeroizing::new(vec![argon2::Block::default(); params.block_count()]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into_with_memory(pass, &bytes[24..40], &mut *wrapping, &mut *workspace)
        .map_err(|_| "kdf")?;
    let cipher = XChaCha20Poly1305::new_from_slice(&*wrapping).map_err(|_| "key")?;
    let aad = [b"intentkey/dek/v1".as_slice(), &bytes[..64]].concat();
    let key = Zeroizing::new(
        cipher
            .decrypt(
                &XNonce::try_from(&bytes[40..64]).map_err(|_| "nonce")?,
                Payload {
                    msg: &bytes[64..112],
                    aad: &aad,
                },
            )
            .map_err(|_| "auth")?,
    );
    let cipher = XChaCha20Poly1305::new_from_slice(&key).map_err(|_| "key")?;
    let aad = [b"intentkey/snapshot/v1".as_slice(), &bytes[..148]].concat();
    let plain = Zeroizing::new(
        cipher
            .decrypt(
                &XNonce::try_from(&bytes[112..136]).map_err(|_| "nonce")?,
                Payload {
                    msg: &bytes[148..],
                    aad: &aad,
                },
            )
            .map_err(|_| "auth")?,
    );
    assert!(plain.starts_with(b"IKSNAP02"));
    let items = &plain[12..];
    assert!(items.starts_with(b"IKSNAP01"));
    assert_eq!(u32::from_be_bytes(items[8..12].try_into()?), 1);
    let metadata_len = u32::from_be_bytes(items[12..16].try_into()?) as usize;
    let start = 16 + metadata_len;
    let value_len = u32::from_be_bytes(items[start..start + 4].try_into()?) as usize;
    assert!(items[start + 4..start + 4 + value_len].eq(value));
    Ok(())
}
