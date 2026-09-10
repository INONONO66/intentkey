// Compiled test-only vendor process. No account access; only random owner-fixture bytes.
use std::{env, fs, io::{Read, Write}, path::PathBuf, process};
fn main() {
    if run().is_err() { process::exit(71); }
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let home = PathBuf::from(env::var_os("HOME").ok_or("home")?);
    let op = fs::read(home.join("family"))? == b"one-password";
    let value = fs::read(home.join("value"))?;
    let token = fs::read(home.join("expected-token"))?;
    if op { assert!(env::var("OP_SERVICE_ACCOUNT_TOKEN")?.as_bytes().eq(&token)); }
    else {
        assert!(env::var_os("OP_SERVICE_ACCOUNT_TOKEN").is_none());
        assert!(env::var_os("PROTON_PASS_SESSION_DIR").as_deref() == Some(home.as_os_str()));
        assert!(env::var("PROTON_PASS_KEY_PROVIDER")? == "fs");
    }
    assert!(env::var_os("PROVIDER_POISON").is_none());
    let args: Vec<_> = env::args().skip(1).collect();
    assert!(!args.iter().any(|arg| arg.as_bytes().windows(value.len()).any(|s| s == value)));
    let mode = fs::read(home.join("mode"))?;
    match mode.as_slice() {
        b"error" => { std::io::stderr().write_all(&value)?; process::exit(7); }
        b"large" => { for _ in 0..9000 { std::io::stdout().write_all(&value)?; } return Ok(()); }
        b"timeout" => { loop { std::thread::park(); } }
        b"malformed" => { std::io::stdout().write_all(&value)?; return Ok(()); }
        _ => {}
    }
    let mut stdin = Vec::new(); std::io::stdin().read_to_end(&mut stdin)?; assert!(stdin.is_empty());
    let session = home.to_str().ok_or("path")?;
    let borrowed: Vec<_> = args.iter().map(String::as_str).collect();
    let kind = if op {
        if borrowed == ["vault","list","--format","json","--cache=false","--config",session] { "vault" }
        else if borrowed == ["item","list","--vault","vault1","--categories","Login","--format","json","--cache=false","--config",session] { "list" }
        else if borrowed == ["item","get","item1","--vault","vault1","--format","json","--cache=false","--config",session] { "get" }
        else if borrowed == ["read","op://vault1/item1/password","--no-newline","--cache=false","--config",session] { "field" }
        else { return Err("argv".into()); }
    } else {
        if borrowed == ["vault","list","--output","json"] { "vault" }
        else if borrowed == ["item","list","--share-id","vault1","--output","json"] { "list" }
        else if borrowed == ["item","view","--share-id","vault1","--item-id","item1","--field","password","--output","json"] { "field" }
        else { return Err("argv".into()); }
    };
    let label = std::str::from_utf8(&token)?;
    if mode == b"duplicate" && kind == "list" {
        if op { print!("[{{\"id\":\"item1\",\"id\":\"item1\",\"vault\":{{\"id\":\"vault1\"}},\"category\":\"LOGIN\",\"version\":1}}]"); }
        else { print!("{{\"items\":[{{\"id\":\"item1\",\"id\":\"item1\",\"share_id\":\"vault1\",\"item_type\":\"login\",\"state\":\"Active\",\"modify_time\":\"1\"}}]}}"); }
        return Ok(());
    }
    let revision = if mode == b"revision" { 2 } else { 1 };
    let vault = if mode == b"wrong-scope" { "other" } else { "vault1" };
    match (op,kind) {
        (true,"vault") => print!("[{{\"id\":\"vault1\",\"name\":\"{label}\"}}]"),
        (false,"vault") => print!("{{\"vaults\":[{{\"share_id\":\"vault1\",\"vault_id\":\"container\",\"name\":\"{label}\"}}]}}"),
        (true,"list") => print!("[{{\"id\":\"item1\",\"vault\":{{\"id\":\"{vault}\"}},\"title\":\"{label}\",\"category\":\"LOGIN\",\"version\":{revision}}}]"),
        (false,"list") => print!("{{\"items\":[{{\"id\":\"item1\",\"share_id\":\"{vault}\",\"vault_id\":\"container\",\"title\":\"{label}\",\"item_type\":\"login\",\"state\":\"Active\",\"modify_time\":\"2026-09-10T00:00:0{revision}\"}}]}}"),
        (true,"get") => {
            let typ = if mode == b"unsupported" { "OTP" } else { "CONCEALED" };
            print!("{{\"id\":\"item1\",\"vault\":{{\"id\":\"vault1\"}},\"category\":\"LOGIN\",\"version\":{revision},\"fields\":[{{\"id\":\"password\",\"type\":\"{typ}\",\"purpose\":\"PASSWORD\",\"value\":\"{label}\"}}]}}");
        }
        (_,"field") => {
            std::io::stdout().write_all(&value)?;
            if !op { std::io::stdout().write_all(b"\n")?; }
            if mode == b"race" { fs::write(home.join("mode"), b"revision")?; }
        }
        _ => return Err("command".into()),
    }
    Ok(())
}
