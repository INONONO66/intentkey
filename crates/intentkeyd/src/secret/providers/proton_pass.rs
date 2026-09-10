//! pass-cli 2.3.3 metadata schema (upstream tagged item/list.rs and vault/list.rs).
use super::super::subprocess::{ProviderCommand, SubprocessRunner};
use super::{Error, Source, id, runner_error};
use serde::Deserialize;

#[derive(Deserialize)]
struct Vaults {
    vaults: Vec<Vault>,
}
#[derive(Deserialize)]
struct Vault {
    share_id: String,
}
#[derive(Deserialize)]
struct Items {
    items: Vec<Item>,
}
#[derive(Deserialize)]
struct Item {
    id: String,
    share_id: String,
    #[serde(rename = "item_type")]
    kind: String,
    state: String,
    modify_time: String,
}

pub(super) async fn connect(runner: &SubprocessRunner, share: &str) -> Result<(), Error> {
    let output = runner
        .run(ProviderCommand::ProtonVaultList)
        .await
        .map_err(runner_error)?;
    let root: Vaults = serde_json::from_slice(&output).map_err(|_| Error::InvalidInput)?;
    if root.vaults.iter().filter(|v| v.share_id == share).count() != 1 {
        return Err(Error::NotFound);
    }
    Ok(())
}
pub(super) async fn list(runner: &SubprocessRunner, share: &str) -> Result<Vec<Source>, Error> {
    let output = runner
        .run(ProviderCommand::ProtonList {
            share_id: id(share)?,
        })
        .await
        .map_err(runner_error)?;
    let root: Items = serde_json::from_slice(&output).map_err(|_| Error::InvalidInput)?;
    let mut result = Vec::new();
    for item in root.items {
        if item.share_id != share {
            return Err(Error::InvalidInput);
        }
        if item.kind == "login" && item.state == "Active" {
            result.push(Source {
                item_id: item.id,
                revision: item.modify_time,
                fingerprint: [0; 32],
            });
        }
    }
    result.sort_by(|a, b| a.item_id.cmp(&b.item_id));
    Ok(result)
}
