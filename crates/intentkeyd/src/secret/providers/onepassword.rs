//! op 2.39: Login password is CONCEALED with purpose PASSWORD, not a type PASSWORD.
use super::super::subprocess::{ProviderCommand, SubprocessRunner};
use super::{Error, Source, id, runner_error};
use serde::Deserialize;

#[derive(Deserialize)]
struct Vault {
    id: String,
}
#[derive(Deserialize)]
struct Item {
    id: String,
    vault: Vault,
    category: String,
    version: u64,
}
#[derive(Deserialize)]
struct Detail {
    id: String,
    vault: Vault,
    category: String,
    version: u64,
    fields: Vec<Field>,
}
#[derive(Deserialize)]
struct Field {
    id: String,
    #[serde(rename = "type")]
    kind: String,
    purpose: Option<String>,
    section: Option<serde::de::IgnoredAny>,
    // Values, titles and labels are deliberately skipped, never owned as Strings.
}

pub(super) async fn connect(runner: &SubprocessRunner, vault: &str) -> Result<(), Error> {
    let output = runner
        .run(ProviderCommand::OnePasswordVaultList)
        .await
        .map_err(runner_error)?;
    let root: Vec<Vault> = serde_json::from_slice(&output).map_err(|_| Error::InvalidInput)?;
    if root.iter().filter(|v| v.id == vault).count() != 1 {
        return Err(Error::NotFound);
    }
    Ok(())
}
pub(super) async fn list(runner: &SubprocessRunner, vault: &str) -> Result<Vec<Source>, Error> {
    let output = runner
        .run(ProviderCommand::OnePasswordList {
            vault_id: id(vault)?,
        })
        .await
        .map_err(runner_error)?;
    let root: Vec<Item> = serde_json::from_slice(&output).map_err(|_| Error::InvalidInput)?;
    if root.len() > super::MAX_SOURCE_ITEMS {
        return Err(Error::TooLarge);
    }
    let mut result = Vec::new();
    for item in root {
        if item.vault.id != vault || item.category != "LOGIN" || item.version == 0 {
            return Err(Error::InvalidInput);
        }
        let output = runner
            .run(ProviderCommand::OnePasswordGet {
                vault_id: id(vault)?,
                item_id: id(&item.id)?,
            })
            .await
            .map_err(runner_error)?;
        let detail: Detail = serde_json::from_slice(&output).map_err(|_| Error::InvalidInput)?;
        if detail.id != item.id
            || detail.vault.id != vault
            || detail.version != item.version
            || detail.category != "LOGIN"
        {
            return Err(Error::RevisionMismatch);
        }
        let fields: Vec<_> = detail
            .fields
            .iter()
            .filter(|f| f.id == "password")
            .collect();
        if fields.len() != 1 {
            return Err(Error::Unsupported);
        }
        let field = fields[0];
        if field.kind != "CONCEALED"
            || field.purpose.as_deref() != Some("PASSWORD")
            || field.section.is_some()
        {
            return Err(Error::Unsupported);
        }
        result.push(Source {
            item_id: item.id,
            revision: item.version.to_string(),
            fingerprint: [0; 32],
        });
    }
    result.sort_by(|a, b| a.item_id.cmp(&b.item_id));
    Ok(result)
}
