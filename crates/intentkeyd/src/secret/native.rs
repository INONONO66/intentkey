//! Private native vault lifecycle and atomic encrypted persistence.

use std::{
    collections::HashSet,
    fs::{self, File, Metadata, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
};

use intentkey_core::{
    ComponentId, ComponentPresence, ItemDescriptor, ItemId, ItemKind, LoginComponentKind,
    LoginComponentMetadata, OperationSupport,
    owner::{NativeKind, SecretErrorCode as Error, VaultStatus},
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::native_format::Envelope;

const MAX_SNAPSHOT: usize = 16 * 1024 * 1024;
const MAX_PAYLOAD: usize = MAX_SNAPSHOT - 148 - 16;
const MAX_ITEMS: usize = 1024;
const MAX_VALUE: usize = 64 * 1024;
const MAX_METADATA: usize = 4096;
const PAYLOAD_MAGIC: &[u8; 8] = b"IKSNAP01";

// Only metadata implements serialization. Values have no Debug, Clone, or serde surface.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MetadataRecord {
    descriptor: ItemDescriptor,
    native_kind: NativeKind,
}

struct Item {
    metadata: MetadataRecord,
    value: Zeroizing<Vec<u8>>,
}

struct Custody {
    envelope: Envelope,
    generation: u64,
    items: Vec<Item>,
}

pub(super) struct NativeVault {
    directory: PathBuf,
    directory_file: File,
    // This stable inode is never renamed or removed; locking native.vault itself
    // would cease to exclude writers after the first atomic replacement.
    _writer_lock: File,
    initialized: bool,
    custody: Option<Custody>,
    #[cfg(test)]
    fault: Option<Fault>,
}

fn unavailable(_: io::Error) -> Error {
    Error::Unavailable
}

fn uid() -> u32 {
    nix::unistd::Uid::effective().as_raw()
}

fn random_id() -> Result<uuid::Uuid, Error> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| Error::Unavailable)?;
    Ok(uuid::Uuid::from_bytes(bytes))
}

fn rename_new(source: &Path, destination: &Path) -> Result<(), Error> {
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        source,
        rustix::fs::CWD,
        destination,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(|error| {
        if error == rustix::io::Errno::EXIST {
            Error::AlreadyInitialized
        } else {
            Error::Unavailable
        }
    })
}

fn private_file(metadata: &Metadata) -> Result<(), Error> {
    if !metadata.is_file()
        || metadata.uid() != uid()
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o600
    {
        return Err(Error::Unavailable);
    }
    Ok(())
}

fn inspect_file(path: &Path) -> Result<Option<Metadata>, Error> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            private_file(&metadata)?;
            Ok(Some(metadata))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(Error::Unavailable),
    }
}

fn same_file(path: &Path, file: &File) -> Result<(), Error> {
    let opened = file.metadata().map_err(unavailable)?;
    private_file(&opened)?;
    let named = inspect_file(path)?.ok_or(Error::Unavailable)?;
    if opened.dev() != named.dev() || opened.ino() != named.ino() {
        return Err(Error::Unavailable);
    }
    Ok(())
}

fn open_private(path: &Path, create: bool) -> Result<File, Error> {
    inspect_file(path)?;
    let file = OpenOptions::new()
        .read(true)
        .write(create)
        .create(create)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                Error::NotFound
            } else {
                Error::Unavailable
            }
        })?;
    same_file(path, &file)?;
    Ok(file)
}

fn private_directory(path: &Path) -> Result<(PathBuf, File), Error> {
    let absolute = std::path::absolute(path).map_err(unavailable)?;
    if absolute
        .components()
        .any(|part| part == Component::ParentDir)
    {
        return Err(Error::InvalidInput);
    }
    // Require an existing directory. No symlink in any supplied component is
    // accepted (on macOS callers can supply the canonical /private/... path).
    for ancestor in absolute.ancestors() {
        let metadata = fs::symlink_metadata(ancestor).map_err(unavailable)?;
        if !metadata.is_dir()
            || (metadata.uid() != uid() && metadata.uid() != 0)
            || (metadata.mode() & 0o022 != 0 && metadata.mode() & 0o1000 == 0)
        {
            return Err(Error::Unavailable);
        }
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(&absolute)
        .map_err(unavailable)?;
    let metadata = file.metadata().map_err(unavailable)?;
    let named = fs::symlink_metadata(&absolute).map_err(unavailable)?;
    if metadata.uid() != uid()
        || metadata.mode() & 0o7777 != 0o700
        || metadata.ino() != named.ino()
        || metadata.dev() != named.dev()
    {
        return Err(Error::Unavailable);
    }
    Ok((absolute, file))
}

fn descriptor(id: ItemId, revision: u64, kind: NativeKind) -> Result<ItemDescriptor, Error> {
    let (kind, components) = match kind {
        NativeKind::Password => (
            ItemKind::Login,
            vec![LoginComponentMetadata::new(
                ComponentId::new("password").map_err(|_| Error::InvalidInput)?,
                LoginComponentKind::Password,
                ComponentPresence::Stored,
                OperationSupport::Unsupported,
            )],
        ),
        NativeKind::Bearer => (ItemKind::ApiCredential, Vec::new()),
    };
    ItemDescriptor::new(id, revision, kind, components).map_err(|_| Error::InvalidInput)
}

const fn check_value(value: &[u8]) -> Result<(), Error> {
    if value.is_empty() {
        return Err(Error::InvalidInput);
    }
    if value.len() > MAX_VALUE {
        return Err(Error::TooLarge);
    }
    Ok(())
}

fn encode_payload<'a>(items: impl Iterator<Item = &'a Item>) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut records = Vec::new();
    let mut length = PAYLOAD_MAGIC.len() + 4;
    for item in items {
        if records.len() == MAX_ITEMS {
            return Err(Error::TooLarge);
        }
        check_value(&item.value)?;
        let metadata =
            Zeroizing::new(serde_json::to_vec(&item.metadata).map_err(|_| Error::InvalidInput)?);
        if metadata.len() > MAX_METADATA {
            return Err(Error::TooLarge);
        }
        length += 8 + metadata.len() + item.value.len();
        if length > MAX_PAYLOAD {
            return Err(Error::TooLarge);
        }
        records.push((metadata, item.value.as_slice()));
    }
    // Allocate once: growing a plaintext Vec could leave its old allocation behind.
    let mut payload = Zeroizing::new(Vec::with_capacity(length));
    payload.extend_from_slice(PAYLOAD_MAGIC);
    put_length(&mut payload, records.len())?;
    for (metadata, value) in records {
        put_length(&mut payload, metadata.len())?;
        payload.extend_from_slice(&metadata);
        put_length(&mut payload, value.len())?;
        payload.extend_from_slice(value);
    }
    Ok(payload)
}

fn put_length(output: &mut Vec<u8>, length: usize) -> Result<(), Error> {
    output.extend_from_slice(
        &u32::try_from(length)
            .map_err(|_| Error::TooLarge)?
            .to_be_bytes(),
    );
    Ok(())
}

const fn take<'a>(input: &mut &'a [u8], length: usize) -> Result<&'a [u8], Error> {
    if length > input.len() {
        return Err(Error::InvalidInput);
    }
    let (value, rest) = input.split_at(length);
    *input = rest;
    Ok(value)
}

fn take_length(input: &mut &[u8], max: usize) -> Result<usize, Error> {
    let bytes = take(input, 4)?
        .try_into()
        .map_err(|_| Error::InvalidInput)?;
    let length = usize::try_from(u32::from_be_bytes(bytes)).map_err(|_| Error::TooLarge)?;
    if length > max {
        return Err(Error::TooLarge);
    }
    Ok(length)
}

fn decode_payload(mut input: &[u8], generation: u64) -> Result<Vec<Item>, Error> {
    if take(&mut input, 8)? != PAYLOAD_MAGIC {
        return Err(Error::InvalidInput);
    }
    let count = take_length(&mut input, MAX_ITEMS)?;
    let mut items = Vec::with_capacity(count);
    let mut ids = HashSet::with_capacity(count);
    for _ in 0..count {
        let length = take_length(&mut input, MAX_METADATA)?;
        let metadata: MetadataRecord =
            serde_json::from_slice(take(&mut input, length)?).map_err(|_| Error::InvalidInput)?;
        let stored = &metadata.descriptor;
        if stored.revision == 0
            || stored.revision > generation
            || *stored
                != descriptor(
                    stored.item_id.clone(),
                    stored.revision,
                    metadata.native_kind,
                )?
            || !ids.insert(stored.item_id.clone())
        {
            return Err(Error::InvalidInput);
        }
        let length = take_length(&mut input, MAX_VALUE)?;
        let value = take(&mut input, length)?;
        check_value(value)?;
        items.push(Item {
            metadata,
            value: Zeroizing::new(value.to_vec()),
        });
    }
    if !input.is_empty() {
        return Err(Error::InvalidInput);
    }
    Ok(items)
}

impl NativeVault {
    /// Opens existing private storage and holds an exclusive writer lock until drop.
    pub(super) fn open(directory: &Path) -> Result<Self, Error> {
        let (directory, directory_file) = private_directory(directory)?;
        let lock_path = directory.join("native.lock");
        let writer_lock = open_private(&lock_path, true)?;
        writer_lock.try_lock().map_err(|error| match error {
            fs::TryLockError::WouldBlock => Error::Busy,
            fs::TryLockError::Error(_) => Error::Unavailable,
        })?;
        same_file(&lock_path, &writer_lock)?;
        let initialized = inspect_file(&directory.join("native.vault"))?.is_some();
        Ok(Self {
            directory,
            directory_file,
            _writer_lock: writer_lock,
            initialized,
            custody: None,
            #[cfg(test)]
            fault: None,
        })
    }

    pub(super) const fn status(&self) -> VaultStatus {
        if self.custody.is_some() {
            VaultStatus::Unlocked
        } else if self.initialized {
            VaultStatus::Locked
        } else {
            VaultStatus::Uninitialized
        }
    }

    pub(super) fn initialize(&mut self, passphrase: &[u8]) -> Result<(), Error> {
        if self.initialized || inspect_file(&self.directory.join("native.vault"))?.is_some() {
            return Err(Error::AlreadyInitialized);
        }
        let envelope = Envelope::create(passphrase)?;
        let payload = encode_payload(std::iter::empty())?;
        let ciphertext = Zeroizing::new(envelope.encode(&payload, 1)?);
        match self.persist(&ciphertext, true) {
            Ok(()) => {
                self.initialized = true;
                self.custody = Some(Custody {
                    envelope,
                    generation: 1,
                    items: Vec::new(),
                });
                Ok(())
            }
            Err(error) => {
                if error == Error::StorageUncertain {
                    self.initialized = true;
                    self.lock();
                }
                Err(error)
            }
        }
    }

    fn load(&self, passphrase: &[u8]) -> Result<Custody, Error> {
        let mut file = open_private(&self.directory.join("native.vault"), false)?;
        let length = usize::try_from(file.metadata().map_err(unavailable)?.len())
            .map_err(|_| Error::TooLarge)?;
        if length > MAX_SNAPSHOT {
            return Err(Error::TooLarge);
        }
        let mut ciphertext = Zeroizing::new(vec![0; length]);
        file.read_exact(&mut ciphertext).map_err(unavailable)?;
        let mut extra = Zeroizing::new([0_u8; 1]);
        if file.read(extra.as_mut()).map_err(unavailable)? != 0 {
            return Err(Error::TooLarge);
        }
        let (envelope, payload, generation) = Envelope::decode(passphrase, &ciphertext)?;
        let items = decode_payload(&payload, generation)?;
        Ok(Custody {
            envelope,
            generation,
            items,
        })
    }

    /// Checks the entire persisted snapshot without granting custody. Failure locks.
    pub(super) fn authenticate(&mut self, passphrase: &[u8]) -> Result<(), Error> {
        match self.load(passphrase) {
            Ok(_) => Ok(()),
            Err(error) => {
                self.lock();
                Err(error)
            }
        }
    }

    pub(super) fn unlock(&mut self, passphrase: &[u8]) -> Result<(), Error> {
        self.lock();
        let custody = self.load(passphrase)?;
        self.initialized = true;
        self.custody = Some(custody);
        Ok(())
    }

    /// Infallibly drops all decrypted values and key material, retaining writer exclusion.
    pub(super) fn lock(&mut self) {
        self.custody = None;
    }

    pub(super) fn list(&self) -> Result<Vec<ItemDescriptor>, Error> {
        Ok(self
            .custody
            .as_ref()
            .ok_or(Error::Locked)?
            .items
            .iter()
            .map(|item| item.metadata.descriptor.clone())
            .collect())
    }

    pub(super) fn store(
        &mut self,
        kind: NativeKind,
        value: Zeroizing<Vec<u8>>,
    ) -> Result<ItemDescriptor, Error> {
        let custody = self.custody.as_ref().ok_or(Error::Locked)?;
        check_value(&value)?;
        if custody.items.len() == MAX_ITEMS {
            return Err(Error::TooLarge);
        }
        let id = ItemId::new(format!("itm_{}", random_id()?.simple()));
        if custody
            .items
            .iter()
            .any(|item| item.metadata.descriptor.item_id == id)
        {
            return Err(Error::Unavailable);
        }
        let item = Item {
            metadata: MetadataRecord {
                descriptor: descriptor(id, 1, kind)?,
                native_kind: kind,
            },
            value,
        };
        let payload = encode_payload(custody.items.iter().chain(std::iter::once(&item)))?;
        self.custody
            .as_mut()
            .ok_or(Error::Locked)?
            .items
            .try_reserve(1)
            .map_err(|_| Error::Unavailable)?;
        self.commit(&payload)?;
        let result = item.metadata.descriptor.clone();
        self.custody.as_mut().ok_or(Error::Locked)?.items.push(item);
        Ok(result)
    }

    fn index(&self, id: &ItemId, revision: u64) -> Result<usize, Error> {
        let items = &self.custody.as_ref().ok_or(Error::Locked)?.items;
        let index = items
            .iter()
            .position(|item| item.metadata.descriptor.item_id == *id)
            .ok_or(Error::NotFound)?;
        if items[index].metadata.descriptor.revision != revision {
            return Err(Error::RevisionMismatch);
        }
        Ok(index)
    }

    pub(super) fn update(
        &mut self,
        id: &ItemId,
        revision: u64,
        value: Zeroizing<Vec<u8>>,
    ) -> Result<ItemDescriptor, Error> {
        let index = self.index(id, revision)?;
        check_value(&value)?;
        let custody = self.custody.as_ref().ok_or(Error::Locked)?;
        let old = &custody.items[index];
        let item = Item {
            metadata: MetadataRecord {
                descriptor: descriptor(
                    id.clone(),
                    revision.checked_add(1).ok_or(Error::TooLarge)?,
                    old.metadata.native_kind,
                )?,
                native_kind: old.metadata.native_kind,
            },
            value,
        };
        let payload = encode_payload(custody.items.iter().enumerate().map(|(position, old)| {
            if position == index { &item } else { old }
        }))?;
        self.commit(&payload)?;
        let result = item.metadata.descriptor.clone();
        self.custody.as_mut().ok_or(Error::Locked)?.items[index] = item;
        Ok(result)
    }

    pub(super) fn remove(&mut self, id: &ItemId, revision: u64) -> Result<(), Error> {
        let index = self.index(id, revision)?;
        let custody = self.custody.as_ref().ok_or(Error::Locked)?;
        let payload = encode_payload(
            custody
                .items
                .iter()
                .enumerate()
                .filter_map(|(position, item)| (position != index).then_some(item)),
        )?;
        self.commit(&payload)?;
        self.custody
            .as_mut()
            .ok_or(Error::Locked)?
            .items
            .remove(index);
        Ok(())
    }

    /// Exact-revision access remains test-only until a real privileged consumer exists.
    #[cfg(test)]
    fn resolve(
        &self,
        id: &ItemId,
        revision: u64,
        kind: NativeKind,
    ) -> Result<&Zeroizing<Vec<u8>>, Error> {
        let index = self.index(id, revision)?;
        let item = &self.custody.as_ref().ok_or(Error::Locked)?.items[index];
        if item.metadata.native_kind != kind {
            return Err(Error::Unsupported);
        }
        Ok(&item.value)
    }

    fn commit(&mut self, payload: &[u8]) -> Result<(), Error> {
        let custody = self.custody.as_ref().ok_or(Error::Locked)?;
        let generation = custody.generation.checked_add(1).ok_or(Error::TooLarge)?;
        let ciphertext = Zeroizing::new(custody.envelope.encode(payload, generation)?);
        match self.persist(&ciphertext, false) {
            Ok(()) => {
                self.custody.as_mut().ok_or(Error::Locked)?.generation = generation;
                Ok(())
            }
            Err(error) => {
                if error == Error::StorageUncertain {
                    self.lock();
                }
                Err(error)
            }
        }
    }

    fn persist(&self, ciphertext: &[u8], initialize: bool) -> Result<(), Error> {
        let destination = self.directory.join("native.vault");
        let exists = inspect_file(&destination)?.is_some();
        if initialize && exists {
            return Err(Error::AlreadyInitialized);
        }
        if !initialize && !exists {
            return Err(Error::NotFound);
        }
        let temporary = self
            .directory
            .join(format!(".native-{}.tmp", random_id()?.simple()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)
            .map_err(unavailable)?;
        let mut published = false;
        let result = (|| {
            same_file(&temporary, &file)?;
            let (first, rest) = ciphertext.split_at(ciphertext.len() / 2);
            file.write_all(first).map_err(unavailable)?;
            #[cfg(test)]
            self.fail(Fault::Write)?;
            file.write_all(rest).map_err(unavailable)?;
            #[cfg(test)]
            self.fail(Fault::FileSync)?;
            file.sync_all().map_err(unavailable)?;
            #[cfg(test)]
            self.fail(Fault::Publish)?;
            if initialize {
                rename_new(&temporary, &destination)?;
            } else {
                fs::rename(&temporary, &destination).map_err(unavailable)?;
            }
            published = true;
            #[cfg(test)]
            self.fail(Fault::DirectorySync)?;
            self.directory_file
                .sync_all()
                .map_err(|_| Error::StorageUncertain)
        })();
        if result.is_err() {
            // Never hide a cleanup failure. The remaining file, if any, contains
            // ciphertext only; no secret bytes have been sent to this file API.
            match fs::remove_file(&temporary) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(_) => {
                    return Err(if published {
                        Error::StorageUncertain
                    } else {
                        Error::Unavailable
                    });
                }
            }
        }
        result
    }

    #[cfg(test)]
    fn fail(&self, fault: Fault) -> Result<(), Error> {
        if self.fault == Some(fault) {
            Err(if fault == Fault::DirectorySync {
                Error::StorageUncertain
            } else {
                Error::Unavailable
            })
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    Write,
    FileSync,
    Publish,
    DirectorySync,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn random(length: usize) -> Zeroizing<Vec<u8>> {
        let mut bytes = Zeroizing::new(vec![0; length]);
        assert!(getrandom::fill(&mut bytes).is_ok(), "OS randomness");
        bytes
    }

    fn directory() -> Result<(tempfile::TempDir, PathBuf), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let path = fs::canonicalize(directory.path())?;
        Ok((directory, path))
    }

    fn no_temporaries(directory: &Path) -> Result<(), io::Error> {
        for entry in fs::read_dir(directory)? {
            let name = entry?.file_name();
            assert!(
                name == "native.vault" || name == "native.lock",
                "temporary removed"
            );
        }
        Ok(())
    }

    fn persist_new(directory: &Path, passphrase: &[u8], value: &[u8]) -> Result<(), Error> {
        let mut vault = NativeVault::open(directory)?;
        vault.initialize(passphrase)?;
        vault.store(NativeKind::Password, Zeroizing::new(value.to_vec()))?;
        Ok(())
    }

    #[test]
    fn native_storage_commits_ciphertext_before_reporting_success()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_directory, path) = directory()?;
        let passphrase = random(32);
        let value = random(128);
        assert!(
            persist_new(&path, &passphrase, &value).is_ok(),
            "native storage must commit an encrypted snapshot"
        );
        let stored = Zeroizing::new(fs::read(path.join("native.vault"))?);
        assert!(
            !stored
                .windows(value.len())
                .any(|bytes| bytes == value.as_slice())
        );
        assert!(
            !stored
                .windows(passphrase.len())
                .any(|bytes| bytes == passphrase.as_slice())
        );
        let mut vault = NativeVault::open(&path)?;
        assert_eq!(vault.status(), VaultStatus::Locked);
        vault.unlock(&passphrase)?;
        let items = vault.list()?;
        assert_eq!(items.len(), 1);
        let item = &items[0];
        assert!(
            vault
                .resolve(&item.item_id, item.revision, NativeKind::Password)?
                .as_slice()
                .eq(value.as_slice())
        );
        let metadata = serde_json::to_vec(&items)?;
        assert!(
            !metadata
                .windows(value.len())
                .any(|bytes| bytes == value.as_slice())
        );
        assert!(
            !stored
                .windows(item.item_id.as_str().len())
                .any(|bytes| bytes == item.item_id.as_str().as_bytes())
        );
        private_file(&fs::metadata(path.join("native.vault"))?)?;
        no_temporaries(&path)?;
        Ok(())
    }

    #[test]
    fn native_lifecycle_exact_revisions_remove_and_locked_custody()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_directory, path) = directory()?;
        let passphrase = random(32);
        let value = random(128);
        let replacement = random(128);
        let mut vault = NativeVault::open(&path)?;
        assert_eq!(vault.status(), VaultStatus::Uninitialized);
        assert!(matches!(vault.unlock(&passphrase), Err(Error::NotFound)));
        vault.initialize(&passphrase)?;
        assert_eq!(vault.status(), VaultStatus::Unlocked);
        let initial_disk = fs::read(path.join("native.vault"))?;
        assert!(matches!(
            vault.initialize(&passphrase),
            Err(Error::AlreadyInitialized)
        ));
        assert!(fs::read(path.join("native.vault"))?.eq(&initial_disk));
        let first = vault.store(NativeKind::Bearer, Zeroizing::new(value.to_vec()))?;
        assert_eq!(first.revision, 1);
        assert_eq!(first.kind, ItemKind::ApiCredential);
        let unchanged = fs::read(path.join("native.vault"))?;
        assert!(matches!(
            vault.update(&first.item_id, 0, random(32)),
            Err(Error::RevisionMismatch)
        ));
        assert!(matches!(
            vault.remove(&first.item_id, 0),
            Err(Error::RevisionMismatch)
        ));
        assert!(matches!(
            vault.resolve(&first.item_id, 0, NativeKind::Bearer),
            Err(Error::RevisionMismatch)
        ));
        assert!(matches!(
            vault.resolve(&first.item_id, 1, NativeKind::Password),
            Err(Error::Unsupported)
        ));
        assert!(fs::read(path.join("native.vault"))?.eq(&unchanged));
        let second = vault.update(&first.item_id, 1, Zeroizing::new(replacement.to_vec()))?;
        assert_eq!(second.revision, 2);
        assert_eq!(second.item_id, first.item_id);
        vault.lock();
        assert_eq!(vault.status(), VaultStatus::Locked);
        assert!(matches!(vault.list(), Err(Error::Locked)));
        assert!(matches!(
            vault.store(NativeKind::Bearer, random(32)),
            Err(Error::Locked)
        ));
        assert!(matches!(
            vault.update(&first.item_id, 2, random(32)),
            Err(Error::Locked)
        ));
        assert!(matches!(
            vault.remove(&first.item_id, 2),
            Err(Error::Locked)
        ));
        assert!(matches!(
            vault.resolve(&first.item_id, 2, NativeKind::Bearer),
            Err(Error::Locked)
        ));
        vault.authenticate(&passphrase)?;
        assert_eq!(vault.status(), VaultStatus::Locked);
        drop(vault);
        let mut vault = NativeVault::open(&path)?;
        vault.unlock(&passphrase)?;
        assert_eq!(vault.list()?, vec![second]);
        assert!(
            vault
                .resolve(&first.item_id, 2, NativeKind::Bearer)?
                .as_slice()
                .eq(replacement.as_slice())
        );
        vault.remove(&first.item_id, 2)?;
        assert!(matches!(
            vault.remove(&first.item_id, 2),
            Err(Error::NotFound)
        ));
        assert!(matches!(
            vault.resolve(&first.item_id, 2, NativeKind::Bearer),
            Err(Error::NotFound)
        ));
        drop(vault);
        let mut vault = NativeVault::open(&path)?;
        vault.unlock(&passphrase)?;
        assert!(vault.list()?.is_empty());
        no_temporaries(&path)?;
        Ok(())
    }

    #[test]
    fn native_wrong_passphrase_and_corruption_fail_closed() -> Result<(), Box<dyn std::error::Error>>
    {
        let (_directory, path) = directory()?;
        let passphrase = random(32);
        let wrong = random(32);
        let mut vault = NativeVault::open(&path)?;
        vault.initialize(&passphrase)?;
        vault.store(NativeKind::Password, random(128))?;
        assert!(matches!(
            vault.authenticate(&wrong),
            Err(Error::AuthenticationFailed)
        ));
        assert_eq!(vault.status(), VaultStatus::Locked);
        assert!(matches!(
            vault.unlock(&wrong),
            Err(Error::AuthenticationFailed)
        ));
        vault.unlock(&passphrase)?;
        let original = fs::read(path.join("native.vault"))?;
        let mut damaged = original.clone();
        let last = damaged.len() - 1;
        damaged[last] ^= 1;
        fs::write(path.join("native.vault"), &damaged)?;
        assert!(matches!(
            vault.unlock(&passphrase),
            Err(Error::AuthenticationFailed)
        ));
        assert_eq!(vault.status(), VaultStatus::Locked);
        damaged[0] ^= 1;
        fs::write(path.join("native.vault"), &damaged)?;
        assert!(matches!(
            vault.unlock(&passphrase),
            Err(Error::InvalidInput)
        ));
        fs::write(path.join("native.vault"), &original[..32])?;
        assert!(matches!(
            vault.unlock(&passphrase),
            Err(Error::InvalidInput)
        ));
        fs::write(path.join("native.vault"), &original)?;
        vault.unlock(&passphrase)?;
        assert_eq!(vault.list()?.len(), 1);
        Ok(())
    }

    #[test]
    fn native_writer_exclusion_and_private_paths() -> Result<(), Box<dyn std::error::Error>> {
        let (_directory, path) = directory()?;
        let mut vault = NativeVault::open(&path)?;
        assert!(matches!(NativeVault::open(&path), Err(Error::Busy)));
        vault.lock();
        assert!(matches!(NativeVault::open(&path), Err(Error::Busy)));
        drop(vault);
        drop(NativeVault::open(&path)?);
        let alias = path.join("alias");
        symlink(&path, &alias)?;
        assert!(matches!(NativeVault::open(&alias), Err(Error::Unavailable)));
        fs::remove_file(&alias)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
        assert!(matches!(NativeVault::open(&path), Err(Error::Unavailable)));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        let lock = path.join("native.lock");
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o644))?;
        assert!(matches!(NativeVault::open(&path), Err(Error::Unavailable)));
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o600))?;
        let linked = path.join("linked");
        fs::hard_link(&lock, &linked)?;
        assert!(matches!(NativeVault::open(&path), Err(Error::Unavailable)));
        fs::remove_file(&linked)?;
        let destination = path.join("native.vault");
        symlink(&lock, &destination)?;
        assert!(matches!(NativeVault::open(&path), Err(Error::Unavailable)));
        fs::remove_file(&destination)?;
        fs::hard_link(&lock, &destination)?;
        assert!(matches!(NativeVault::open(&path), Err(Error::Unavailable)));
        fs::remove_file(&destination)?;
        fs::write(&destination, [])?;
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o600))?;
        let before = fs::metadata(&destination)?.ino();
        let mut vault = NativeVault::open(&path)?;
        assert!(matches!(
            vault.initialize(&random(32)),
            Err(Error::AlreadyInitialized)
        ));
        assert_eq!(fs::metadata(&destination)?.ino(), before);
        Ok(())
    }

    #[test]
    fn native_publication_never_clobbers_an_existing_name() -> Result<(), Box<dyn std::error::Error>>
    {
        let (_directory, path) = directory()?;
        let source = path.join("source");
        let destination = path.join("native.vault");
        File::create(&source)?;
        File::create(&destination)?;
        let inode = fs::metadata(&destination)?.ino();
        assert!(matches!(
            rename_new(&source, &destination),
            Err(Error::AlreadyInitialized)
        ));
        assert_eq!(fs::metadata(&destination)?.ino(), inode);
        assert!(source.exists());
        fs::remove_file(&destination)?;
        symlink(&source, &destination)?;
        assert!(matches!(
            rename_new(&source, &destination),
            Err(Error::AlreadyInitialized)
        ));
        assert!(fs::symlink_metadata(&destination)?.is_symlink());
        fs::remove_file(&destination)?;
        let inode = fs::metadata(&source)?.ino();
        rename_new(&source, &destination)?;
        assert_eq!(fs::metadata(&destination)?.ino(), inode);
        assert!(!source.exists());
        assert_eq!(fs::metadata(&destination)?.nlink(), 1);
        Ok(())
    }

    #[test]
    fn native_atomic_failures_keep_old_or_lock_on_new_snapshot()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_directory, path) = directory()?;
        let passphrase = random(32);
        let value = random(128);
        let mut vault = NativeVault::open(&path)?;
        for fault in [Fault::Write, Fault::FileSync, Fault::Publish] {
            vault.fault = Some(fault);
            assert!(matches!(
                vault.initialize(&passphrase),
                Err(Error::Unavailable)
            ));
            assert_eq!(vault.status(), VaultStatus::Uninitialized);
            assert!(!path.join("native.vault").exists());
            no_temporaries(&path)?;
        }
        vault.fault = None;
        vault.initialize(&passphrase)?;
        let item = vault.store(NativeKind::Bearer, Zeroizing::new(value.to_vec()))?;
        let old_disk = fs::read(path.join("native.vault"))?;
        for fault in [Fault::Write, Fault::FileSync, Fault::Publish] {
            vault.fault = Some(fault);
            assert!(matches!(
                vault.update(&item.item_id, 1, random(128)),
                Err(Error::Unavailable)
            ));
            assert!(fs::read(path.join("native.vault"))?.eq(&old_disk));
            assert!(
                vault
                    .resolve(&item.item_id, 1, NativeKind::Bearer)?
                    .as_slice()
                    .eq(value.as_slice())
            );
            assert!(matches!(
                vault.remove(&item.item_id, 1),
                Err(Error::Unavailable)
            ));
            assert!(matches!(
                vault.store(NativeKind::Password, random(128)),
                Err(Error::Unavailable)
            ));
            assert!(fs::read(path.join("native.vault"))?.eq(&old_disk));
            assert_eq!(vault.list()?.len(), 1);
            no_temporaries(&path)?;
        }
        let replacement = random(128);
        vault.fault = Some(Fault::DirectorySync);
        assert!(matches!(
            vault.update(&item.item_id, 1, Zeroizing::new(replacement.to_vec())),
            Err(Error::StorageUncertain)
        ));
        assert_eq!(vault.status(), VaultStatus::Locked);
        assert!(matches!(vault.list(), Err(Error::Locked)));
        assert!(!fs::read(path.join("native.vault"))?.eq(&old_disk));
        no_temporaries(&path)?;
        drop(vault);
        let mut vault = NativeVault::open(&path)?;
        vault.unlock(&passphrase)?;
        assert!(
            vault
                .resolve(&item.item_id, 2, NativeKind::Bearer)?
                .as_slice()
                .eq(replacement.as_slice())
        );
        Ok(())
    }

    #[test]
    fn native_initialization_uncertain_is_locked_and_recoverable()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_directory, path) = directory()?;
        let passphrase = random(32);
        let mut vault = NativeVault::open(&path)?;
        vault.fault = Some(Fault::DirectorySync);
        assert!(matches!(
            vault.initialize(&passphrase),
            Err(Error::StorageUncertain)
        ));
        assert_eq!(vault.status(), VaultStatus::Locked);
        private_file(&fs::metadata(path.join("native.vault"))?)?;
        no_temporaries(&path)?;
        vault.fault = None;
        vault.unlock(&passphrase)?;
        assert!(vault.list()?.is_empty());
        Ok(())
    }

    fn test_item(index: usize, length: usize) -> Result<Item, Error> {
        Ok(Item {
            metadata: MetadataRecord {
                descriptor: descriptor(ItemId::new(format!("itm_{index}")), 1, NativeKind::Bearer)?,
                native_kind: NativeKind::Bearer,
            },
            value: random(length),
        })
    }

    #[test]
    fn native_payload_bounds_and_strict_binary_framing() -> Result<(), Box<dyn std::error::Error>> {
        let mut items = vec![test_item(0, MAX_VALUE)?];
        let encoded = encode_payload(items.iter())?;
        let decoded = decode_payload(&encoded, 1)?;
        assert!(decoded[0].value.as_slice().eq(items[0].value.as_slice()));
        let oversized = test_item(1, MAX_VALUE + 1)?;
        assert!(matches!(
            encode_payload(std::iter::once(&oversized)),
            Err(Error::TooLarge)
        ));
        let empty = test_item(1, 0)?;
        assert!(matches!(
            encode_payload(std::iter::once(&empty)),
            Err(Error::InvalidInput)
        ));
        for index in 1..256 {
            items.push(test_item(index, MAX_VALUE)?);
        }
        assert!(matches!(encode_payload(items.iter()), Err(Error::TooLarge)));
        let mut many = Vec::new();
        for index in 0..MAX_ITEMS {
            many.push(test_item(index, 1)?);
        }
        let encoded = encode_payload(many.iter())?;
        assert_eq!(decode_payload(&encoded, 1)?.len(), MAX_ITEMS);
        many.push(test_item(MAX_ITEMS, 1)?);
        assert!(matches!(encode_payload(many.iter()), Err(Error::TooLarge)));
        let duplicate = [test_item(0, 1)?, test_item(0, 1)?];
        assert!(matches!(
            decode_payload(&encode_payload(duplicate.iter())?, 1),
            Err(Error::InvalidInput)
        ));
        let mut malformed = Zeroizing::new(Vec::with_capacity(encoded.len() + 1));
        malformed.extend_from_slice(&encoded);
        malformed.push(0);
        assert!(matches!(
            decode_payload(&malformed, 1),
            Err(Error::InvalidInput)
        ));
        assert!(matches!(
            decode_payload(&encoded[..encoded.len() - 1], 1),
            Err(Error::InvalidInput)
        ));
        malformed[..8].fill(0);
        assert!(matches!(
            decode_payload(&malformed, 1),
            Err(Error::InvalidInput)
        ));
        Ok(())
    }
}
