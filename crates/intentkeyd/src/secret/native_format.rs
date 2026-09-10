//! Authenticated, bounded native-vault envelope.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use intentkey_core::owner::SecretErrorCode as Error;
use zeroize::Zeroizing;

const HEADER: usize = 148;
const LIMIT: usize = 16 * 1024 * 1024;
const TAG: usize = 16;
type DecodedSnapshot = (Envelope, Zeroizing<Vec<u8>>, u64);

pub(super) struct Envelope {
    header: [u8; HEADER],
    key: Zeroizing<[u8; 32]>,
}

fn wrapping_key(passphrase: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, Error> {
    if passphrase.is_empty() || passphrase.len() > 1024 {
        return Err(Error::InvalidInput);
    }
    let params = Params::new(65_536, 3, 1, Some(32)).map_err(|_| Error::Unavailable)?;
    let mut key = Zeroizing::new([0_u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase, salt, key.as_mut())
        .map_err(|_| Error::Unavailable)?;
    Ok(key)
}

fn aad(domain: &[u8], header: &[u8]) -> Vec<u8> {
    [domain, header].concat()
}

impl Envelope {
    pub(super) fn create(passphrase: &[u8]) -> Result<Self, Error> {
        let mut header = [0_u8; HEADER];
        header[..8].copy_from_slice(b"IKVAULT1");
        header[8..10].copy_from_slice(&1_u16.to_be_bytes());
        header[10..12].copy_from_slice(&148_u16.to_be_bytes());
        header[12..16].copy_from_slice(&65_536_u32.to_be_bytes());
        header[16..20].copy_from_slice(&3_u32.to_be_bytes());
        header[20..24].copy_from_slice(&1_u32.to_be_bytes());
        getrandom::fill(&mut header[24..64]).map_err(|_| Error::Unavailable)?;
        let mut key = Zeroizing::new([0_u8; 32]);
        getrandom::fill(key.as_mut()).map_err(|_| Error::Unavailable)?;
        let wrapping = wrapping_key(passphrase, &header[24..40])?;
        let cipher =
            XChaCha20Poly1305::new_from_slice(wrapping.as_ref()).map_err(|_| Error::Unavailable)?;
        let wrapped = cipher
            .encrypt(
                &XNonce::try_from(&header[40..64]).map_err(|_| Error::InvalidInput)?,
                Payload {
                    msg: key.as_ref(),
                    aad: &aad(b"intentkey/dek/v1", &header[..64]),
                },
            )
            .map_err(|_| Error::Unavailable)?;
        header[64..112].copy_from_slice(&wrapped);
        Ok(Self { header, key })
    }

    pub(super) fn encode(&self, payload: &[u8], generation: u64) -> Result<Vec<u8>, Error> {
        if payload.len() > LIMIT - HEADER - TAG || generation == 0 {
            return Err(Error::TooLarge);
        }
        let mut header = self.header;
        getrandom::fill(&mut header[112..136]).map_err(|_| Error::Unavailable)?;
        let length = u32::try_from(payload.len() + TAG).map_err(|_| Error::TooLarge)?;
        header[136..140].copy_from_slice(&length.to_be_bytes());
        header[140..].copy_from_slice(&generation.to_be_bytes());
        let cipher =
            XChaCha20Poly1305::new_from_slice(self.key.as_ref()).map_err(|_| Error::Unavailable)?;
        let ciphertext = cipher
            .encrypt(
                &XNonce::try_from(&header[112..136]).map_err(|_| Error::InvalidInput)?,
                Payload {
                    msg: payload,
                    aad: &aad(b"intentkey/snapshot/v1", &header),
                },
            )
            .map_err(|_| Error::Unavailable)?;
        Ok([header.as_slice(), ciphertext.as_slice()].concat())
    }

    pub(super) fn decode(passphrase: &[u8], bytes: &[u8]) -> Result<DecodedSnapshot, Error> {
        if !(HEADER + TAG..=LIMIT).contains(&bytes.len()) {
            return Err(Error::InvalidInput);
        }
        let header: [u8; HEADER] = bytes[..HEADER]
            .try_into()
            .map_err(|_| Error::InvalidInput)?;
        if &header[..8] != b"IKVAULT1"
            || header[8..12] != [0, 1, 0, 148]
            || header[12..16] != 65_536_u32.to_be_bytes()
            || header[16..20] != 3_u32.to_be_bytes()
            || header[20..24] != 1_u32.to_be_bytes()
        {
            return Err(Error::InvalidInput);
        }
        let length = u32::from_be_bytes(
            header[136..140]
                .try_into()
                .map_err(|_| Error::InvalidInput)?,
        );
        let generation =
            u64::from_be_bytes(header[140..].try_into().map_err(|_| Error::InvalidInput)?);
        if usize::try_from(length).map_err(|_| Error::InvalidInput)? != bytes.len() - HEADER
            || generation == 0
        {
            return Err(Error::InvalidInput);
        }
        let wrapping = wrapping_key(passphrase, &header[24..40])?;
        let cipher =
            XChaCha20Poly1305::new_from_slice(wrapping.as_ref()).map_err(|_| Error::Unavailable)?;
        let raw_key = Zeroizing::new(
            cipher
                .decrypt(
                    &XNonce::try_from(&header[40..64]).map_err(|_| Error::InvalidInput)?,
                    Payload {
                        msg: &header[64..112],
                        aad: &aad(b"intentkey/dek/v1", &header[..64]),
                    },
                )
                .map_err(|_| Error::AuthenticationFailed)?,
        );
        let mut key = Zeroizing::new([0_u8; 32]);
        if raw_key.len() != key.len() {
            return Err(Error::AuthenticationFailed);
        }
        key.copy_from_slice(&raw_key);
        let cipher =
            XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| Error::Unavailable)?;
        let payload = Zeroizing::new(
            cipher
                .decrypt(
                    &XNonce::try_from(&header[112..136]).map_err(|_| Error::InvalidInput)?,
                    Payload {
                        msg: &bytes[HEADER..],
                        aad: &aad(b"intentkey/snapshot/v1", &header),
                    },
                )
                .map_err(|_| Error::AuthenticationFailed)?,
        );
        Ok((Self { header, key }, payload, generation))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_envelope_encrypts_generated_material_without_plaintext() {
        let mut passphrase = Zeroizing::new(vec![0_u8; 32]);
        let mut payload = Zeroizing::new(vec![0_u8; 128]);
        getrandom::fill(&mut passphrase).expect("OS randomness");
        getrandom::fill(&mut payload).expect("OS randomness");
        let encrypted = Envelope::create(&passphrase).and_then(|vault| vault.encode(&payload, 1));
        assert!(encrypted.is_ok(), "native encryption must be available");
        if let Ok(encrypted) = encrypted {
            assert!(
                !encrypted
                    .windows(payload.len())
                    .any(|part| part == payload.as_slice()),
                "vault output must not contain the input"
            );
            let (_, decoded, generation) =
                Envelope::decode(&passphrase, &encrypted).expect("authenticated roundtrip");
            assert!(
                decoded.as_slice().eq(payload.as_slice()),
                "payload preserved"
            );
            assert_eq!(generation, 1);
            let mut tampered = encrypted.clone();
            tampered[HEADER] ^= 1;
            assert!(matches!(
                Envelope::decode(&passphrase, &tampered),
                Err(Error::AuthenticationFailed)
            ));
            let mut invalid_profile = encrypted;
            invalid_profile[12..16].copy_from_slice(&u32::MAX.to_be_bytes());
            assert!(matches!(
                Envelope::decode(&passphrase, &invalid_profile),
                Err(Error::InvalidInput)
            ));
        }
    }
}
