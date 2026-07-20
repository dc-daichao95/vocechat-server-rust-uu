//! Pure MLS group messaging built on OpenMLS.

pub mod application;
pub mod commands;

use openmls::prelude::tls_codec::{Deserialize, Serialize};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::{MemoryStorage, RustCrypto};
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// Opaque error returned by the MLS facade.
#[derive(Debug, thiserror::Error)]
#[error("MLS operation failed: {0}")]
pub struct MlsError(String);

fn mls_error(error: impl core::fmt::Debug) -> MlsError {
    MlsError(format!("{error:?}"))
}

#[derive(Debug, Default)]
struct MlsProvider {
    crypto: RustCrypto,
    storage: MemoryStorage,
}

impl OpenMlsProvider for MlsProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = MemoryStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

#[derive(SerdeSerialize, SerdeDeserialize)]
struct GroupSnapshot {
    signer: SignatureKeyPair,
    group_id: Vec<u8>,
    storage: Vec<(Vec<u8>, Vec<u8>)>,
}

#[derive(SerdeSerialize, SerdeDeserialize)]
struct DeviceSnapshot {
    signer: SignatureKeyPair,
    identity: Vec<u8>,
    storage: Vec<(Vec<u8>, Vec<u8>)>,
}

/// A device identity and its local OpenMLS key store.
pub struct MlsClient {
    provider: MlsProvider,
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
    identity: Vec<u8>,
}

/// A key package published by a device for one-time group admission.
pub struct MlsKeyPackage(KeyPackage);

/// A Welcome and the authenticated public tree needed to join its group.
pub struct MlsWelcome {
    welcome: Welcome,
    ratchet_tree: RatchetTreeIn,
}

/// The Commit for existing members and Welcome bundle for newly admitted members.
pub struct MlsAdmission {
    commit: Vec<u8>,
    welcome: MlsWelcome,
}

/// Result of processing one MLS protocol wire message.
pub enum MlsProcessed {
    Application(Vec<u8>),
    Commit,
}

/// An active MLS group bound to a single device.
pub struct MlsGroupState {
    provider: MlsProvider,
    signer: SignatureKeyPair,
    group: MlsGroup,
}

impl MlsClient {
    /// Generate an MLS device credential. The caller owns the identity bytes.
    pub fn generate(identity: &[u8]) -> Result<Self, MlsError> {
        let provider = MlsProvider::default();
        let credential = BasicCredential::new(identity.to_vec());
        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).map_err(mls_error)?;
        signer.store(provider.storage()).map_err(mls_error)?;
        let credential = CredentialWithKey {
            credential: credential.into(),
            signature_key: signer.public().into(),
        };

        Ok(Self {
            provider,
            signer,
            credential,
            identity: identity.to_vec(),
        })
    }

    /// Serialize device credential state for platform-protected persistence.
    pub fn snapshot(&self) -> Result<Vec<u8>, MlsError> {
        serde_json::to_vec(&DeviceSnapshot {
            signer: self.signer.clone(),
            identity: self.identity.clone(),
            storage: snapshot_storage(&self.provider)?,
        })
        .map_err(mls_error)
    }

    /// Restore device state previously returned by [`Self::snapshot`].
    pub fn restore(snapshot: &[u8]) -> Result<Self, MlsError> {
        let snapshot: DeviceSnapshot = serde_json::from_slice(snapshot).map_err(mls_error)?;
        let provider = provider_from_storage(snapshot.storage)?;
        let credential = CredentialWithKey {
            credential: BasicCredential::new(snapshot.identity.clone()).into(),
            signature_key: snapshot.signer.public().into(),
        };
        Ok(Self {
            provider,
            signer: snapshot.signer,
            credential,
            identity: snapshot.identity,
        })
    }

    /// Create a fresh one-time KeyPackage for this device.
    pub fn key_package(&mut self) -> Result<MlsKeyPackage, MlsError> {
        let bundle = KeyPackage::builder()
            .build(
                CIPHERSUITE,
                &self.provider,
                &self.signer,
                self.credential.clone(),
            )
            .map_err(mls_error)?;
        Ok(MlsKeyPackage(bundle.key_package().clone()))
    }

    /// Consume the device state to create a new group.
    pub fn create_group(self, group_id: &[u8]) -> Result<MlsGroupState, MlsError> {
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
            .build();
        let group = MlsGroup::new_with_group_id(
            &self.provider,
            &self.signer,
            &config,
            GroupId::from_slice(group_id),
            self.credential,
        )
        .map_err(mls_error)?;

        Ok(MlsGroupState {
            provider: self.provider,
            signer: self.signer,
            group,
        })
    }

    /// Consume the device state and join from a Welcome.
    pub fn join_group(self, welcome: &MlsWelcome) -> Result<MlsGroupState, MlsError> {
        let group = StagedWelcome::new_from_welcome(
            &self.provider,
            &MlsGroupJoinConfig::default(),
            welcome.welcome.clone(),
            Some(welcome.ratchet_tree.clone()),
        )
        .map_err(mls_error)?
        .into_group(&self.provider)
        .map_err(mls_error)?;

        Ok(MlsGroupState {
            provider: self.provider,
            signer: self.signer,
            group,
        })
    }
}

impl MlsKeyPackage {
    pub fn to_bytes(&self) -> Result<Vec<u8>, MlsError> {
        self.0.tls_serialize_detached().map_err(mls_error)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MlsError> {
        let provider = MlsProvider::default();
        let input = KeyPackageIn::tls_deserialize_exact(bytes).map_err(mls_error)?;
        let package = input
            .validate(provider.crypto(), ProtocolVersion::Mls10)
            .map_err(mls_error)?;
        Ok(Self(package))
    }
}

impl MlsWelcome {
    pub fn to_bytes(&self) -> Result<Vec<u8>, MlsError> {
        let welcome = self.welcome.tls_serialize_detached().map_err(mls_error)?;
        let tree = self
            .ratchet_tree
            .tls_serialize_detached()
            .map_err(mls_error)?;
        let mut output = Vec::with_capacity(8 + welcome.len() + tree.len());
        append_len_prefixed(&mut output, &welcome)?;
        append_len_prefixed(&mut output, &tree)?;
        Ok(output)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MlsError> {
        let (welcome, remaining) = take_len_prefixed(bytes)?;
        let (tree, remaining) = take_len_prefixed(remaining)?;
        if !remaining.is_empty() {
            return Err(MlsError("trailing Welcome bundle bytes".into()));
        }
        Ok(Self {
            welcome: Welcome::tls_deserialize_exact(welcome).map_err(mls_error)?,
            ratchet_tree: RatchetTreeIn::tls_deserialize_exact(tree).map_err(mls_error)?,
        })
    }
}

impl MlsGroupState {
    /// Current RFC 9420 group epoch for authenticated routing metadata.
    pub fn epoch(&self) -> u64 {
        self.group.epoch().as_u64()
    }

    /// Return authenticated BasicCredential identities currently in the tree.
    pub fn member_identities(&self) -> Vec<Vec<u8>> {
        self.group
            .members()
            .map(|member| member.credential.serialized_content().to_vec())
            .collect()
    }

    /// Remove the leaves matching authenticated credential identities.
    pub fn remove_identities(&mut self, identities: &[Vec<u8>]) -> Result<Vec<u8>, MlsError> {
        let indices = self
            .group
            .members()
            .filter(|member| {
                identities
                    .iter()
                    .any(|identity| member.credential.serialized_content() == identity)
            })
            .map(|member| member.index)
            .collect::<Vec<_>>();
        if indices.is_empty() {
            return Err(MlsError("no matching MLS members to remove".into()));
        }
        let (commit, _, _) = self
            .group
            .remove_members(&self.provider, &self.signer, &indices)
            .map_err(mls_error)?;
        let commit = commit.tls_serialize_detached().map_err(mls_error)?;
        self.group
            .merge_pending_commit(&self.provider)
            .map_err(mls_error)?;
        Ok(commit)
    }

    /// Serialize all secret group state for platform-protected persistence.
    ///
    /// The returned bytes contain key material and must be wrapped by the
    /// platform keystore before they leave process memory.
    pub fn snapshot(&self) -> Result<Vec<u8>, MlsError> {
        serde_json::to_vec(&GroupSnapshot {
            signer: self.signer.clone(),
            group_id: self.group.group_id().to_vec(),
            storage: snapshot_storage(&self.provider)?,
        })
        .map_err(mls_error)
    }

    /// Restore group state previously returned by [`Self::snapshot`].
    pub fn restore(snapshot: &[u8]) -> Result<Self, MlsError> {
        let snapshot: GroupSnapshot = serde_json::from_slice(snapshot).map_err(mls_error)?;
        let provider = provider_from_storage(snapshot.storage)?;
        let group_id = GroupId::from_slice(&snapshot.group_id);
        let group = MlsGroup::load(provider.storage(), &group_id)
            .map_err(mls_error)?
            .ok_or_else(|| MlsError("snapshot contains no MLS group state".into()))?;

        Ok(Self {
            provider,
            signer: snapshot.signer,
            group,
        })
    }

    /// Add one member and return its Welcome message.
    pub fn add_member(&mut self, key_package: MlsKeyPackage) -> Result<MlsWelcome, MlsError> {
        self.add_members(vec![key_package])
    }

    /// Add all devices in one Commit so every Welcome joins the same epoch.
    pub fn add_members(
        &mut self,
        key_packages: Vec<MlsKeyPackage>,
    ) -> Result<MlsWelcome, MlsError> {
        Ok(self.add_members_with_commit(key_packages)?.welcome)
    }

    /// Add devices and return both artifacts required to advance every member.
    pub fn add_members_with_commit(
        &mut self,
        key_packages: Vec<MlsKeyPackage>,
    ) -> Result<MlsAdmission, MlsError> {
        if key_packages.is_empty() {
            return Err(MlsError("at least one KeyPackage is required".into()));
        }
        let key_packages = key_packages
            .into_iter()
            .map(|package| package.0)
            .collect::<Vec<_>>();
        let (commit, welcome, _) = self
            .group
            .add_members(&self.provider, &self.signer, &key_packages)
            .map_err(mls_error)?;
        let commit = commit.tls_serialize_detached().map_err(mls_error)?;
        self.group
            .merge_pending_commit(&self.provider)
            .map_err(mls_error)?;
        let serialized_welcome = welcome.tls_serialize_detached().map_err(mls_error)?;
        let welcome =
            MlsMessageIn::tls_deserialize(&mut serialized_welcome.as_slice()).map_err(mls_error)?;
        let welcome = match welcome.extract() {
            MlsMessageBodyIn::Welcome(welcome) => welcome,
            _ => {
                return Err(MlsError(
                    "OpenMLS returned a non-Welcome message after add_members".into(),
                ))
            }
        };

        Ok(MlsAdmission {
            commit,
            welcome: MlsWelcome {
                welcome,
                ratchet_tree: self.group.export_ratchet_tree().into(),
            },
        })
    }

    /// Return the serialized MLS Commit that existing members must process.
    pub fn admission_commit(admission: &MlsAdmission) -> &[u8] {
        &admission.commit
    }

    /// Return the Welcome bundle that newly admitted members consume.
    pub fn admission_welcome(admission: MlsAdmission) -> MlsWelcome {
        admission.welcome
    }

    /// Encrypt an application payload as an MLS PrivateMessage wire blob.
    pub fn encrypt_application(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, MlsError> {
        self.group
            .create_message(&self.provider, &self.signer, plaintext)
            .map_err(mls_error)?
            .tls_serialize_detached()
            .map_err(mls_error)
    }

    /// Authenticate and decrypt an MLS application PrivateMessage wire blob.
    pub fn decrypt_application(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, MlsError> {
        match self.process_message(ciphertext)? {
            MlsProcessed::Application(plaintext) => Ok(plaintext),
            MlsProcessed::Commit => Err(MlsError("expected an MLS application message".into())),
        }
    }

    /// Authenticate a protocol message and merge Commit state when necessary.
    pub fn process_message(&mut self, ciphertext: &[u8]) -> Result<MlsProcessed, MlsError> {
        let message = MlsMessageIn::tls_deserialize(&mut ciphertext.as_ref()).map_err(mls_error)?;
        let protocol_message = message.try_into_protocol_message().map_err(mls_error)?;
        // OpenMLS 0.8 has a debug assertion on AEAD failure. Convert that
        // assertion to a normal facade error so malformed network input can
        // never unwind across FFI/WASM boundaries.
        let processed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.group.process_message(&self.provider, protocol_message)
        }))
        .map_err(|_| MlsError("MLS ciphertext authentication failed".into()))?
        .map_err(mls_error)?;

        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(message) => {
                Ok(MlsProcessed::Application(message.into_bytes()))
            }
            ProcessedMessageContent::StagedCommitMessage(commit) => {
                self.group
                    .merge_staged_commit(&self.provider, *commit)
                    .map_err(mls_error)?;
                Ok(MlsProcessed::Commit)
            }
            _ => Err(MlsError("expected an MLS application message".into())),
        }
    }
}

fn snapshot_storage(provider: &MlsProvider) -> Result<Vec<(Vec<u8>, Vec<u8>)>, MlsError> {
    Ok(provider
        .storage
        .values
        .read()
        .map_err(mls_error)?
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect())
}

fn provider_from_storage(storage: Vec<(Vec<u8>, Vec<u8>)>) -> Result<MlsProvider, MlsError> {
    let provider = MlsProvider::default();
    provider
        .storage
        .values
        .write()
        .map_err(mls_error)?
        .extend(storage);
    Ok(provider)
}

fn append_len_prefixed(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), MlsError> {
    let length = u32::try_from(bytes.len())
        .map_err(|_| MlsError("MLS artifact exceeds maximum wire length".into()))?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

fn take_len_prefixed(input: &[u8]) -> Result<(&[u8], &[u8]), MlsError> {
    if input.len() < 4 {
        return Err(MlsError("truncated MLS artifact length".into()));
    }
    let length = u32::from_be_bytes(input[..4].try_into().map_err(mls_error)?) as usize;
    if length > input.len() - 4 {
        return Err(MlsError("truncated MLS artifact".into()));
    }
    Ok((&input[4..4 + length], &input[4 + length..]))
}
