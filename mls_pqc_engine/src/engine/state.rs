//! State management for MLS groups and members.
//!
//! Provides persistence and management for MLS group state,
//! including suite selection and PQC keypair storage.
//!
//! ## Persistence design
//!
//! Each GroupState is saved as TWO files:
//!   - `<path>.json`     — metadata snapshot (group_id, identity, suite, epoch)
//!   - `<path>.storage`  — full MemoryStorage dump (member tree, epoch keys, ratchet state)
//!
//! The `.storage` file is what actually makes load() work correctly.
//! Without it, load() would recreate a bare empty group (epoch 0, creator only).

use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_memory_storage::MemoryStorage;
use openmls_basic_credential::SignatureKeyPair;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufReader, BufWriter};
use tls_codec::Serialize as TlsSerialize;

use crate::error::{EngineError, EngineResult};
use crate::provider::DEFAULT_CIPHERSUITE;
use super::suite::CryptoSuite;

/// Serialize a MemoryStorage to bytes using a temp file.
pub fn storage_to_bytes(storage: &MemoryStorage) -> EngineResult<Vec<u8>> {
    let temp_file = tempfile::tempfile()
        .map_err(|e| EngineError::Storage(format!("Failed to create temp file: {}", e)))?;
    storage.save_to_file(&temp_file)
        .map_err(|e| EngineError::Storage(format!("Failed to save storage: {}", e)))?;
    use std::io::{Read, Seek, SeekFrom};
    let mut file = temp_file;
    file.seek(SeekFrom::Start(0))
        .map_err(|e| EngineError::Storage(format!("Seek error: {}", e)))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|e| EngineError::Storage(format!("Read error: {}", e)))?;
    Ok(bytes)
}

/// Restore a MemoryStorage from previously serialized bytes.
pub fn storage_from_bytes(bytes: &[u8]) -> EngineResult<MemoryStorage> {
    let temp_file = tempfile::tempfile()
        .map_err(|e| EngineError::Storage(format!("Failed to create temp file: {}", e)))?;
    use std::io::Write;
    let mut file = temp_file;
    file.write_all(bytes)
        .map_err(|e| EngineError::Storage(format!("Write error: {}", e)))?;
    use std::io::{Seek, SeekFrom};
    file.seek(SeekFrom::Start(0))
        .map_err(|e| EngineError::Storage(format!("Seek error: {}", e)))?;
    let mut storage = MemoryStorage::default();
    storage.load_from_file(&file)
        .map_err(|e| EngineError::Storage(format!("Failed to load storage: {}", e)))?;
    Ok(storage)
}

/// Current schema version for state serialization.
pub const CURRENT_SCHEMA_VERSION: u32 = 1;

// ============================================================================
// MemberIdentity
// ============================================================================

/// Member identity containing credentials and signing keys.
pub struct MemberIdentity {
    pub name: Vec<u8>,
    pub credential_with_key: CredentialWithKey,
    pub signature_keys: SignatureKeyPair,
}

impl MemberIdentity {
    pub fn new(name: &[u8], ciphersuite: Ciphersuite) -> EngineResult<Self> {
        let credential = BasicCredential::new(name.to_vec());
        let signature_keys = SignatureKeyPair::new(ciphersuite.signature_algorithm())
            .map_err(|e| EngineError::Crypto(format!("Failed to generate signature keys: {:?}", e)))?;

        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: signature_keys.to_public_vec().into(),
        };

        Ok(Self { name: name.to_vec(), credential_with_key, signature_keys })
    }

    pub fn store_keys(&self, provider: &OpenMlsRustCrypto) -> EngineResult<()> {
        self.signature_keys.store(provider.storage())
            .map_err(|e| EngineError::Storage(format!("Failed to store signature keys: {:?}", e)))
    }

    pub fn to_bytes(&self) -> EngineResult<SerializedIdentity> {
        let sig_key_bytes = self.signature_keys.tls_serialize_detached()
            .map_err(|e| EngineError::Serialization(format!("Failed to serialize signature keys: {:?}", e)))?;
        Ok(SerializedIdentity { name: self.name.clone(), signature_key_bytes: sig_key_bytes })
    }

    pub fn from_serialized(data: SerializedIdentity) -> EngineResult<Self> {
        let signature_keys = SignatureKeyPair::tls_deserialize_exact_bytes(&data.signature_key_bytes)
            .map_err(|e| EngineError::Deserialization(format!("Failed to deserialize signature keys: {:?}", e)))?;
        let credential = BasicCredential::new(data.name.clone());
        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: signature_keys.to_public_vec().into(),
        };
        Ok(Self { name: data.name, credential_with_key, signature_keys })
    }
}

// ============================================================================
// Serializable types
// ============================================================================

#[derive(Serialize, Deserialize, Clone)]
pub struct SerializedIdentity {
    pub name: Vec<u8>,
    pub signature_key_bytes: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MemberInfo {
    pub leaf_index: u32,
    pub identity: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SerializedPqcKeyPair {
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SerializedKeyPackageData {
    pub schema_version: u32,
    pub identity: SerializedIdentity,
    pub suite: CryptoSuite,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pqc_keypair: Option<SerializedPqcKeyPair>,
    /// Serialized MemoryStorage bytes (base64-encoded JSON) containing the HPKE
    /// init private key needed to process a Welcome message in join-group.
    /// Without this, StagedWelcome will fail with NoMatchingKeyPackage.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_storage_bytes: Option<Vec<u8>>,
}

impl SerializedKeyPackageData {
    pub fn save(&self, path: &str) -> EngineResult<()> {
        let file = File::create(path)?;
        let writer = BufWriter::new(file);
        serde_json::to_writer_pretty(writer, self)
            .map_err(|e| EngineError::Serialization(e.to_string()))?;
        Ok(())
    }

    pub fn load(path: &str) -> EngineResult<Self> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let data: Self = serde_json::from_reader(reader)
            .map_err(|e| EngineError::Deserialization(e.to_string()))?;
        if data.schema_version > CURRENT_SCHEMA_VERSION {
            return Err(EngineError::Deserialization(
                format!("Unsupported schema version {} (max supported: {})",
                    data.schema_version, CURRENT_SCHEMA_VERSION)
            ));
        }
        Ok(data)
    }
}

// ============================================================================
// GroupState
// ============================================================================

/// Holds the runtime state of an MLS group.
pub struct GroupState {
    pub group: MlsGroup,
    pub identity: MemberIdentity,
    pub provider: OpenMlsRustCrypto,
    pub suite: CryptoSuite,
    pub pqc_keypair: Option<SerializedPqcKeyPair>,
}

impl GroupState {
    pub fn new(group_id: &[u8], identity: MemberIdentity) -> EngineResult<Self> {
        Self::new_with_suite(group_id, identity, CryptoSuite::Classic, None)
    }

    pub fn new_with_suite(
        group_id: &[u8],
        identity: MemberIdentity,
        suite: CryptoSuite,
        pqc_keypair: Option<SerializedPqcKeyPair>,
    ) -> EngineResult<Self> {
        let provider = OpenMlsRustCrypto::default();
        identity.store_keys(&provider)?;

        let group_config = MlsGroupCreateConfig::builder()
            .ciphersuite(DEFAULT_CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .build();

        let group = MlsGroup::new_with_group_id(
            &provider,
            &identity.signature_keys,
            &group_config,
            GroupId::from_slice(group_id),
            identity.credential_with_key.clone(),
        ).map_err(|e| EngineError::GroupCreation(format!("{:?}", e)))?;

        Ok(Self { group, identity, provider, suite, pqc_keypair })
    }

    pub fn from_group(
        group: MlsGroup,
        identity: MemberIdentity,
        provider: OpenMlsRustCrypto,
    ) -> Self {
        Self { group, identity, provider, suite: CryptoSuite::Classic, pqc_keypair: None }
    }

    pub fn from_group_with_suite(
        group: MlsGroup,
        identity: MemberIdentity,
        provider: OpenMlsRustCrypto,
        suite: CryptoSuite,
        pqc_keypair: Option<SerializedPqcKeyPair>,
    ) -> Self {
        Self { group, identity, provider, suite, pqc_keypair }
    }

    // -------------------------------------------------------------------------
    // Persistence
    // -------------------------------------------------------------------------

    /// Save group state to disk.
    ///
    /// Writes two files:
    ///   - `path`          — JSON metadata (group_id, identity, suite, epoch)
    ///   - `path.storage`  — MemoryStorage dump (full MlsGroup internal state)
    ///
    /// Both files are required for load() to correctly restore the group.
    pub fn save(&self, path: &str) -> EngineResult<()> {
        // 1. Save the MemoryStorage to a sidecar file.
        //    This captures the full MlsGroup state: member tree, epoch ratchet keys, etc.
        let storage_path = format!("{}.storage", path);
        let storage_file = File::create(&storage_path)?;
        self.provider
            .storage()
            .save_to_file(&storage_file)
            .map_err(|e| EngineError::Serialization(
                format!("Failed to save provider storage: {}", e)
            ))?;

        // 2. Save the metadata snapshot.
        let snapshot = GroupStateSnapshot {
            schema_version: CURRENT_SCHEMA_VERSION,
            group_id: self.group.group_id().as_slice().to_vec(),
            identity: self.identity.to_bytes()?,
            epoch: self.group.epoch().as_u64(),
            suite: self.suite,
            pqc_keypair: self.pqc_keypair.clone(),
        };

        let file = File::create(path)?;
        let writer = BufWriter::new(file);
        serde_json::to_writer_pretty(writer, &snapshot)
            .map_err(|e| EngineError::Serialization(e.to_string()))?;

        Ok(())
    }

    /// Load group state from disk.
    ///
    /// Reads `path` for metadata and `path.storage` for full MlsGroup state.
    /// If `.storage` is missing (old format), falls back to a bare empty group.
    pub fn load(path: &str) -> EngineResult<Self> {
        // 1. Load the metadata snapshot.
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let snapshot: GroupStateSnapshot = serde_json::from_reader(reader)
            .map_err(|e| EngineError::Deserialization(e.to_string()))?;

        if snapshot.schema_version > CURRENT_SCHEMA_VERSION {
            return Err(EngineError::Deserialization(
                format!("Unsupported state schema version {} (max supported: {})",
                    snapshot.schema_version, CURRENT_SCHEMA_VERSION)
            ));
        }

        let identity = MemberIdentity::from_serialized(snapshot.identity)?;
        let suite = snapshot.suite;
        let pqc_keypair = snapshot.pqc_keypair;

        // 2. Check for the sidecar storage file.
        let storage_path = format!("{}.storage", path);
        if !std::path::Path::new(&storage_path).exists() {
            // Legacy fallback: no sidecar, recreate a bare group.
            // Epoch and member list will be reset to initial state.
            return GroupState::new_with_suite(&snapshot.group_id, identity, suite, pqc_keypair);
        }

        // 3. Reconstruct MemoryStorage from the sidecar.
        let mut storage = MemoryStorage::default();
        let storage_file = File::open(&storage_path)?;
        storage
            .load_from_file(&storage_file)
            .map_err(|e| EngineError::Deserialization(
                format!("Failed to load provider storage: {}", e)
            ))?;

        // 4. Build a fresh provider and transplant all loaded key-value pairs into it.
        //    OpenMlsRustCrypto has no public constructor accepting MemoryStorage,
        //    but MemoryStorage.values is a public RwLock<HashMap>, so we can copy
        //    all entries directly.
        let provider = OpenMlsRustCrypto::default();
        transplant_storage(&storage, provider.storage())?;

        // Re-store signature keys (idempotent, ensures they are accessible).
        identity.store_keys(&provider)?;

        // 5. Load the MlsGroup from the restored provider storage.
        let group_id = GroupId::from_slice(&snapshot.group_id);
        let group = MlsGroup::load(provider.storage(), &group_id)
            .map_err(|e| EngineError::Deserialization(
                format!("Failed to load MlsGroup from storage: {:?}", e)
            ))?
            .ok_or_else(|| EngineError::Deserialization(
                format!("Group '{}' not found in restored storage",
                    String::from_utf8_lossy(&snapshot.group_id))
            ))?;

        Ok(Self { group, identity, provider, suite, pqc_keypair })
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    pub fn group_id_string(&self) -> String {
        String::from_utf8_lossy(self.group.group_id().as_slice()).to_string()
    }

    pub fn epoch(&self) -> u64 {
        self.group.epoch().as_u64()
    }

    pub fn list_members(&self) -> Vec<MemberInfo> {
        self.group
            .members()
            .map(|member| {
                let identity_bytes = member.credential.serialized_content();
                let identity = String::from_utf8_lossy(identity_bytes).to_string();
                MemberInfo { leaf_index: member.index.u32(), identity }
            })
            .collect()
    }

    pub fn find_member(&self, identity: &str) -> Option<u32> {
        self.group.members().find_map(|member| {
            let s = String::from_utf8_lossy(member.credential.serialized_content());
            if s == identity { Some(member.index.u32()) } else { None }
        })
    }
}

// ============================================================================
// Storage transplant helper
// ============================================================================

/// Copy all key-value pairs from `src` into `dst`.
///
/// `OpenMlsRustCrypto` has no public constructor that accepts an existing
/// `MemoryStorage`, so we Default-construct a provider and then replay all
/// entries from the loaded storage into its internal store via the public
/// `values: RwLock<HashMap<Vec<u8>, Vec<u8>>>` field.
fn transplant_storage(src: &MemoryStorage, dst: &MemoryStorage) -> EngineResult<()> {
    let src_values = src.values.read()
        .map_err(|_| EngineError::Storage("Failed to read source storage".into()))?;
    let mut dst_values = dst.values.write()
        .map_err(|_| EngineError::Storage("Failed to write destination storage".into()))?;

    for (k, v) in src_values.iter() {
        dst_values.insert(k.clone(), v.clone());
    }

    Ok(())
}

// ============================================================================
// Snapshot (on-disk format)
// ============================================================================

fn default_schema_version() -> u32 { 1 }

/// Metadata snapshot saved alongside the `.storage` sidecar file.
#[derive(Serialize, Deserialize)]
struct GroupStateSnapshot {
    #[serde(default = "default_schema_version")]
    schema_version: u32,
    group_id: Vec<u8>,
    identity: SerializedIdentity,
    /// Epoch at save time (informational; authoritative epoch is in the storage sidecar).
    epoch: u64,
    #[serde(default)]
    suite: CryptoSuite,
    #[serde(default)]
    pqc_keypair: Option<SerializedPqcKeyPair>,
}
