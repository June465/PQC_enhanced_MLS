//! State management for MLS groups and members.
//!
//! Provides persistence and management for MLS group state,
//! including suite selection and PQC keypair storage.

use openmls::prelude::*;
use openmls_rust_crypto::{MemoryStorage, OpenMlsRustCrypto};
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
/// Increment when making breaking changes to state format.
pub const CURRENT_SCHEMA_VERSION: u32 = 1;

/// Member identity containing credentials and signing keys.
pub struct MemberIdentity {
    /// The member's display name / identity bytes.
    pub name: Vec<u8>,
    /// The credential with associated public key.
    pub credential_with_key: CredentialWithKey,
    /// The signature key pair for this member.
    pub signature_keys: SignatureKeyPair,
}

impl MemberIdentity {
    /// Create a new member identity with the given name.
    pub fn new(name: &[u8], ciphersuite: Ciphersuite) -> EngineResult<Self> {
        let credential = BasicCredential::new(name.to_vec());
        let signature_keys = SignatureKeyPair::new(ciphersuite.signature_algorithm())
            .map_err(|e| EngineError::Crypto(format!("Failed to generate signature keys: {:?}", e)))?;
        
        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: signature_keys.to_public_vec().into(),
        };

        Ok(Self {
            name: name.to_vec(),
            credential_with_key,
            signature_keys,
        })
    }
    
    /// Store the signature keys in the provider's storage.
    pub fn store_keys(&self, provider: &OpenMlsRustCrypto) -> EngineResult<()> {
        self.signature_keys.store(provider.storage())
            .map_err(|e| EngineError::Storage(format!("Failed to store signature keys: {:?}", e)))
    }
    
    /// Serialize identity to bytes for persistence using TLS encoding.
    pub fn to_bytes(&self) -> EngineResult<SerializedIdentity> {
        // Use TLS serialization for signature keys
        let sig_key_bytes = self.signature_keys.tls_serialize_detached()
            .map_err(|e| EngineError::Serialization(format!("Failed to serialize signature keys: {:?}", e)))?;
        
        Ok(SerializedIdentity {
            name: self.name.clone(),
            signature_key_bytes: sig_key_bytes,
        })
    }
    
    /// Create identity from serialized data.
    pub fn from_serialized(data: SerializedIdentity) -> EngineResult<Self> {
        // Deserialize signature keys using TLS encoding
        let signature_keys = SignatureKeyPair::tls_deserialize_exact_bytes(&data.signature_key_bytes)
            .map_err(|e| EngineError::Deserialization(format!("Failed to deserialize signature keys: {:?}", e)))?;
        
        // Reconstruct credential
        let credential = BasicCredential::new(data.name.clone());
        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: signature_keys.to_public_vec().into(),
        };
        
        Ok(Self {
            name: data.name,
            credential_with_key,
            signature_keys,
        })
    }
}

/// Serializable representation of MemberIdentity
#[derive(Serialize, Deserialize, Clone)]
pub struct SerializedIdentity {
    pub name: Vec<u8>,
    /// TLS-encoded SignatureKeyPair bytes
    pub signature_key_bytes: Vec<u8>,
}

/// Information about a group member for listing and export.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MemberInfo {
    /// The member's leaf index in the group tree.
    pub leaf_index: u32,
    /// The member's identity string (decoded from credential).
    pub identity: String,
}

/// Serializable PQC/Hybrid keypair for persistence
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SerializedPqcKeyPair {
    /// Public key (PQC or Hybrid combined)
    pub public_key: Vec<u8>,
    /// Private key (PQC or Hybrid combined)
    pub private_key: Vec<u8>,
}

/// Serializable KeyPackageData for CLI persistence.
/// Used to store the private key material needed for join-group operations.
#[derive(Serialize, Deserialize, Clone)]
pub struct SerializedKeyPackageData {
    /// Schema version for future migrations.
    pub schema_version: u32,
    /// Serialized member identity with signature keys.
    pub identity: SerializedIdentity,
    /// The cryptographic suite in use.
    pub suite: CryptoSuite,
    /// Optional PQC/Hybrid keypair.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pqc_keypair: Option<SerializedPqcKeyPair>,
    /// Serialized MemoryStorage bytes (base64-encoded JSON) containing the HPKE
    /// init private key needed to process a Welcome message in join-group.
    /// Without this, StagedWelcome will fail with NoMatchingKeyPackage.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_storage_bytes: Option<Vec<u8>>,
}

impl SerializedKeyPackageData {
    /// Save to a JSON file.
    pub fn save(&self, path: &str) -> EngineResult<()> {
        let file = File::create(path)?;
        let writer = BufWriter::new(file);
        serde_json::to_writer_pretty(writer, self)
            .map_err(|e| EngineError::Serialization(e.to_string()))?;
        Ok(())
    }

    /// Load from a JSON file.
    pub fn load(path: &str) -> EngineResult<Self> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let data: Self = serde_json::from_reader(reader)
            .map_err(|e| EngineError::Deserialization(e.to_string()))?;
        
        // Validate schema version
        if data.schema_version > CURRENT_SCHEMA_VERSION {
            return Err(EngineError::Deserialization(
                format!("Unsupported schema version {} (max supported: {})",
                    data.schema_version, CURRENT_SCHEMA_VERSION)
            ));
        }
        
        Ok(data)
    }
}

/// Holds the runtime state of an MLS group.
/// 
/// This structure combines:
/// - The MlsGroup instance
/// - The member's identity (credentials + signing keys)
/// - The OpenMLS provider for cryptographic operations
/// - The crypto suite selection (Classic/PQC/Hybrid)
/// - Optional PQC/Hybrid keypair for enhanced security
pub struct GroupState {
    /// The OpenMLS group instance.
    pub group: MlsGroup,
    /// The current member's identity.
    pub identity: MemberIdentity,
    /// The OpenMLS provider (crypto + storage).
    pub provider: OpenMlsRustCrypto,
    /// The cryptographic suite in use.
    pub suite: CryptoSuite,
    /// Optional PQC/Hybrid keypair (present when suite != Classic).
    pub pqc_keypair: Option<SerializedPqcKeyPair>,
}

impl GroupState {
    /// Create a new group with the given ID and member identity.
    pub fn new(
        group_id: &[u8],
        identity: MemberIdentity,
    ) -> EngineResult<Self> {
        let provider = OpenMlsRustCrypto::default();
        
        // Store the signature keys
        identity.store_keys(&provider)?;
        
        // Create the MLS group configuration
        let group_config = MlsGroupCreateConfig::builder()
            .ciphersuite(DEFAULT_CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .build();
        
        // Create the MLS group
        let group = MlsGroup::new_with_group_id(
            &provider,
            &identity.signature_keys,
            &group_config,
            GroupId::from_slice(group_id),
            identity.credential_with_key.clone(),
        ).map_err(|e| EngineError::GroupCreation(format!("{:?}", e)))?;

        Ok(Self {
            group,
            identity,
            provider,
            suite: CryptoSuite::Classic,
            pqc_keypair: None,
        })
    }

    /// Create a new group with specified crypto suite.
    pub fn new_with_suite(
        group_id: &[u8],
        identity: MemberIdentity,
        suite: CryptoSuite,
        pqc_keypair: Option<SerializedPqcKeyPair>,
    ) -> EngineResult<Self> {
        let provider = OpenMlsRustCrypto::default();
        
        // Store the signature keys
        identity.store_keys(&provider)?;
        
        // Create the MLS group configuration
        let group_config = MlsGroupCreateConfig::builder()
            .ciphersuite(DEFAULT_CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .build();
        
        // Create the MLS group
        let group = MlsGroup::new_with_group_id(
            &provider,
            &identity.signature_keys,
            &group_config,
            GroupId::from_slice(group_id),
            identity.credential_with_key.clone(),
        ).map_err(|e| EngineError::GroupCreation(format!("{:?}", e)))?;

        Ok(Self {
            group,
            identity,
            provider,
            suite,
            pqc_keypair,
        })
    }
    
    /// Create a GroupState from an existing group and identity.
    pub fn from_group(
        group: MlsGroup,
        identity: MemberIdentity,
        provider: OpenMlsRustCrypto,
    ) -> Self {
        Self {
            group,
            identity,
            provider,
            suite: CryptoSuite::Classic,
            pqc_keypair: None,
        }
    }

    /// Create a GroupState from an existing group with suite and PQC keypair.
    pub fn from_group_with_suite(
        group: MlsGroup,
        identity: MemberIdentity,
        provider: OpenMlsRustCrypto,
        suite: CryptoSuite,
        pqc_keypair: Option<SerializedPqcKeyPair>,
    ) -> Self {
        Self {
            group,
            identity,
            provider,
            suite,
            pqc_keypair,
        }
    }

    /// Save the group state to a file.
    /// Saves group_id, identity, suite, optional PQC keypair, and full MemoryStorage.
    pub fn save(&self, path: &str) -> EngineResult<()> {
        // Serialize the full MemoryStorage which contains all MLS group state
        // (ratchet tree, key schedule, epoch secrets, etc.)
        let provider_storage_bytes = storage_to_bytes(self.provider.storage())
            .map(Some)
            .unwrap_or(None);

        let snapshot = GroupStateSnapshot {
            schema_version: CURRENT_SCHEMA_VERSION,
            group_id: self.group.group_id().as_slice().to_vec(),
            identity: self.identity.to_bytes()?,
            epoch: self.group.epoch().as_u64(),
            suite: self.suite,
            pqc_keypair: self.pqc_keypair.clone(),
            provider_storage_bytes,
        };

        let file = File::create(path)?;
        let writer = BufWriter::new(file);
        serde_json::to_writer_pretty(writer, &snapshot)
            .map_err(|e| EngineError::Serialization(e.to_string()))?;
        
        Ok(())
    }

    /// Load group state from a file.
    /// Restores the full MLS group state from persisted MemoryStorage.
    pub fn load(path: &str) -> EngineResult<Self> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        
        let snapshot: GroupStateSnapshot = serde_json::from_reader(reader)
            .map_err(|e| EngineError::Deserialization(e.to_string()))?;

        // Validate schema version
        if snapshot.schema_version > CURRENT_SCHEMA_VERSION {
            return Err(EngineError::Deserialization(
                format!("Unsupported state schema version {} (max supported: {})",
                    snapshot.schema_version, CURRENT_SCHEMA_VERSION)
            ));
        }

        let identity = MemberIdentity::from_serialized(snapshot.identity)?;
        let suite = snapshot.suite;
        let pqc_keypair = snapshot.pqc_keypair;

        // Try to restore full group state from persisted MemoryStorage
        if let Some(storage_bytes) = snapshot.provider_storage_bytes {
            let restored_storage = storage_from_bytes(&storage_bytes)?;
            let provider = OpenMlsRustCrypto::default();
            
            // Copy the restored storage into the new provider
            {
                let source = restored_storage.values.read().unwrap();
                let mut target = provider.storage().values.write().unwrap();
                for (k, v) in source.iter() {
                    target.insert(k.clone(), v.clone());
                }
            }
            
            // Also ensure signature keys are accessible
            identity.store_keys(&provider)?;
            
            // Load the MlsGroup from storage using the group_id as key
            let group_id = GroupId::from_slice(&snapshot.group_id);
            match MlsGroup::load(provider.storage(), &group_id) {
                Ok(Some(group)) => {
                    return Ok(Self {
                        group,
                        identity,
                        provider,
                        suite,
                        pqc_keypair,
                    });
                }
                Ok(None) => {
                    // Storage exists but group not found - fall through to legacy path
                }
                Err(e) => {
                    // If load fails, fall through to legacy path
                    let _ = e; // suppress warning
                }
            }
        }
        
        // Fallback: recreate a fresh group (legacy behavior for old state files)
        GroupState::new_with_suite(&snapshot.group_id, identity, suite, pqc_keypair)
    }
    
    /// Get the group ID as a string (for display purposes).
    pub fn group_id_string(&self) -> String {
        String::from_utf8_lossy(self.group.group_id().as_slice()).to_string()
    }
    
    /// Get the current epoch of the group.
    pub fn epoch(&self) -> u64 {
        self.group.epoch().as_u64()
    }
    
    /// List all members in the group with their leaf indices and identities.
    pub fn list_members(&self) -> Vec<MemberInfo> {
        self.group
            .members()
            .map(|member| {
                // Extract identity bytes from the credential
                let identity_bytes = member.credential.serialized_content();
                let identity = String::from_utf8_lossy(identity_bytes).to_string();
                
                MemberInfo {
                    leaf_index: member.index.u32(),
                    identity,
                }
            })
            .collect()
    }
    
    /// Find a member by their identity string.
    /// Returns the leaf index if found.
    pub fn find_member(&self, identity: &str) -> Option<u32> {
        self.group.members().find_map(|member| {
            let member_identity = member.credential.serialized_content();
            let member_identity_str = String::from_utf8_lossy(member_identity);
            if member_identity_str == identity {
                Some(member.index.u32())
            } else {
                None
            }
        })
    }
}

/// Default schema version for backward compatibility with old state files.
fn default_schema_version() -> u32 {
    1
}

/// Serializable snapshot of GroupState for persistence.\
#[derive(Serialize, Deserialize)]
struct GroupStateSnapshot {
    /// Schema version for future migrations.
    #[serde(default = "default_schema_version")]
    schema_version: u32,
    /// The group ID bytes.
    group_id: Vec<u8>,
    /// Serialized member identity.
    identity: SerializedIdentity,
    /// The epoch at save time (for reference).
    epoch: u64,
    /// The cryptographic suite in use.
    #[serde(default)]
    suite: CryptoSuite,
    /// Optional PQC/Hybrid keypair.
    #[serde(default)]
    pqc_keypair: Option<SerializedPqcKeyPair>,
    /// Serialized MemoryStorage bytes containing MLS group state
    /// (ratchet tree, key schedule, epoch secrets, etc.).
    /// When present, allows full group state restoration via MlsGroup::load().
    #[serde(default, skip_serializing_if = "Option::is_none")]
    provider_storage_bytes: Option<Vec<u8>>,
}
