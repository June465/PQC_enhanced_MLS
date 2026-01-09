//! State management for MLS groups and members.
//!
//! Provides persistence and management for MLS group state.

use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_basic_credential::SignatureKeyPair;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufReader, BufWriter};
use tls_codec::Serialize as TlsSerialize;

use crate::error::{EngineError, EngineResult};
use crate::provider::DEFAULT_CIPHERSUITE;

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

/// Holds the runtime state of an MLS group.
/// 
/// This structure combines:
/// - The MlsGroup instance
/// - The member's identity (credentials + signing keys)
/// - The OpenMLS provider for cryptographic operations
pub struct GroupState {
    /// The OpenMLS group instance.
    pub group: MlsGroup,
    /// The current member's identity.
    pub identity: MemberIdentity,
    /// The OpenMLS provider (crypto + storage).
    pub provider: OpenMlsRustCrypto,
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
        }
    }

    /// Save the group state to a file.
    /// Note: For Phase 1, this only saves the group_id and identity.
    /// Full MLS state persistence would require additional work.
    pub fn save(&self, path: &str) -> EngineResult<()> {
        let snapshot = GroupStateSnapshot {
            group_id: self.group.group_id().as_slice().to_vec(),
            identity: self.identity.to_bytes()?,
            epoch: self.group.epoch().as_u64(),
        };

        let file = File::create(path)?;
        let writer = BufWriter::new(file);
        serde_json::to_writer_pretty(writer, &snapshot)
            .map_err(|e| EngineError::Serialization(e.to_string()))?;
        
        Ok(())
    }

    /// Load group state from a file.
    /// Note: This recreates a fresh group - full state loading needs persistence.
    pub fn load(path: &str) -> EngineResult<Self> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        
        let snapshot: GroupStateSnapshot = serde_json::from_reader(reader)
            .map_err(|e| EngineError::Deserialization(e.to_string()))?;

        let identity = MemberIdentity::from_serialized(snapshot.identity)?;
        
        // Recreate the group (note: this resets state in Phase 1)
        GroupState::new(&snapshot.group_id, identity)
    }
    
    /// Get the group ID as a string (for display purposes).
    pub fn group_id_string(&self) -> String {
        String::from_utf8_lossy(self.group.group_id().as_slice()).to_string()
    }
    
    /// Get the current epoch of the group.
    pub fn epoch(&self) -> u64 {
        self.group.epoch().as_u64()
    }
}

/// Serializable snapshot of GroupState for persistence.
#[derive(Serialize, Deserialize)]
struct GroupStateSnapshot {
    /// The group ID bytes.
    group_id: Vec<u8>,
    /// Serialized member identity.
    identity: SerializedIdentity,
    /// The epoch at save time (for reference).
    epoch: u64,
}
