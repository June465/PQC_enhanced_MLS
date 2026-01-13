//! Engine operations for MLS group management.
//!
//! This module provides the core MLS operations:
//! - Group creation and management
//! - Member addition and removal
//! - Message encryption and decryption
//! - PQC/Hybrid suite support

use crate::error::{EngineError, EngineResult};
use crate::provider::DEFAULT_CIPHERSUITE;
use crate::provider::{PqcKemProvider, HybridKemProvider};

pub mod state;
pub mod suite;

pub use state::{GroupState, MemberIdentity, SerializedIdentity, SerializedPqcKeyPair, SerializedKeyPackageData, CURRENT_SCHEMA_VERSION};
pub use suite::CryptoSuite;

use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use tls_codec::Serialize as TlsSerialize;

/// Bundle returned when generating a key package for a new member.
/// Contains everything needed to process a welcome message.
pub struct KeyPackageData {
    /// Serialized key package bytes to share with the group creator
    pub key_package_bytes: Vec<u8>,
    /// The member's identity
    pub identity: MemberIdentity,
    /// The provider containing the private key material
    pub provider: OpenMlsRustCrypto,
    /// The crypto suite used
    pub suite: CryptoSuite,
    /// Optional PQC/Hybrid keypair for PQC-enhanced operations
    pub pqc_keypair: Option<SerializedPqcKeyPair>,
}

impl KeyPackageData {
    /// Convert to serializable form for CLI persistence.
    /// Note: key_package_bytes are NOT included - they're saved separately as the public .bin file.
    pub fn to_serialized(&self) -> EngineResult<SerializedKeyPackageData> {
        Ok(SerializedKeyPackageData {
            schema_version: CURRENT_SCHEMA_VERSION,
            identity: self.identity.to_bytes()?,
            suite: self.suite,
            pqc_keypair: self.pqc_keypair.clone(),
        })
    }

    /// Reconstruct from serialized form.
    /// Creates a fresh provider and restores the identity and keys.
    pub fn from_serialized(data: SerializedKeyPackageData) -> EngineResult<Self> {
        let provider = OpenMlsRustCrypto::default();
        let identity = MemberIdentity::from_serialized(data.identity)?;
        
        // Store the signature keys in the new provider
        identity.store_keys(&provider)?;
        
        Ok(Self {
            key_package_bytes: Vec::new(), // Not stored in serialized form
            identity,
            provider,
            suite: data.suite,
            pqc_keypair: data.pqc_keypair,
        })
    }
}

/// The MLS Engine handling group operations.
/// 
/// This engine is stateless - all state is passed via GroupState.
pub struct MlsEngine;

impl MlsEngine {
    /// Create a new MLS engine instance.
    pub fn new() -> EngineResult<Self> {
        Ok(Self)
    }

    /// Create a new group with the given group ID and member name.
    /// Returns the initial GroupState.
    pub fn create_group(&self, group_id: &[u8], member_name: &[u8]) -> EngineResult<GroupState> {
        // Create member identity with credentials and signing keys
        let identity = MemberIdentity::new(member_name, DEFAULT_CIPHERSUITE)?;
        
        // Create the group state
        GroupState::new(group_id, identity)
    }

    /// Generate a key package for a new member to join a group.
    /// Returns KeyPackageData containing everything needed to join a group.
    pub fn generate_key_package(&self, member_name: &[u8]) -> EngineResult<KeyPackageData> {
        self.generate_key_package_with_suite(member_name, CryptoSuite::Classic)
    }

    /// Create a new group with specified crypto suite.
    /// When suite is PQC or Hybrid, additional PQC keypairs are generated.
    pub fn create_group_with_suite(
        &self,
        group_id: &[u8],
        member_name: &[u8],
        suite: CryptoSuite,
    ) -> EngineResult<GroupState> {
        // Create member identity with credentials and signing keys
        let identity = MemberIdentity::new(member_name, DEFAULT_CIPHERSUITE)?;
        
        // Generate PQC keypair if needed
        let pqc_keypair = match suite {
            CryptoSuite::Classic => None,
            CryptoSuite::PqcKem => {
                let kp = PqcKemProvider::generate_keypair()?;
                Some(SerializedPqcKeyPair {
                    public_key: kp.encapsulation_key,
                    private_key: kp.decapsulation_key,
                })
            }
            CryptoSuite::HybridKem => {
                let kp = HybridKemProvider::generate_keypair()?;
                Some(SerializedPqcKeyPair {
                    public_key: kp.public_key(),
                    private_key: kp.private_key(),
                })
            }
        };
        
        // Create the group state with suite
        GroupState::new_with_suite(group_id, identity, suite, pqc_keypair)
    }

    /// Generate a key package with specified crypto suite.
    /// When suite is PQC or Hybrid, additional PQC keypairs are generated.
    pub fn generate_key_package_with_suite(
        &self,
        member_name: &[u8],
        suite: CryptoSuite,
    ) -> EngineResult<KeyPackageData> {
        let provider = OpenMlsRustCrypto::default();
        
        // Create member identity
        let identity = MemberIdentity::new(member_name, DEFAULT_CIPHERSUITE)?;
        identity.store_keys(&provider)?;
        
        // Generate key package bundle
        let key_package_bundle = KeyPackage::builder()
            .build(
                DEFAULT_CIPHERSUITE,
                &provider,
                &identity.signature_keys,
                identity.credential_with_key.clone(),
            )
            .map_err(|e| EngineError::Generic(format!("Failed to create key package: {:?}", e)))?;
        
        // Serialize the key package (not the bundle) to bytes using TLS encoding
        let key_package_bytes = key_package_bundle.key_package().tls_serialize_detached()
            .map_err(|e| EngineError::Serialization(format!("Failed to serialize key package: {:?}", e)))?;
        
        // Generate PQC keypair if needed
        let pqc_keypair = match suite {
            CryptoSuite::Classic => None,
            CryptoSuite::PqcKem => {
                let kp = PqcKemProvider::generate_keypair()?;
                Some(SerializedPqcKeyPair {
                    public_key: kp.encapsulation_key,
                    private_key: kp.decapsulation_key,
                })
            }
            CryptoSuite::HybridKem => {
                let kp = HybridKemProvider::generate_keypair()?;
                Some(SerializedPqcKeyPair {
                    public_key: kp.public_key(),
                    private_key: kp.private_key(),
                })
            }
        };
        
        Ok(KeyPackageData {
            key_package_bytes,
            identity,
            provider,
            suite,
            pqc_keypair,
        })
    }

    /// Add a member to the group using their key package.
    /// Returns (Welcome bytes, Commit bytes).
    pub fn add_member(
        &self,
        group_state: &mut GroupState,
        key_package_bytes: &[u8],
    ) -> EngineResult<(Vec<u8>, Vec<u8>)> {
        // Ensure signature keys are in storage
        group_state.identity.store_keys(&group_state.provider)?;
        
        // Deserialize the key package
        let key_package = KeyPackageIn::tls_deserialize_exact_bytes(key_package_bytes)
            .map_err(|e| EngineError::Deserialization(format!("Invalid key package: {:?}", e)))?;
        
        // Validate the key package
        let validated_kp = key_package
            .validate(group_state.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|e| EngineError::MemberAddition(format!("Key package validation failed: {:?}", e)))?;
        
        // Add the member - returns (MlsMessageOut, Welcome, Option<GroupInfo>)
        let (commit_msg, welcome, _group_info) = group_state.group
            .add_members(&group_state.provider, &group_state.identity.signature_keys, &[validated_kp])
            .map_err(|e| EngineError::MemberAddition(format!("Failed to add member: {:?}", e)))?;
        
        // Merge the pending commit
        group_state.group
            .merge_pending_commit(&group_state.provider)
            .map_err(|e| EngineError::CommitProcessing(format!("Failed to merge commit: {:?}", e)))?;
        
        // Serialize messages
        let welcome_bytes = welcome.tls_serialize_detached()
            .map_err(|e| EngineError::Serialization(format!("Failed to serialize welcome: {:?}", e)))?;
        
        let commit_bytes = commit_msg.tls_serialize_detached()
            .map_err(|e| EngineError::Serialization(format!("Failed to serialize commit: {:?}", e)))?;
        
        Ok((welcome_bytes, commit_bytes))
    }

    /// Process a welcome message to join a group.
    /// Takes the KeyPackageData that was used to generate the key package.
    /// Returns a new GroupState for the joining member.
    pub fn process_welcome(
        &self,
        welcome_bytes: &[u8],
        kp_data: KeyPackageData,
    ) -> EngineResult<GroupState> {
        let provider = kp_data.provider;
        let identity = kp_data.identity;
        let suite = kp_data.suite;
        let pqc_keypair = kp_data.pqc_keypair;
        
        // Deserialize welcome message (comes as MlsMessageOut, deserialize as MlsMessageIn)
        let mls_message = MlsMessageIn::tls_deserialize_exact_bytes(welcome_bytes)
            .map_err(|e| EngineError::Deserialization(format!("Invalid welcome message: {:?}", e)))?;
        
        // Extract the welcome from the message body
        let welcome = match mls_message.extract() {
            MlsMessageBodyIn::Welcome(w) => w,
            _ => return Err(EngineError::Deserialization("Message is not a Welcome".into())),
        };
        
        // Join configuration
        let join_config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();
        
        // Stage the welcome
        let staged = StagedWelcome::new_from_welcome(
            &provider,
            &join_config,
            welcome,
            None, // No ratchet tree, using extension
        ).map_err(|e| EngineError::Generic(format!("Failed to stage welcome: {:?}", e)))?;
        
        // Create the group from staged welcome
        let group = staged.into_group(&provider)
            .map_err(|e| EngineError::Generic(format!("Failed to create group from welcome: {:?}", e)))?;
        
        Ok(GroupState::from_group_with_suite(group, identity, provider, suite, pqc_keypair))
    }

    /// Encrypt a message for the group.
    /// Returns the ciphertext bytes.
    pub fn encrypt_message(
        &self,
        group_state: &mut GroupState,
        plaintext: &[u8],
    ) -> EngineResult<Vec<u8>> {
        // Ensure signature keys are in storage
        group_state.identity.store_keys(&group_state.provider)?;
        
        // Create the encrypted message
        let mls_message = group_state.group
            .create_message(&group_state.provider, &group_state.identity.signature_keys, plaintext)
            .map_err(|e| EngineError::Encryption(format!("Failed to encrypt message: {:?}", e)))?;
        
        // Serialize to bytes
        let ciphertext = mls_message.tls_serialize_detached()
            .map_err(|e| EngineError::Serialization(format!("Failed to serialize message: {:?}", e)))?;
        
        Ok(ciphertext)
    }

    /// Decrypt a message from the group.
    /// Returns the plaintext bytes.
    pub fn decrypt_message(
        &self,
        group_state: &mut GroupState,
        ciphertext: &[u8],
    ) -> EngineResult<Vec<u8>> {
        // Deserialize the message
        let mls_message = MlsMessageIn::tls_deserialize_exact_bytes(ciphertext)
            .map_err(|e| EngineError::Deserialization(format!("Invalid ciphertext: {:?}", e)))?;
        
        // Convert to protocol message
        let protocol_message = mls_message
            .try_into_protocol_message()
            .map_err(|e| EngineError::Decryption(format!("Not a protocol message: {:?}", e)))?;
        
        // Process the message
        let processed = group_state.group
            .process_message(&group_state.provider, protocol_message)
            .map_err(|e| EngineError::Decryption(format!("Failed to process message: {:?}", e)))?;
        
        // Extract application message content
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app_msg) => {
                Ok(app_msg.into_bytes())
            }
            ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                // This is a commit message, merge it
                group_state.group
                    .merge_staged_commit(&group_state.provider, *staged_commit)
                    .map_err(|e| EngineError::CommitProcessing(format!("Failed to merge commit: {:?}", e)))?;
                Err(EngineError::Decryption("Received commit message, not application message".into()))
            }
            _ => {
                Err(EngineError::Decryption("Unexpected message type".into()))
            }
        }
    }

    /// Remove a member from the group by their leaf index.
    /// Returns the Commit bytes.
    pub fn remove_member(
        &self,
        group_state: &mut GroupState,
        leaf_index: u32,
    ) -> EngineResult<Vec<u8>> {
        // Ensure signature keys are in storage
        group_state.identity.store_keys(&group_state.provider)?;
        
        // Remove the member
        let (commit_msg, _welcome, _group_info) = group_state.group
            .remove_members(&group_state.provider, &group_state.identity.signature_keys, &[LeafNodeIndex::new(leaf_index)])
            .map_err(|e| EngineError::MemberRemoval(format!("Failed to remove member: {:?}", e)))?;
        
        // Merge the pending commit
        group_state.group
            .merge_pending_commit(&group_state.provider)
            .map_err(|e| EngineError::CommitProcessing(format!("Failed to merge commit: {:?}", e)))?;
        
        // Serialize commit
        let commit_bytes = commit_msg.tls_serialize_detached()
            .map_err(|e| EngineError::Serialization(format!("Failed to serialize commit: {:?}", e)))?;
        
        Ok(commit_bytes)
    }

    /// Process incoming commit message (for members receiving commits).
    pub fn process_commit(
        &self,
        group_state: &mut GroupState,
        commit_bytes: &[u8],
    ) -> EngineResult<()> {
        // Deserialize the commit message
        let mls_message = MlsMessageIn::tls_deserialize_exact_bytes(commit_bytes)
            .map_err(|e| EngineError::Deserialization(format!("Invalid commit message: {:?}", e)))?;
        
        // Convert to protocol message
        let protocol_message = mls_message
            .try_into_protocol_message()
            .map_err(|e| EngineError::CommitProcessing(format!("Not a protocol message: {:?}", e)))?;
        
        // Process the message
        let processed = group_state.group
            .process_message(&group_state.provider, protocol_message)
            .map_err(|e| EngineError::CommitProcessing(format!("Failed to process commit: {:?}", e)))?;
        
        // Handle the commit
        match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                group_state.group
                    .merge_staged_commit(&group_state.provider, *staged_commit)
                    .map_err(|e| EngineError::CommitProcessing(format!("Failed to merge commit: {:?}", e)))?;
                Ok(())
            }
            _ => {
                Err(EngineError::CommitProcessing("Expected commit message".into()))
            }
        }
    }
}

impl Default for MlsEngine {
    fn default() -> Self {
        Self
    }
}
