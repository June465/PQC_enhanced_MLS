//! # MLS PQC Engine
//!
//! A Post-Quantum Cryptography enhanced implementation of the
//! Messaging Layer Security (MLS) protocol.
//!
//! This library provides the core engine functionality for:
//! - Group management (create, add members, remove members)
//! - Message encryption/decryption
//! - State persistence
//! - PQC/Hybrid KEM support (in later phases)

// Re-export commonly used types from openmls
pub use openmls::prelude::*;
pub use openmls_rust_crypto::OpenMlsRustCrypto;
pub use openmls_basic_credential::SignatureKeyPair;
pub use openmls_memory_storage::MemoryStorage;

/// Error types for the MLS PQC Engine
pub mod error;

/// Engine operations for group management
pub mod engine;

/// Crypto provider implementations
pub mod provider;

