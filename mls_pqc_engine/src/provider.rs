//! Crypto provider implementations
//!
//! This module contains:
//! - Classic crypto provider (wrapper around openmls_rust_crypto)
//! - PQC KEM provider (ML-KEM 768)
//! - Hybrid KEM provider (X25519 + ML-KEM 768)

/// PQC KEM provider for ML-KEM 768 operations
pub mod pqc_kem;

/// Hybrid KEM provider for X25519 + ML-KEM 768 operations
pub mod hybrid_kem;

/// Re-export the default OpenMLS crypto provider
pub use openmls_rust_crypto::OpenMlsRustCrypto;

/// Re-export PQC KEM types for convenience
pub use pqc_kem::{PqcKemKeyPair, PqcKemProvider};

/// Re-export Hybrid KEM types for convenience
pub use hybrid_kem::{HybridKemKeyPair, HybridKemProvider};

/// Default ciphersuite for classic MLS operations
pub const DEFAULT_CIPHERSUITE: openmls::prelude::Ciphersuite =
    openmls::prelude::Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;


