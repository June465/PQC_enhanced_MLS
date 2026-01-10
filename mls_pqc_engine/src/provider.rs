//! Crypto provider implementations
//!
//! This module contains:
//! - Classic crypto provider (wrapper around openmls_rust_crypto)
//! - PQC KEM provider (ML-KEM 768)
//! - Hybrid KEM provider (Phase 4)

/// PQC KEM provider for ML-KEM 768 operations
pub mod pqc_kem;

/// Re-export the default OpenMLS crypto provider
pub use openmls_rust_crypto::OpenMlsRustCrypto;

/// Re-export PQC KEM types for convenience
pub use pqc_kem::{PqcKemKeyPair, PqcKemProvider};

/// Default ciphersuite for classic MLS operations
pub const DEFAULT_CIPHERSUITE: openmls::prelude::Ciphersuite =
    openmls::prelude::Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

