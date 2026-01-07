//! Crypto provider implementations
//!
//! This module will contain:
//! - Classic crypto provider (wrapper around openmls_rust_crypto)
//! - PQC KEM provider (Phase 3)
//! - Hybrid KEM provider (Phase 4)
//!
//! Implementation will be expanded in later phases.

/// Re-export the default OpenMLS crypto provider
pub use openmls_rust_crypto::OpenMlsRustCrypto;

/// Default ciphersuite for classic MLS operations
pub const DEFAULT_CIPHERSUITE: openmls::prelude::Ciphersuite =
    openmls::prelude::Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
