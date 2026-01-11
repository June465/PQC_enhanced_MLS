//! Hybrid KEM Provider
//!
//! This module provides a Hybrid Key Encapsulation Mechanism (KEM) that combines:
//! - Classical KEM: X25519 Diffie-Hellman
//! - Post-Quantum KEM: ML-KEM 768 (FIPS 203 compliant)
//!
//! The hybrid construction provides security against both classical and quantum
//! adversaries. An attacker would need to break BOTH cryptosystems to compromise
//! the shared secret.
//!
//! ## Hybrid Construction
//!
//! - **Ciphertext**: X25519 ephemeral public key (32 bytes) || ML-KEM ciphertext (1088 bytes)
//! - **Shared Secret**: HKDF-SHA256(X25519_SS || PQC_SS, info="hybrid-kem-shared-secret")

use hkdf::Hkdf;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};

use crate::error::{EngineError, EngineResult};
use crate::provider::pqc_kem::{
    PqcKemProvider, CIPHERTEXT_SIZE as PQC_CIPHERTEXT_SIZE,
    DECAPSULATION_KEY_SIZE as PQC_DECAPSULATION_KEY_SIZE,
    ENCAPSULATION_KEY_SIZE as PQC_ENCAPSULATION_KEY_SIZE,
};

// =============================================================================
// Constants
// =============================================================================

/// X25519 public key size in bytes
pub const X25519_PUBLIC_KEY_SIZE: usize = 32;

/// X25519 private key size in bytes
pub const X25519_PRIVATE_KEY_SIZE: usize = 32;

/// X25519 shared secret size in bytes
pub const X25519_SHARED_SECRET_SIZE: usize = 32;

/// Hybrid public key size: X25519 (32) + ML-KEM 768 (1184) = 1216 bytes
pub const HYBRID_PUBLIC_KEY_SIZE: usize = X25519_PUBLIC_KEY_SIZE + PQC_ENCAPSULATION_KEY_SIZE;

/// Hybrid private key size: X25519 (32) + ML-KEM 768 (2400) = 2432 bytes
pub const HYBRID_PRIVATE_KEY_SIZE: usize = X25519_PRIVATE_KEY_SIZE + PQC_DECAPSULATION_KEY_SIZE;

/// Hybrid ciphertext size: X25519 ephemeral public (32) + ML-KEM ciphertext (1088) = 1120 bytes
pub const HYBRID_CIPHERTEXT_SIZE: usize = X25519_PUBLIC_KEY_SIZE + PQC_CIPHERTEXT_SIZE;

/// Hybrid shared secret size (output of HKDF)
pub const HYBRID_SHARED_SECRET_SIZE: usize = 32;

/// HKDF domain separator for hybrid shared secret derivation
const HKDF_INFO: &[u8] = b"hybrid-kem-shared-secret";

// =============================================================================
// Hybrid Keypair
// =============================================================================

/// Hybrid KEM keypair combining X25519 and ML-KEM 768
///
/// This keypair contains both classical (X25519) and post-quantum (ML-KEM 768)
/// key material for hybrid encryption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridKemKeyPair {
    /// X25519 public key (32 bytes)
    pub x25519_public: Vec<u8>,
    /// X25519 private key (32 bytes)
    pub x25519_private: Vec<u8>,
    /// ML-KEM 768 encapsulation key (public, 1184 bytes)
    pub pqc_public: Vec<u8>,
    /// ML-KEM 768 decapsulation key (private, 2400 bytes)
    pub pqc_private: Vec<u8>,
}

impl HybridKemKeyPair {
    /// Returns the combined hybrid public key (X25519 || PQC)
    pub fn public_key(&self) -> Vec<u8> {
        let mut combined = Vec::with_capacity(HYBRID_PUBLIC_KEY_SIZE);
        combined.extend_from_slice(&self.x25519_public);
        combined.extend_from_slice(&self.pqc_public);
        combined
    }

    /// Returns the combined hybrid private key (X25519 || PQC)
    pub fn private_key(&self) -> Vec<u8> {
        let mut combined = Vec::with_capacity(HYBRID_PRIVATE_KEY_SIZE);
        combined.extend_from_slice(&self.x25519_private);
        combined.extend_from_slice(&self.pqc_private);
        combined
    }

    /// Returns the X25519 public key component
    pub fn x25519_public_key(&self) -> &[u8] {
        &self.x25519_public
    }

    /// Returns the PQC public key component
    pub fn pqc_public_key(&self) -> &[u8] {
        &self.pqc_public
    }
}

// =============================================================================
// Hybrid KEM Provider
// =============================================================================

/// Hybrid KEM Provider for X25519 + ML-KEM 768 operations
///
/// This struct provides static methods for hybrid KEM operations:
/// - Key generation (both classical and PQC)
/// - Encapsulation (creates shared secret + ciphertext)
/// - Decapsulation (recovers shared secret from ciphertext)
pub struct HybridKemProvider;

impl HybridKemProvider {
    /// Generate a new hybrid keypair (X25519 + ML-KEM 768)
    ///
    /// # Returns
    /// A `HybridKemKeyPair` containing both X25519 and ML-KEM keypairs
    ///
    /// # Errors
    /// Returns an error if key generation fails
    ///
    /// # Example
    /// ```
    /// use mls_pqc_engine::provider::hybrid_kem::HybridKemProvider;
    ///
    /// let keypair = HybridKemProvider::generate_keypair().unwrap();
    /// assert_eq!(keypair.public_key().len(), 1216); // 32 + 1184
    /// assert_eq!(keypair.private_key().len(), 2432); // 32 + 2400
    /// ```
    pub fn generate_keypair() -> EngineResult<HybridKemKeyPair> {
        // Generate X25519 keypair
        let x25519_secret = X25519Secret::random_from_rng(OsRng);
        let x25519_public = X25519PublicKey::from(&x25519_secret);

        // Generate ML-KEM 768 keypair
        let pqc_keypair = PqcKemProvider::generate_keypair()?;

        Ok(HybridKemKeyPair {
            x25519_public: x25519_public.as_bytes().to_vec(),
            x25519_private: x25519_secret.as_bytes().to_vec(),
            pqc_public: pqc_keypair.encapsulation_key,
            pqc_private: pqc_keypair.decapsulation_key,
        })
    }

    /// Encapsulate a shared secret using the recipient's hybrid public key
    ///
    /// This creates a ciphertext that can only be decapsulated by the holder
    /// of the corresponding private key. The shared secret is derived from
    /// both X25519 and ML-KEM shared secrets using HKDF-SHA256.
    ///
    /// # Arguments
    /// * `hybrid_public_key` - The recipient's hybrid public key (1216 bytes)
    ///
    /// # Returns
    /// A tuple of (ciphertext, shared_secret):
    /// - `ciphertext`: Combined X25519 ephemeral + PQC ciphertext (1120 bytes)
    /// - `shared_secret`: HKDF-derived shared secret (32 bytes)
    ///
    /// # Errors
    /// Returns an error if the public key is invalid or encapsulation fails
    pub fn encapsulate(hybrid_public_key: &[u8]) -> EngineResult<(Vec<u8>, Vec<u8>)> {
        // Validate hybrid public key size
        if hybrid_public_key.len() != HYBRID_PUBLIC_KEY_SIZE {
            return Err(EngineError::KemError(format!(
                "Invalid hybrid public key size: expected {}, got {}",
                HYBRID_PUBLIC_KEY_SIZE,
                hybrid_public_key.len()
            )));
        }

        // Split the hybrid public key into components
        let x25519_pk_bytes = &hybrid_public_key[..X25519_PUBLIC_KEY_SIZE];
        let pqc_pk_bytes = &hybrid_public_key[X25519_PUBLIC_KEY_SIZE..];

        // Parse X25519 public key
        let x25519_pk_array: [u8; X25519_PUBLIC_KEY_SIZE] = x25519_pk_bytes
            .try_into()
            .map_err(|_| EngineError::KemError("Failed to parse X25519 public key".to_string()))?;
        let recipient_x25519_pk = X25519PublicKey::from(x25519_pk_array);

        // Generate ephemeral X25519 keypair for this encapsulation
        let ephemeral_secret = X25519Secret::random_from_rng(OsRng);
        let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);

        // Compute X25519 shared secret
        let x25519_shared = ephemeral_secret.diffie_hellman(&recipient_x25519_pk);

        // Perform PQC encapsulation
        let (pqc_ciphertext, pqc_shared_secret) = PqcKemProvider::encapsulate(pqc_pk_bytes)?;

        // Combine shared secrets using HKDF
        let combined_shared_secret =
            Self::derive_shared_secret(x25519_shared.as_bytes(), &pqc_shared_secret)?;

        // Construct hybrid ciphertext: ephemeral_public || pqc_ciphertext
        let mut hybrid_ciphertext = Vec::with_capacity(HYBRID_CIPHERTEXT_SIZE);
        hybrid_ciphertext.extend_from_slice(ephemeral_public.as_bytes());
        hybrid_ciphertext.extend_from_slice(&pqc_ciphertext);

        Ok((hybrid_ciphertext, combined_shared_secret.to_vec()))
    }

    /// Decapsulate a hybrid ciphertext using the private key to recover the shared secret
    ///
    /// # Arguments
    /// * `hybrid_private_key` - The private key (2432 bytes)
    /// * `hybrid_ciphertext` - The hybrid ciphertext (1120 bytes)
    ///
    /// # Returns
    /// The HKDF-derived shared secret (32 bytes)
    ///
    /// # Errors
    /// Returns an error if the keys are invalid or decapsulation fails
    pub fn decapsulate(hybrid_private_key: &[u8], hybrid_ciphertext: &[u8]) -> EngineResult<Vec<u8>> {
        // Validate private key size
        if hybrid_private_key.len() != HYBRID_PRIVATE_KEY_SIZE {
            return Err(EngineError::KemError(format!(
                "Invalid hybrid private key size: expected {}, got {}",
                HYBRID_PRIVATE_KEY_SIZE,
                hybrid_private_key.len()
            )));
        }

        // Validate ciphertext size
        if hybrid_ciphertext.len() != HYBRID_CIPHERTEXT_SIZE {
            return Err(EngineError::KemError(format!(
                "Invalid hybrid ciphertext size: expected {}, got {}",
                HYBRID_CIPHERTEXT_SIZE,
                hybrid_ciphertext.len()
            )));
        }

        // Split the hybrid private key into components
        let x25519_sk_bytes = &hybrid_private_key[..X25519_PRIVATE_KEY_SIZE];
        let pqc_sk_bytes = &hybrid_private_key[X25519_PRIVATE_KEY_SIZE..];

        // Split the hybrid ciphertext into components
        let ephemeral_pk_bytes = &hybrid_ciphertext[..X25519_PUBLIC_KEY_SIZE];
        let pqc_ct_bytes = &hybrid_ciphertext[X25519_PUBLIC_KEY_SIZE..];

        // Parse X25519 private key
        let x25519_sk_array: [u8; X25519_PRIVATE_KEY_SIZE] = x25519_sk_bytes
            .try_into()
            .map_err(|_| EngineError::KemError("Failed to parse X25519 private key".to_string()))?;
        let x25519_secret = X25519Secret::from(x25519_sk_array);

        // Parse ephemeral X25519 public key from ciphertext
        let ephemeral_pk_array: [u8; X25519_PUBLIC_KEY_SIZE] = ephemeral_pk_bytes
            .try_into()
            .map_err(|_| EngineError::KemError("Failed to parse ephemeral public key".to_string()))?;
        let ephemeral_public = X25519PublicKey::from(ephemeral_pk_array);

        // Compute X25519 shared secret
        let x25519_shared = x25519_secret.diffie_hellman(&ephemeral_public);

        // Perform PQC decapsulation
        let pqc_shared_secret = PqcKemProvider::decapsulate(pqc_sk_bytes, pqc_ct_bytes)?;

        // Combine shared secrets using HKDF
        let combined_shared_secret =
            Self::derive_shared_secret(x25519_shared.as_bytes(), &pqc_shared_secret)?;

        Ok(combined_shared_secret.to_vec())
    }

    /// Derive a combined shared secret from X25519 and PQC shared secrets using HKDF-SHA256
    fn derive_shared_secret(
        x25519_ss: &[u8],
        pqc_ss: &[u8],
    ) -> EngineResult<[u8; HYBRID_SHARED_SECRET_SIZE]> {
        // Concatenate the shared secrets as IKM (Input Key Material)
        let mut ikm = Vec::with_capacity(x25519_ss.len() + pqc_ss.len());
        ikm.extend_from_slice(x25519_ss);
        ikm.extend_from_slice(pqc_ss);

        // Use HKDF-SHA256 to derive the final shared secret
        let hk = Hkdf::<Sha256>::new(None, &ikm);
        let mut okm = [0u8; HYBRID_SHARED_SECRET_SIZE];
        hk.expand(HKDF_INFO, &mut okm)
            .map_err(|e| EngineError::KemError(format!("HKDF expansion failed: {:?}", e)))?;

        Ok(okm)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Test complete hybrid KEM roundtrip: generate keypair, encapsulate, decapsulate
    #[test]
    fn test_hybrid_kem_roundtrip() {
        // Generate a hybrid keypair
        let keypair = HybridKemProvider::generate_keypair().expect("Keypair generation failed");

        // Get the combined public key
        let public_key = keypair.public_key();
        let private_key = keypair.private_key();

        // Encapsulate using the public key
        let (ciphertext, shared_secret_sender) =
            HybridKemProvider::encapsulate(&public_key).expect("Encapsulation failed");

        // Decapsulate using the private key
        let shared_secret_receiver =
            HybridKemProvider::decapsulate(&private_key, &ciphertext).expect("Decapsulation failed");

        // Verify the shared secrets match
        assert_eq!(
            shared_secret_sender, shared_secret_receiver,
            "Shared secrets should match after roundtrip"
        );

        // Verify shared secret size
        assert_eq!(
            shared_secret_sender.len(),
            HYBRID_SHARED_SECRET_SIZE,
            "Shared secret should be 32 bytes"
        );
    }

    /// Test that hybrid keypair has correct sizes
    #[test]
    fn test_hybrid_keypair_sizes() {
        let keypair = HybridKemProvider::generate_keypair().expect("Keypair generation failed");

        // Check individual component sizes
        assert_eq!(
            keypair.x25519_public.len(),
            X25519_PUBLIC_KEY_SIZE,
            "X25519 public key should be {} bytes",
            X25519_PUBLIC_KEY_SIZE
        );

        assert_eq!(
            keypair.x25519_private.len(),
            X25519_PRIVATE_KEY_SIZE,
            "X25519 private key should be {} bytes",
            X25519_PRIVATE_KEY_SIZE
        );

        assert_eq!(
            keypair.pqc_public.len(),
            PQC_ENCAPSULATION_KEY_SIZE,
            "PQC public key should be {} bytes",
            PQC_ENCAPSULATION_KEY_SIZE
        );

        assert_eq!(
            keypair.pqc_private.len(),
            PQC_DECAPSULATION_KEY_SIZE,
            "PQC private key should be {} bytes",
            PQC_DECAPSULATION_KEY_SIZE
        );

        // Check combined sizes
        assert_eq!(
            keypair.public_key().len(),
            HYBRID_PUBLIC_KEY_SIZE,
            "Hybrid public key should be {} bytes",
            HYBRID_PUBLIC_KEY_SIZE
        );

        assert_eq!(
            keypair.private_key().len(),
            HYBRID_PRIVATE_KEY_SIZE,
            "Hybrid private key should be {} bytes",
            HYBRID_PRIVATE_KEY_SIZE
        );
    }

    /// Test that hybrid ciphertext has correct size
    #[test]
    fn test_hybrid_ciphertext_size() {
        let keypair = HybridKemProvider::generate_keypair().expect("Keypair generation failed");
        let (ciphertext, _) =
            HybridKemProvider::encapsulate(&keypair.public_key()).expect("Encapsulation failed");

        assert_eq!(
            ciphertext.len(),
            HYBRID_CIPHERTEXT_SIZE,
            "Hybrid ciphertext should be {} bytes (32 + 1088)",
            HYBRID_CIPHERTEXT_SIZE
        );
    }

    /// Test that HKDF produces consistent shared secrets
    #[test]
    fn test_hybrid_shared_secret_consistency() {
        // This test verifies that given the same inputs, HKDF produces the same output
        let x25519_ss = [1u8; 32];
        let pqc_ss = [2u8; 32];

        let derived1 =
            HybridKemProvider::derive_shared_secret(&x25519_ss, &pqc_ss).expect("HKDF failed");
        let derived2 =
            HybridKemProvider::derive_shared_secret(&x25519_ss, &pqc_ss).expect("HKDF failed");

        assert_eq!(derived1, derived2, "HKDF should produce consistent output");

        // Verify different inputs produce different outputs
        let pqc_ss_different = [3u8; 32];
        let derived3 = HybridKemProvider::derive_shared_secret(&x25519_ss, &pqc_ss_different)
            .expect("HKDF failed");

        assert_ne!(
            derived1, derived3,
            "Different inputs should produce different outputs"
        );
    }

    /// Test that invalid hybrid public key is rejected
    #[test]
    fn test_invalid_hybrid_public_key() {
        let invalid_key = vec![0u8; 100]; // Wrong size
        let result = HybridKemProvider::encapsulate(&invalid_key);

        assert!(result.is_err(), "Should reject invalid hybrid public key");
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("Invalid hybrid public key size"),
            "Error should mention invalid key size"
        );
    }

    /// Test that invalid hybrid ciphertext is rejected
    #[test]
    fn test_invalid_hybrid_ciphertext() {
        let keypair = HybridKemProvider::generate_keypair().expect("Keypair generation failed");
        let invalid_ciphertext = vec![0u8; 100]; // Wrong size

        let result = HybridKemProvider::decapsulate(&keypair.private_key(), &invalid_ciphertext);

        assert!(result.is_err(), "Should reject invalid ciphertext");
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("Invalid hybrid ciphertext size"),
            "Error should mention invalid ciphertext size"
        );
    }

    /// Test that invalid hybrid private key is rejected
    #[test]
    fn test_invalid_hybrid_private_key() {
        let keypair = HybridKemProvider::generate_keypair().expect("Keypair generation failed");
        let (ciphertext, _) =
            HybridKemProvider::encapsulate(&keypair.public_key()).expect("Encapsulation failed");

        let invalid_key = vec![0u8; 100]; // Wrong size
        let result = HybridKemProvider::decapsulate(&invalid_key, &ciphertext);

        assert!(result.is_err(), "Should reject invalid private key");
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("Invalid hybrid private key size"),
            "Error should mention invalid key size"
        );
    }

    /// Test multiple encapsulations produce different ciphertexts but valid shared secrets
    #[test]
    fn test_multiple_hybrid_encapsulations() {
        let keypair = HybridKemProvider::generate_keypair().expect("Keypair generation failed");
        let public_key = keypair.public_key();
        let private_key = keypair.private_key();

        let (ct1, ss1) =
            HybridKemProvider::encapsulate(&public_key).expect("First encapsulation failed");
        let (ct2, ss2) =
            HybridKemProvider::encapsulate(&public_key).expect("Second encapsulation failed");

        // Ciphertexts should be different (uses ephemeral keys)
        assert_ne!(
            ct1, ct2,
            "Ciphertexts should be different due to ephemeral keys"
        );

        // Both should decapsulate correctly
        let recovered1 =
            HybridKemProvider::decapsulate(&private_key, &ct1).expect("First decapsulation failed");
        let recovered2 = HybridKemProvider::decapsulate(&private_key, &ct2)
            .expect("Second decapsulation failed");

        assert_eq!(ss1, recovered1, "First shared secret should match");
        assert_eq!(ss2, recovered2, "Second shared secret should match");

        // The shared secrets should be different
        assert_ne!(
            ss1, ss2,
            "Different encapsulations should produce different shared secrets"
        );
    }

    /// Test keypair accessor methods
    #[test]
    fn test_keypair_accessors() {
        let keypair = HybridKemProvider::generate_keypair().expect("Keypair generation failed");

        assert_eq!(
            keypair.x25519_public_key(),
            &keypair.x25519_public[..],
            "x25519_public_key() should return X25519 public key"
        );

        assert_eq!(
            keypair.pqc_public_key(),
            &keypair.pqc_public[..],
            "pqc_public_key() should return PQC public key"
        );
    }
}
