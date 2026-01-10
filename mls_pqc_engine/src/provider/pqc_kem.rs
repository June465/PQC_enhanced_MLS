//! PQC KEM Provider
//!
//! This module provides Post-Quantum Cryptography Key Encapsulation Mechanism (KEM)
//! functionality using ML-KEM 768 (FIPS 203 compliant).
//!
//! ML-KEM (formerly Kyber) is a lattice-based KEM that provides quantum-resistant
//! key encapsulation. This implementation uses the 768-bit security level (NIST Level 3).

use ml_kem::{
    kem::{Decapsulate, Encapsulate},
    EncodedSizeUser, KemCore, MlKem768,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::error::{EngineError, EngineResult};

/// ML-KEM 768 encapsulation key (public key) size in bytes
pub const ENCAPSULATION_KEY_SIZE: usize = 1184;

/// ML-KEM 768 decapsulation key (private key) size in bytes
pub const DECAPSULATION_KEY_SIZE: usize = 2400;

/// ML-KEM 768 ciphertext size in bytes
pub const CIPHERTEXT_SIZE: usize = 1088;

/// ML-KEM 768 shared secret size in bytes
pub const SHARED_SECRET_SIZE: usize = 32;

/// Encoded ML-KEM 768 keypair for persistence and transport
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PqcKemKeyPair {
    /// Encapsulation key (public key) - can be shared publicly
    pub encapsulation_key: Vec<u8>,
    /// Decapsulation key (private key) - must be kept secret
    pub decapsulation_key: Vec<u8>,
}

impl PqcKemKeyPair {
    /// Returns the encapsulation key (public key) as bytes
    pub fn public_key(&self) -> &[u8] {
        &self.encapsulation_key
    }

    /// Returns the decapsulation key (private key) as bytes
    pub fn private_key(&self) -> &[u8] {
        &self.decapsulation_key
    }
}

/// PQC KEM Provider for ML-KEM 768 operations
///
/// This struct provides static methods for KEM operations:
/// - Key generation
/// - Encapsulation (creates shared secret + ciphertext)
/// - Decapsulation (recovers shared secret from ciphertext)
pub struct PqcKemProvider;

impl PqcKemProvider {
    /// Generate a new ML-KEM 768 keypair
    ///
    /// # Returns
    /// A `PqcKemKeyPair` containing the encoded public and private keys
    ///
    /// # Errors
    /// Returns an error if the RNG fails
    ///
    /// # Example
    /// ```
    /// use mls_pqc_engine::provider::pqc_kem::PqcKemProvider;
    ///
    /// let keypair = PqcKemProvider::generate_keypair().unwrap();
    /// assert_eq!(keypair.encapsulation_key.len(), 1184);
    /// assert_eq!(keypair.decapsulation_key.len(), 2400);
    /// ```
    pub fn generate_keypair() -> EngineResult<PqcKemKeyPair> {
        let mut rng = OsRng;
        let (dk, ek) = MlKem768::generate(&mut rng);

        // Encode keys to bytes
        let encapsulation_key = ek.as_bytes().to_vec();
        let decapsulation_key = dk.as_bytes().to_vec();

        Ok(PqcKemKeyPair {
            encapsulation_key,
            decapsulation_key,
        })
    }

    /// Encapsulate a shared secret using the recipient's public key
    ///
    /// This creates a ciphertext that can only be decapsulated by the holder
    /// of the corresponding private key.
    ///
    /// # Arguments
    /// * `encapsulation_key` - The recipient's public key (1184 bytes)
    ///
    /// # Returns
    /// A tuple of (ciphertext, shared_secret):
    /// - `ciphertext`: The encrypted key material (1088 bytes)
    /// - `shared_secret`: The shared secret derived from this encapsulation (32 bytes)
    ///
    /// # Errors
    /// Returns an error if the encapsulation key is invalid
    pub fn encapsulate(encapsulation_key: &[u8]) -> EngineResult<(Vec<u8>, Vec<u8>)> {
        // Validate key size
        if encapsulation_key.len() != ENCAPSULATION_KEY_SIZE {
            return Err(EngineError::KemError(format!(
                "Invalid encapsulation key size: expected {}, got {}",
                ENCAPSULATION_KEY_SIZE,
                encapsulation_key.len()
            )));
        }

        // Parse the encapsulation key
        let ek_array: [u8; ENCAPSULATION_KEY_SIZE] = encapsulation_key
            .try_into()
            .map_err(|_| EngineError::KemError("Failed to parse encapsulation key".to_string()))?;

        let ek = <MlKem768 as KemCore>::EncapsulationKey::from_bytes(&ek_array.into());

        // Perform encapsulation
        let mut rng = OsRng;
        let (ct, shared_secret) = ek
            .encapsulate(&mut rng)
            .map_err(|e| EngineError::KemError(format!("Encapsulation failed: {:?}", e)))?;

        Ok((ct.as_slice().to_vec(), shared_secret.as_slice().to_vec()))
    }

    /// Decapsulate a ciphertext using the private key to recover the shared secret
    ///
    /// # Arguments
    /// * `decapsulation_key` - The private key (2400 bytes)
    /// * `ciphertext` - The ciphertext to decapsulate (1088 bytes)
    ///
    /// # Returns
    /// The shared secret (32 bytes) that matches the one produced during encapsulation
    ///
    /// # Errors
    /// Returns an error if the keys are invalid or decapsulation fails
    pub fn decapsulate(decapsulation_key: &[u8], ciphertext: &[u8]) -> EngineResult<Vec<u8>> {
        // Validate key size
        if decapsulation_key.len() != DECAPSULATION_KEY_SIZE {
            return Err(EngineError::KemError(format!(
                "Invalid decapsulation key size: expected {}, got {}",
                DECAPSULATION_KEY_SIZE,
                decapsulation_key.len()
            )));
        }

        // Validate ciphertext size
        if ciphertext.len() != CIPHERTEXT_SIZE {
            return Err(EngineError::KemError(format!(
                "Invalid ciphertext size: expected {}, got {}",
                CIPHERTEXT_SIZE,
                ciphertext.len()
            )));
        }

        // Parse the decapsulation key
        let dk_array: [u8; DECAPSULATION_KEY_SIZE] = decapsulation_key
            .try_into()
            .map_err(|_| EngineError::KemError("Failed to parse decapsulation key".to_string()))?;

        let dk = <MlKem768 as KemCore>::DecapsulationKey::from_bytes(&dk_array.into());

        // Parse the ciphertext
        let ct_array: [u8; CIPHERTEXT_SIZE] = ciphertext
            .try_into()
            .map_err(|_| EngineError::KemError("Failed to parse ciphertext".to_string()))?;

        // Perform decapsulation
        let shared_secret = dk
            .decapsulate(&ct_array.into())
            .map_err(|e| EngineError::KemError(format!("Decapsulation failed: {:?}", e)))?;

        Ok(shared_secret.as_slice().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test complete KEM roundtrip: generate keypair, encapsulate, decapsulate
    #[test]
    fn test_kem_roundtrip() {
        // Generate a keypair
        let keypair = PqcKemProvider::generate_keypair().expect("Keypair generation failed");

        // Encapsulate using the public key
        let (ciphertext, shared_secret_sender) =
            PqcKemProvider::encapsulate(&keypair.encapsulation_key)
                .expect("Encapsulation failed");

        // Decapsulate using the private key
        let shared_secret_receiver =
            PqcKemProvider::decapsulate(&keypair.decapsulation_key, &ciphertext)
                .expect("Decapsulation failed");

        // Verify the shared secrets match
        assert_eq!(
            shared_secret_sender, shared_secret_receiver,
            "Shared secrets should match after roundtrip"
        );

        // Verify shared secret size
        assert_eq!(
            shared_secret_sender.len(),
            SHARED_SECRET_SIZE,
            "Shared secret should be 32 bytes"
        );
    }

    /// Test that keypair has correct sizes
    #[test]
    fn test_keypair_sizes() {
        let keypair = PqcKemProvider::generate_keypair().expect("Keypair generation failed");

        assert_eq!(
            keypair.encapsulation_key.len(),
            ENCAPSULATION_KEY_SIZE,
            "Encapsulation key should be {} bytes",
            ENCAPSULATION_KEY_SIZE
        );

        assert_eq!(
            keypair.decapsulation_key.len(),
            DECAPSULATION_KEY_SIZE,
            "Decapsulation key should be {} bytes",
            DECAPSULATION_KEY_SIZE
        );
    }

    /// Test that encapsulation produces correct sizes
    #[test]
    fn test_encapsulation_sizes() {
        let keypair = PqcKemProvider::generate_keypair().expect("Keypair generation failed");
        let (ciphertext, shared_secret) =
            PqcKemProvider::encapsulate(&keypair.encapsulation_key)
                .expect("Encapsulation failed");

        assert_eq!(
            ciphertext.len(),
            CIPHERTEXT_SIZE,
            "Ciphertext should be {} bytes",
            CIPHERTEXT_SIZE
        );

        assert_eq!(
            shared_secret.len(),
            SHARED_SECRET_SIZE,
            "Shared secret should be {} bytes",
            SHARED_SECRET_SIZE
        );
    }

    /// Test that invalid encapsulation key is rejected
    #[test]
    fn test_invalid_encapsulation_key_rejected() {
        let invalid_key = vec![0u8; 100]; // Wrong size
        let result = PqcKemProvider::encapsulate(&invalid_key);

        assert!(result.is_err(), "Should reject invalid encapsulation key");
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("Invalid encapsulation key size"),
            "Error should mention invalid key size"
        );
    }

    /// Test that invalid ciphertext is rejected
    #[test]
    fn test_invalid_ciphertext_rejected() {
        let keypair = PqcKemProvider::generate_keypair().expect("Keypair generation failed");
        let invalid_ciphertext = vec![0u8; 100]; // Wrong size

        let result = PqcKemProvider::decapsulate(&keypair.decapsulation_key, &invalid_ciphertext);

        assert!(result.is_err(), "Should reject invalid ciphertext");
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("Invalid ciphertext size"),
            "Error should mention invalid ciphertext size"
        );
    }

    /// Test that invalid decapsulation key is rejected
    #[test]
    fn test_invalid_decapsulation_key_rejected() {
        let keypair = PqcKemProvider::generate_keypair().expect("Keypair generation failed");
        let (ciphertext, _) = PqcKemProvider::encapsulate(&keypair.encapsulation_key)
            .expect("Encapsulation failed");

        let invalid_key = vec![0u8; 100]; // Wrong size
        let result = PqcKemProvider::decapsulate(&invalid_key, &ciphertext);

        assert!(result.is_err(), "Should reject invalid decapsulation key");
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("Invalid decapsulation key size"),
            "Error should mention invalid key size"
        );
    }

    /// Test multiple encapsulations produce different ciphertexts but valid shared secrets
    #[test]
    fn test_multiple_encapsulations() {
        let keypair = PqcKemProvider::generate_keypair().expect("Keypair generation failed");

        let (ct1, ss1) = PqcKemProvider::encapsulate(&keypair.encapsulation_key)
            .expect("First encapsulation failed");
        let (ct2, ss2) = PqcKemProvider::encapsulate(&keypair.encapsulation_key)
            .expect("Second encapsulation failed");

        // Ciphertexts should be different (randomized encapsulation)
        assert_ne!(ct1, ct2, "Ciphertexts should be different due to randomization");

        // But both should decapsulate correctly
        let recovered1 = PqcKemProvider::decapsulate(&keypair.decapsulation_key, &ct1)
            .expect("First decapsulation failed");
        let recovered2 = PqcKemProvider::decapsulate(&keypair.decapsulation_key, &ct2)
            .expect("Second decapsulation failed");

        assert_eq!(ss1, recovered1, "First shared secret should match");
        assert_eq!(ss2, recovered2, "Second shared secret should match");

        // The shared secrets should be different since they come from different encapsulations
        assert_ne!(ss1, ss2, "Different encapsulations should produce different shared secrets");
    }

    /// Test that keypair helper methods work correctly
    #[test]
    fn test_keypair_accessors() {
        let keypair = PqcKemProvider::generate_keypair().expect("Keypair generation failed");

        assert_eq!(
            keypair.public_key(),
            &keypair.encapsulation_key[..],
            "public_key() should return encapsulation key"
        );

        assert_eq!(
            keypair.private_key(),
            &keypair.decapsulation_key[..],
            "private_key() should return decapsulation key"
        );
    }
}
