//! Cryptographic suite selection for MLS operations.
//!
//! This module defines the supported cryptographic suites for the PQC-enhanced MLS engine:
//! - Classic: Standard MLS with X25519/Ed25519 (DHKEM)
//! - PqcKem: Post-Quantum KEM using ML-KEM 768
//! - HybridKem: Combined X25519 + ML-KEM 768 for defense-in-depth

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Cryptographic suite options for MLS operations.
///
/// The suite determines which key encapsulation mechanism is used:
/// - `Classic`: Standard MLS using X25519 DHKEM (no PQC)
/// - `PqcKem`: ML-KEM 768 for post-quantum security
/// - `HybridKem`: X25519 + ML-KEM 768 for defense-in-depth
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CryptoSuite {
    /// Classic MLS with X25519/Ed25519 (no PQC enhancement)
    #[default]
    Classic,
    /// Post-Quantum KEM only (ML-KEM 768)
    PqcKem,
    /// Hybrid: Classic X25519 + ML-KEM 768
    HybridKem,
}

impl CryptoSuite {
    /// Returns true if this suite uses PQC key encapsulation.
    pub fn is_pqc(&self) -> bool {
        matches!(self, CryptoSuite::PqcKem | CryptoSuite::HybridKem)
    }

    /// Returns true if this suite uses hybrid (classical + PQC) encapsulation.
    pub fn is_hybrid(&self) -> bool {
        matches!(self, CryptoSuite::HybridKem)
    }

    /// Returns a human-readable description of the suite.
    pub fn description(&self) -> &'static str {
        match self {
            CryptoSuite::Classic => "Classic MLS (X25519/Ed25519)",
            CryptoSuite::PqcKem => "Post-Quantum KEM (ML-KEM 768)",
            CryptoSuite::HybridKem => "Hybrid KEM (X25519 + ML-KEM 768)",
        }
    }
}

impl fmt::Display for CryptoSuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoSuite::Classic => write!(f, "classic"),
            CryptoSuite::PqcKem => write!(f, "pqc_kem"),
            CryptoSuite::HybridKem => write!(f, "hybrid_kem"),
        }
    }
}

impl FromStr for CryptoSuite {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().replace('-', "_").as_str() {
            "classic" => Ok(CryptoSuite::Classic),
            "pqc_kem" | "pqckem" | "pqc" => Ok(CryptoSuite::PqcKem),
            "hybrid_kem" | "hybridkem" | "hybrid" => Ok(CryptoSuite::HybridKem),
            _ => Err(format!(
                "Unknown crypto suite '{}'. Valid options: classic, pqc_kem, hybrid_kem",
                s
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_suite_default_is_classic() {
        assert_eq!(CryptoSuite::default(), CryptoSuite::Classic);
    }

    #[test]
    fn test_suite_is_pqc() {
        assert!(!CryptoSuite::Classic.is_pqc());
        assert!(CryptoSuite::PqcKem.is_pqc());
        assert!(CryptoSuite::HybridKem.is_pqc());
    }

    #[test]
    fn test_suite_is_hybrid() {
        assert!(!CryptoSuite::Classic.is_hybrid());
        assert!(!CryptoSuite::PqcKem.is_hybrid());
        assert!(CryptoSuite::HybridKem.is_hybrid());
    }

    #[test]
    fn test_suite_display() {
        assert_eq!(CryptoSuite::Classic.to_string(), "classic");
        assert_eq!(CryptoSuite::PqcKem.to_string(), "pqc_kem");
        assert_eq!(CryptoSuite::HybridKem.to_string(), "hybrid_kem");
    }

    #[test]
    fn test_suite_from_str() {
        assert_eq!("classic".parse::<CryptoSuite>().unwrap(), CryptoSuite::Classic);
        assert_eq!("pqc_kem".parse::<CryptoSuite>().unwrap(), CryptoSuite::PqcKem);
        assert_eq!("pqc-kem".parse::<CryptoSuite>().unwrap(), CryptoSuite::PqcKem);
        assert_eq!("hybrid_kem".parse::<CryptoSuite>().unwrap(), CryptoSuite::HybridKem);
        assert_eq!("hybrid-kem".parse::<CryptoSuite>().unwrap(), CryptoSuite::HybridKem);
        assert!("invalid".parse::<CryptoSuite>().is_err());
    }

    #[test]
    fn test_suite_serde_roundtrip() {
        let suites = [CryptoSuite::Classic, CryptoSuite::PqcKem, CryptoSuite::HybridKem];
        for suite in suites {
            let json = serde_json::to_string(&suite).unwrap();
            let parsed: CryptoSuite = serde_json::from_str(&json).unwrap();
            assert_eq!(suite, parsed);
        }
    }
}
