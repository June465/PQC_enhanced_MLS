//! Error types for the MLS PQC Engine

use thiserror::Error;

/// Errors that can occur in the MLS PQC Engine
#[derive(Error, Debug)]
pub enum EngineError {
    /// Error during group creation
    #[error("Failed to create group: {0}")]
    GroupCreation(String),

    /// Error during member addition
    #[error("Failed to add member: {0}")]
    MemberAddition(String),

    /// Error during member removal
    #[error("Failed to remove member: {0}")]
    MemberRemoval(String),

    /// Error during commit processing
    #[error("Failed to process commit: {0}")]
    CommitProcessing(String),

    /// Error during message encryption
    #[error("Encryption failed: {0}")]
    Encryption(String),

    /// Error during message decryption
    #[error("Decryption failed: {0}")]
    Decryption(String),

    /// Error during state serialization
    #[error("Serialization failed: {0}")]
    Serialization(String),

    /// Error during state deserialization
    #[error("Deserialization failed: {0}")]
    Deserialization(String),

    /// Error in cryptographic operations
    #[error("Crypto error: {0}")]
    Crypto(String),

    /// Error reading/writing state files
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Generic error
    #[error("Generic error: {0}")]
    Generic(String),

    /// Storage error
    #[error("Storage error: {0}")]
    Storage(String),
}

/// Result type alias for engine operations
pub type EngineResult<T> = Result<T, EngineError>;
