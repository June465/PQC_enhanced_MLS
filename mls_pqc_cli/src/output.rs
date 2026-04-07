//! Benchmark-ready JSONL output for CLI commands.
//!
//! This module provides structured output with timing, byte metrics,
//! and epoch tracking for all CLI operations.

use serde::Serialize;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Schema version for benchmark output format.
/// Matches CURRENT_SCHEMA_VERSION from engine state.
pub const OUTPUT_SCHEMA_VERSION: u32 = 1;

/// Get current Unix timestamp in milliseconds.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// Artifact byte sizes for operations that produce artifacts.
#[derive(Serialize, Default)]
pub struct ArtifactBytes {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub welcome: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ciphertext: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_package: Option<u64>,
}

impl ArtifactBytes {
    /// Check if any artifact bytes are set.
    pub fn is_empty(&self) -> bool {
        self.welcome.is_none()
            && self.commit.is_none()
            && self.ciphertext.is_none()
            && self.key_package.is_none()
    }
}

/// Comprehensive benchmark output for all CLI operations.
///
/// Every CLI command emits exactly one JSONL line with this structure.
#[derive(Serialize)]
pub struct BenchmarkOutput {
    /// Schema version (always 1)
    pub schema_version: u32,
    /// Unix timestamp in milliseconds
    pub ts_ms: u64,
    /// Cryptographic suite name
    pub suite: String,
    /// Operation name (init_group, add_member, encrypt, etc.)
    pub op: String,
    /// Group identifier (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_id: Option<String>,
    /// Member ID performing the operation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member_id: Option<String>,
    /// Number of members in group after operation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_size: Option<u32>,
    /// Epoch before state-modifying operation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch_before: Option<u64>,
    /// Epoch after state-modifying operation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch_after: Option<u64>,
    /// Whether operation succeeded
    pub ok: bool,
    /// Operation duration in milliseconds
    pub time_ms: u64,
    /// Input bytes (key package, ciphertext, plaintext)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_in: Option<u64>,
    /// Output bytes (ciphertext, plaintext)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_out: Option<u64>,
    /// Artifact sizes produced by operation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_bytes: Option<ArtifactBytes>,
    /// Error message if ok=false
    #[serde(skip_serializing_if = "Option::is_none")]
    pub err: Option<String>,
}

impl BenchmarkOutput {
    /// Create a new benchmark output with required fields.
    pub fn new(op: &str, suite: &str) -> Self {
        Self {
            schema_version: OUTPUT_SCHEMA_VERSION,
            ts_ms: now_ms(),
            suite: suite.to_string(),
            op: op.to_string(),
            group_id: None,
            member_id: None,
            group_size: None,
            epoch_before: None,
            epoch_after: None,
            ok: true,
            time_ms: 0,
            bytes_in: None,
            bytes_out: None,
            artifact_bytes: None,
            err: None,
        }
    }

    /// Set group_id.
    pub fn with_group_id(mut self, group_id: &str) -> Self {
        self.group_id = Some(group_id.to_string());
        self
    }

    /// Set member_id.
    pub fn with_member_id(mut self, member_id: &str) -> Self {
        self.member_id = Some(member_id.to_string());
        self
    }

    /// Set group_size.
    pub fn with_group_size(mut self, size: u32) -> Self {
        self.group_size = Some(size);
        self
    }

    /// Set epoch_before.
    pub fn with_epoch_before(mut self, epoch: u64) -> Self {
        self.epoch_before = Some(epoch);
        self
    }

    /// Set epoch_after.
    pub fn with_epoch_after(mut self, epoch: u64) -> Self {
        self.epoch_after = Some(epoch);
        self
    }

    /// Set timing from Instant.
    pub fn with_timing(mut self, start: Instant) -> Self {
        self.time_ms = start.elapsed().as_millis() as u64;
        self
    }

    /// Set bytes_in.
    pub fn with_bytes_in(mut self, bytes: u64) -> Self {
        self.bytes_in = Some(bytes);
        self
    }

    /// Set bytes_out.
    pub fn with_bytes_out(mut self, bytes: u64) -> Self {
        self.bytes_out = Some(bytes);
        self
    }

    /// Set artifact_bytes.
    pub fn with_artifact_bytes(mut self, artifacts: ArtifactBytes) -> Self {
        if !artifacts.is_empty() {
            self.artifact_bytes = Some(artifacts);
        }
        self
    }

    /// Mark as error with message.
    pub fn with_error(mut self, err: &str) -> Self {
        self.ok = false;
        self.err = Some(err.to_string());
        self
    }

    /// Create an error output.
    pub fn error(op: &str, suite: &str, err: &str, start: Instant) -> Self {
        Self::new(op, suite)
            .with_timing(start)
            .with_error(err)
    }

    /// Print as single JSONL line to stdout.
    pub fn print(&self) {
        let json = serde_json::to_string(self).expect("Failed to serialize BenchmarkOutput");
        println!("{}", json);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_now_ms_is_reasonable() {
        let ts = now_ms();
        // Should be after 2024-01-01 (in ms)
        assert!(ts > 1_704_067_200_000);
    }

    #[test]
    fn test_benchmark_output_required_fields() {
        let output = BenchmarkOutput::new("test_op", "classic");
        let json = serde_json::to_string(&output).unwrap();
        
        // Verify required fields present
        assert!(json.contains("\"schema_version\":1"));
        assert!(json.contains("\"ts_ms\":"));
        assert!(json.contains("\"suite\":\"classic\""));
        assert!(json.contains("\"op\":\"test_op\""));
        assert!(json.contains("\"ok\":true"));
        assert!(json.contains("\"time_ms\":"));
    }

    #[test]
    fn test_benchmark_output_skips_none_fields() {
        let output = BenchmarkOutput::new("test", "classic");
        let json = serde_json::to_string(&output).unwrap();
        
        // Optional fields should not be present when None
        assert!(!json.contains("\"group_id\""));
        assert!(!json.contains("\"member_id\""));
        assert!(!json.contains("\"err\""));
        assert!(!json.contains("\"artifact_bytes\""));
    }

    #[test]
    fn test_artifact_bytes_serialization() {
        let artifacts = ArtifactBytes {
            welcome: Some(1234),
            commit: Some(567),
            ciphertext: None,
            key_package: None,
        };
        
        let output = BenchmarkOutput::new("add_member", "hybrid_kem")
            .with_artifact_bytes(artifacts);
        let json = serde_json::to_string(&output).unwrap();
        
        assert!(json.contains("\"welcome\":1234"));
        assert!(json.contains("\"commit\":567"));
        assert!(!json.contains("\"ciphertext\""));
        assert!(!json.contains("\"key_package\""));
    }

    #[test]
    fn test_error_output() {
        let start = Instant::now();
        std::thread::sleep(std::time::Duration::from_millis(1));
        let output = BenchmarkOutput::error("encrypt", "pqc_kem", "Test error", start);
        
        assert!(!output.ok);
        assert_eq!(output.err, Some("Test error".to_string()));
        assert!(output.time_ms >= 1);
    }
}
