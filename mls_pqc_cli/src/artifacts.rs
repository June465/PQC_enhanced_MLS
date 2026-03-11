//! Artifact persistence for MLS CLI operations.
//!
//! This module provides deterministic file naming and storage for
//! MLS protocol artifacts (Welcome, Commit, Ciphertext) to support
//! automated benchmarking and reproducibility.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::output::now_ms;

/// Manages artifact persistence with deterministic naming.
///
/// Artifacts are stored in the following structure:
/// ```text
/// <state_dir>/[<run_id>/]<group_id>/artifacts/
///   welcome/
///     <ts_ms>_<member_id>.bin
///   commit/
///     <ts_ms>_epoch<N>.bin
///   ciphertext/
///     <ts_ms>_<seq>.bin
///   key_package/
///     <member_id>.bin
///     <member_id>_data.json
/// ```
pub struct ArtifactManager {
    /// Base directory for artifacts (state_dir/[run_id/]group_id/artifacts)
    base_dir: PathBuf,
}

impl ArtifactManager {
    /// Create a new artifact manager for a specific group.
    ///
    /// # Arguments
    /// * `state_dir` - Root state directory
    /// * `group_id` - Group identifier
    /// * `run_id` - Optional run identifier for experiment isolation
    pub fn new(state_dir: &Path, group_id: &str, run_id: Option<&str>) -> Self {
        let mut base = state_dir.to_path_buf();
        
        // Add run_id subdirectory if provided
        if let Some(rid) = run_id {
            base.push(rid);
        }
        
        base.push(group_id);
        base.push("artifacts");
        
        Self { base_dir: base }
    }

    /// Ensure a directory exists, creating it if necessary.
    fn ensure_dir(&self, subdir: &str) -> io::Result<PathBuf> {
        let dir = self.base_dir.join(subdir);
        fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    /// Save a Welcome message artifact.
    ///
    /// Filename format: `<ts_ms>_<member_id>.bin`
    ///
    /// # Arguments
    /// * `member_id` - ID of the new member being welcomed
    /// * `data` - Raw Welcome message bytes
    ///
    /// # Returns
    /// Path to the saved artifact
    pub fn save_welcome(&self, member_id: &str, data: &[u8]) -> io::Result<PathBuf> {
        let dir = self.ensure_dir("welcome")?;
        let filename = format!("{}_{}.bin", now_ms(), sanitize_filename(member_id));
        let path = dir.join(filename);
        
        let mut file = fs::File::create(&path)?;
        file.write_all(data)?;
        
        Ok(path)
    }

    /// Save a Commit message artifact.
    ///
    /// Filename format: `<ts_ms>_epoch<N>.bin`
    ///
    /// # Arguments
    /// * `epoch` - Epoch number after the commit
    /// * `data` - Raw Commit message bytes
    ///
    /// # Returns
    /// Path to the saved artifact
    pub fn save_commit(&self, epoch: u64, data: &[u8]) -> io::Result<PathBuf> {
        let dir = self.ensure_dir("commit")?;
        let filename = format!("{}_epoch{}.bin", now_ms(), epoch);
        let path = dir.join(filename);
        
        let mut file = fs::File::create(&path)?;
        file.write_all(data)?;
        
        Ok(path)
    }

    /// Save a Ciphertext artifact.
    ///
    /// Filename format: `<ts_ms>_<seq>.bin`
    ///
    /// # Arguments
    /// * `seq` - Sequence number for ordering
    /// * `data` - Raw ciphertext bytes
    ///
    /// # Returns
    /// Path to the saved artifact
    pub fn save_ciphertext(&self, seq: u32, data: &[u8]) -> io::Result<PathBuf> {
        let dir = self.ensure_dir("ciphertext")?;
        let filename = format!("{}_{:06}.bin", now_ms(), seq);
        let path = dir.join(filename);
        
        let mut file = fs::File::create(&path)?;
        file.write_all(data)?;
        
        Ok(path)
    }

    /// Save a Key Package artifact.
    ///
    /// Filename format: `<member_id>.bin`
    ///
    /// # Arguments
    /// * `member_id` - ID of the member
    /// * `data` - Raw KeyPackage bytes
    ///
    /// # Returns
    /// Path to the saved artifact
    #[allow(dead_code)]
    pub fn save_key_package(&self, member_id: &str, data: &[u8]) -> io::Result<PathBuf> {
        let dir = self.ensure_dir("key_package")?;
        let filename = format!("{}.bin", sanitize_filename(member_id));
        let path = dir.join(filename);
        
        let mut file = fs::File::create(&path)?;
        file.write_all(data)?;
        
        Ok(path)
    }

    /// Save Key Package data JSON.
    ///
    /// Filename format: `<member_id>_data.json`
    ///
    /// # Arguments
    /// * `member_id` - ID of the member
    /// * `data` - Serialized KeyPackageData JSON
    ///
    /// # Returns
    /// Path to the saved artifact
    #[allow(dead_code)]
    pub fn save_key_package_data(&self, member_id: &str, data: &str) -> io::Result<PathBuf> {
        let dir = self.ensure_dir("key_package")?;
        let filename = format!("{}_data.json", sanitize_filename(member_id));
        let path = dir.join(filename);
        
        let mut file = fs::File::create(&path)?;
        file.write_all(data.as_bytes())?;
        
        Ok(path)
    }

    /// Get the base artifacts directory path.
    #[allow(dead_code)]
    pub fn base_path(&self) -> &Path {
        &self.base_dir
    }

    /// Get the path to the ciphertext counter file.
    fn counter_path(&self) -> PathBuf {
        self.base_dir.join(".ciphertext_counter")
    }

    /// Read and increment the ciphertext sequence counter.
    ///
    /// Returns the current counter value and increments it for next use.
    pub fn next_ciphertext_seq(&self) -> io::Result<u32> {
        let counter_file = self.counter_path();
        
        // Ensure base directory exists
        fs::create_dir_all(&self.base_dir)?;
        
        // Read current counter or default to 0
        let current = if counter_file.exists() {
            let content = fs::read_to_string(&counter_file)?;
            content.trim().parse::<u32>().unwrap_or(0)
        } else {
            0
        };
        
        // Increment and save
        let next = current + 1;
        fs::write(&counter_file, next.to_string())?;
        
        Ok(current)
    }
}

/// Sanitize a string for use in a filename.
///
/// Replaces potentially problematic characters with underscores.
fn sanitize_filename(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            _ => c,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_artifact_manager_creates_directories() {
        let temp_dir = std::env::temp_dir().join("mls_test_artifacts_dirs");
        let _ = fs::remove_dir_all(&temp_dir);
        
        let manager = ArtifactManager::new(&temp_dir, "test-group", None);
        
        // Save a welcome artifact (should create directories)
        let result = manager.save_welcome("Bob", b"welcome data");
        assert!(result.is_ok());
        
        let path = result.unwrap();
        assert!(path.exists());
        assert!(path.to_string_lossy().contains("welcome"));
        assert!(path.to_string_lossy().contains("Bob"));
        
        // Verify contents
        let content = fs::read(&path).unwrap();
        assert_eq!(content, b"welcome data");
        
        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_save_commit_with_epoch() {
        let temp_dir = std::env::temp_dir().join("mls_test_artifacts_commit");
        let _ = fs::remove_dir_all(&temp_dir);
        
        let manager = ArtifactManager::new(&temp_dir, "test-group", None);
        
        let result = manager.save_commit(42, b"commit data");
        assert!(result.is_ok());
        
        let path = result.unwrap();
        assert!(path.exists());
        assert!(path.to_string_lossy().contains("epoch42"));
        
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_save_ciphertext_with_sequence() {
        let temp_dir = std::env::temp_dir().join("mls_test_artifacts_ct");
        let _ = fs::remove_dir_all(&temp_dir);
        
        let manager = ArtifactManager::new(&temp_dir, "test-group", None);
        
        let result = manager.save_ciphertext(5, b"encrypted");
        assert!(result.is_ok());
        
        let path = result.unwrap();
        assert!(path.exists());
        assert!(path.to_string_lossy().contains("000005"));
        
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_ciphertext_counter() {
        let temp_dir = std::env::temp_dir().join("mls_test_counter");
        let _ = fs::remove_dir_all(&temp_dir);
        
        let manager = ArtifactManager::new(&temp_dir, "test-group", None);
        
        // First call should return 0
        assert_eq!(manager.next_ciphertext_seq().unwrap(), 0);
        // Second call should return 1
        assert_eq!(manager.next_ciphertext_seq().unwrap(), 1);
        // Third call should return 2
        assert_eq!(manager.next_ciphertext_seq().unwrap(), 2);
        
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_run_id_isolation() {
        let temp_dir = std::env::temp_dir().join("mls_test_run_id");
        let _ = fs::remove_dir_all(&temp_dir);
        
        let manager1 = ArtifactManager::new(&temp_dir, "group1", Some("experiment1"));
        let manager2 = ArtifactManager::new(&temp_dir, "group1", Some("experiment2"));
        
        manager1.save_welcome("Alice", b"exp1 data").unwrap();
        manager2.save_welcome("Alice", b"exp2 data").unwrap();
        
        // Verify paths are different
        assert!(manager1.base_path().to_string_lossy().contains("experiment1"));
        assert!(manager2.base_path().to_string_lossy().contains("experiment2"));
        
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_sanitize_filename() {
        assert_eq!(sanitize_filename("normal"), "normal");
        assert_eq!(sanitize_filename("has/slash"), "has_slash");
        assert_eq!(sanitize_filename("has\\backslash"), "has_backslash");
        assert_eq!(sanitize_filename("has:colon"), "has_colon");
        assert_eq!(sanitize_filename("user@example.com"), "user@example.com");
    }
}
