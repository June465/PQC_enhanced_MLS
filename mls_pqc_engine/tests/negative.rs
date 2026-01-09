//! Negative tests for MLS engine error handling
//!
//! These tests verify that the engine handles error conditions gracefully
//! without panicking and returns appropriate error messages.

use mls_pqc_engine::engine::MlsEngine;
use mls_pqc_engine::error::EngineResult;

/// Test that decrypting with wrong group state fails gracefully
#[test]
fn test_decrypt_wrong_group_fails() -> EngineResult<()> {
    let engine = MlsEngine::new()?;
    
    // Create two separate groups
    let mut alice_group1 = engine.create_group(b"group-1", b"Alice")?;
    let mut alice_group2 = engine.create_group(b"group-2", b"Alice-2")?;
    
    // Add Bob to group 1
    let bob_kp_data = engine.generate_key_package(b"Bob")?;
    let (welcome, _) = engine.add_member(&mut alice_group1, &bob_kp_data.key_package_bytes)?;
    let mut bob_group1 = engine.process_welcome(&welcome, bob_kp_data)?;
    
    // Alice in group 1 encrypts a message
    let ciphertext = engine.encrypt_message(&mut alice_group1, b"Secret for group 1")?;
    
    // Try to decrypt with wrong group state (group 2 instead of group 1)
    let result = engine.decrypt_message(&mut alice_group2, &ciphertext);
    
    // Should fail - not panic
    assert!(result.is_err(), "Decryption with wrong group should fail");
    
    // Verify Bob in the correct group CAN decrypt
    let decrypted = engine.decrypt_message(&mut bob_group1, &ciphertext)?;
    assert_eq!(decrypted, b"Secret for group 1".to_vec());
    
    Ok(())
}

/// Test that invalid key package bytes are rejected
#[test]
fn test_invalid_key_package() -> EngineResult<()> {
    let engine = MlsEngine::new()?;
    
    let mut alice_state = engine.create_group(b"invalid-kp-test", b"Alice")?;
    
    // Try to add a member with garbage key package data
    let garbage_kp = vec![0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    let result = engine.add_member(&mut alice_state, &garbage_kp);
    
    // Should fail with deserialization error
    assert!(result.is_err(), "Adding member with invalid key package should fail");
    let error = result.unwrap_err();
    assert!(error.to_string().contains("Invalid key package") || 
            error.to_string().contains("Deserialization"),
            "Error should mention invalid key package or deserialization");
    
    Ok(())
}

/// Test that empty key package is rejected
#[test]
fn test_empty_key_package() -> EngineResult<()> {
    let engine = MlsEngine::new()?;
    
    let mut alice_state = engine.create_group(b"empty-kp-test", b"Alice")?;
    
    // Try to add a member with empty key package
    let empty_kp = vec![];
    let result = engine.add_member(&mut alice_state, &empty_kp);
    
    // Should fail
    assert!(result.is_err(), "Adding member with empty key package should fail");
    
    Ok(())
}

/// Test that invalid ciphertext is rejected
#[test]
fn test_invalid_ciphertext() -> EngineResult<()> {
    let engine = MlsEngine::new()?;
    
    // Create group with two members
    let mut alice_state = engine.create_group(b"invalid-ct-test", b"Alice")?;
    let bob_kp_data = engine.generate_key_package(b"Bob")?;
    let (welcome, _) = engine.add_member(&mut alice_state, &bob_kp_data.key_package_bytes)?;
    let mut bob_state = engine.process_welcome(&welcome, bob_kp_data)?;
    
    // Try to decrypt garbage data
    let garbage = vec![0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let result = engine.decrypt_message(&mut bob_state, &garbage);
    
    // Should fail with deserialization error
    assert!(result.is_err(), "Decryption of invalid ciphertext should fail");
    
    Ok(())
}

/// Test that loading from non-existent file fails gracefully
#[test]
fn test_load_nonexistent_file() {
    use mls_pqc_engine::engine::state::GroupState;
    
    let result = GroupState::load("/path/that/does/not/exist.json");
    
    assert!(result.is_err(), "Loading non-existent file should fail");
}

/// Test that engine handles empty plaintext
#[test]
fn test_encrypt_empty_message() -> EngineResult<()> {
    let engine = MlsEngine::new()?;
    
    // Create group with two members
    let mut alice_state = engine.create_group(b"empty-msg-test", b"Alice")?;
    let bob_kp_data = engine.generate_key_package(b"Bob")?;
    let (welcome, _) = engine.add_member(&mut alice_state, &bob_kp_data.key_package_bytes)?;
    let mut bob_state = engine.process_welcome(&welcome, bob_kp_data)?;
    
    // Encrypt empty message
    let ciphertext = engine.encrypt_message(&mut alice_state, b"")?;
    
    // Decrypt and verify
    let decrypted = engine.decrypt_message(&mut bob_state, &ciphertext)?;
    assert!(decrypted.is_empty(), "Decrypted empty message should be empty");
    
    Ok(())
}

/// Test that corrupted welcome message is rejected
#[test]
fn test_corrupted_welcome_message() -> EngineResult<()> {
    let engine = MlsEngine::new()?;
    
    // Alice creates a group
    let mut alice_state = engine.create_group(b"corrupt-welcome-test", b"Alice")?;
    
    // Generate key package for Bob
    let bob_kp_data = engine.generate_key_package(b"Bob")?;
    
    // Alice adds Bob and gets welcome
    let (mut welcome_bytes, _) = engine.add_member(&mut alice_state, &bob_kp_data.key_package_bytes)?;
    
    // Corrupt the welcome message
    if !welcome_bytes.is_empty() {
        welcome_bytes[0] ^= 0xFF; // Flip bits in first byte
    }
    
    // Generate fresh key package for Bob (since original one was used)
    let bob_kp_data2 = engine.generate_key_package(b"Bob2")?;
    let result = engine.process_welcome(&welcome_bytes, bob_kp_data2);
    
    // Should fail
    assert!(result.is_err(), "Processing corrupted welcome should fail");
    
    Ok(())
}
