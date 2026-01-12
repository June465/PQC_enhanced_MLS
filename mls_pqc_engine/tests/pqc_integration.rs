//! Integration tests for PQC/Hybrid suite support
//!
//! These tests verify that the PQC and Hybrid KEM suites work
//! correctly with the MLS engine for full group lifecycle operations.

use mls_pqc_engine::engine::{MlsEngine, CryptoSuite, GroupState};
use mls_pqc_engine::error::EngineResult;

// =============================================================================
// PQC Suite Tests
// =============================================================================

/// Test that a group can be created with PQC suite
#[test]
fn test_pqc_create_group() -> EngineResult<()> {
    let engine = MlsEngine::new()?;
    let group_state = engine.create_group_with_suite(
        b"pqc-test-group",
        b"Alice",
        CryptoSuite::PqcKem,
    )?;
    
    assert_eq!(group_state.suite, CryptoSuite::PqcKem);
    assert!(group_state.pqc_keypair.is_some(), "PQC keypair should be present");
    
    let pqc_kp = group_state.pqc_keypair.as_ref().unwrap();
    assert_eq!(pqc_kp.public_key.len(), 1184, "ML-KEM 768 public key should be 1184 bytes");
    assert_eq!(pqc_kp.private_key.len(), 2400, "ML-KEM 768 private key should be 2400 bytes");
    
    Ok(())
}

/// Test that a group can be created with Hybrid suite
#[test]
fn test_hybrid_create_group() -> EngineResult<()> {
    let engine = MlsEngine::new()?;
    let group_state = engine.create_group_with_suite(
        b"hybrid-test-group",
        b"Alice",
        CryptoSuite::HybridKem,
    )?;
    
    assert_eq!(group_state.suite, CryptoSuite::HybridKem);
    assert!(group_state.pqc_keypair.is_some(), "Hybrid keypair should be present");
    
    let hybrid_kp = group_state.pqc_keypair.as_ref().unwrap();
    assert_eq!(hybrid_kp.public_key.len(), 1216, "Hybrid public key should be 1216 bytes (32 + 1184)");
    assert_eq!(hybrid_kp.private_key.len(), 2432, "Hybrid private key should be 2432 bytes (32 + 2400)");
    
    Ok(())
}

/// Test that Classic suite does NOT generate PQC keypair
#[test]
fn test_classic_no_pqc_keypair() -> EngineResult<()> {
    let engine = MlsEngine::new()?;
    let group_state = engine.create_group_with_suite(
        b"classic-test-group",
        b"Alice",
        CryptoSuite::Classic,
    )?;
    
    assert_eq!(group_state.suite, CryptoSuite::Classic);
    assert!(group_state.pqc_keypair.is_none(), "Classic suite should NOT have PQC keypair");
    
    Ok(())
}

// =============================================================================
// PQC Key Package Tests
// =============================================================================

/// Test that key packages can be generated with PQC suite
#[test]
fn test_pqc_generate_key_package() -> EngineResult<()> {
    let engine = MlsEngine::new()?;
    let kp_data = engine.generate_key_package_with_suite(b"Bob", CryptoSuite::PqcKem)?;
    
    assert_eq!(kp_data.suite, CryptoSuite::PqcKem);
    assert!(kp_data.pqc_keypair.is_some(), "PQC keypair should be present in key package data");
    assert!(!kp_data.key_package_bytes.is_empty(), "Key package bytes should not be empty");
    
    Ok(())
}

/// Test that key packages can be generated with Hybrid suite
#[test]
fn test_hybrid_generate_key_package() -> EngineResult<()> {
    let engine = MlsEngine::new()?;
    let kp_data = engine.generate_key_package_with_suite(b"Charlie", CryptoSuite::HybridKem)?;
    
    assert_eq!(kp_data.suite, CryptoSuite::HybridKem);
    assert!(kp_data.pqc_keypair.is_some(), "Hybrid keypair should be present in key package data");
    
    Ok(())
}

// =============================================================================
// PQC Full Lifecycle Tests
// =============================================================================

/// Test full PQC lifecycle: create group, add member, encrypt/decrypt
#[test]
fn test_pqc_full_lifecycle() -> EngineResult<()> {
    let engine = MlsEngine::new()?;
    
    // Alice creates a group with PQC suite
    let mut alice_state = engine.create_group_with_suite(
        b"pqc-lifecycle-test",
        b"Alice",
        CryptoSuite::PqcKem,
    )?;
    assert_eq!(alice_state.suite, CryptoSuite::PqcKem);
    
    // Bob generates a key package (also with PQC suite)
    let bob_kp_data = engine.generate_key_package_with_suite(b"Bob", CryptoSuite::PqcKem)?;
    
    // Alice adds Bob
    let (welcome_bytes, _commit_bytes) = engine.add_member(
        &mut alice_state,
        &bob_kp_data.key_package_bytes,
    )?;
    
    // Bob joins the group
    let mut bob_state = engine.process_welcome(&welcome_bytes, bob_kp_data)?;
    
    // Verify both are using PQC suite
    assert_eq!(alice_state.suite, CryptoSuite::PqcKem);
    assert_eq!(bob_state.suite, CryptoSuite::PqcKem);
    
    // Verify epoch convergence
    assert_eq!(alice_state.epoch(), 1);
    assert_eq!(bob_state.epoch(), 1);
    
    // Alice encrypts a message
    let plaintext = b"Secret PQC message from Alice!";
    let ciphertext = engine.encrypt_message(&mut alice_state, plaintext)?;
    
    // Bob decrypts the message
    let decrypted = engine.decrypt_message(&mut bob_state, &ciphertext)?;
    assert_eq!(decrypted, plaintext.to_vec());
    
    Ok(())
}

/// Test full Hybrid lifecycle: create group, add member, encrypt/decrypt
#[test]
fn test_hybrid_full_lifecycle() -> EngineResult<()> {
    let engine = MlsEngine::new()?;
    
    // Alice creates a group with Hybrid suite
    let mut alice_state = engine.create_group_with_suite(
        b"hybrid-lifecycle-test",
        b"Alice",
        CryptoSuite::HybridKem,
    )?;
    assert_eq!(alice_state.suite, CryptoSuite::HybridKem);
    
    // Bob generates a key package (also with Hybrid suite)  
    let bob_kp_data = engine.generate_key_package_with_suite(b"Bob", CryptoSuite::HybridKem)?;
    
    // Alice adds Bob
    let (welcome_bytes, _commit_bytes) = engine.add_member(
        &mut alice_state,
        &bob_kp_data.key_package_bytes,
    )?;
    
    // Bob joins the group
    let mut bob_state = engine.process_welcome(&welcome_bytes, bob_kp_data)?;
    
    // Verify both are using Hybrid suite
    assert_eq!(alice_state.suite, CryptoSuite::HybridKem);
    assert_eq!(bob_state.suite, CryptoSuite::HybridKem);
    
    // Bidirectional messaging test
    let msg1 = b"Hybrid message from Alice";
    let ct1 = engine.encrypt_message(&mut alice_state, msg1)?;
    let pt1 = engine.decrypt_message(&mut bob_state, &ct1)?;
    assert_eq!(pt1, msg1.to_vec());
    
    let msg2 = b"Hybrid reply from Bob";
    let ct2 = engine.encrypt_message(&mut bob_state, msg2)?;
    let pt2 = engine.decrypt_message(&mut alice_state, &ct2)?;
    assert_eq!(pt2, msg2.to_vec());
    
    Ok(())
}

// =============================================================================
// State Persistence Tests
// =============================================================================

/// Test that PQC suite info is preserved across save/load
#[test]
fn test_pqc_state_persistence() -> EngineResult<()> {
    let engine = MlsEngine::new()?;
    let temp_dir = tempfile::tempdir().expect("Failed to create temp directory");
    let state_path = temp_dir.path().join("pqc_group.json");
    let state_path_str = state_path.to_str().unwrap();
    
    // Create a group with PQC suite
    let group_state = engine.create_group_with_suite(
        b"pqc-persistence-test",
        b"Alice",
        CryptoSuite::PqcKem,
    )?;
    
    // Save state
    group_state.save(state_path_str)?;
    
    // Load state
    let loaded_state = GroupState::load(state_path_str)?;
    
    // Verify suite is preserved
    assert_eq!(loaded_state.suite, CryptoSuite::PqcKem);
    assert!(loaded_state.pqc_keypair.is_some(), "PQC keypair should be preserved");
    
    // Verify key sizes are correct after load
    let pqc_kp = loaded_state.pqc_keypair.as_ref().unwrap();
    assert_eq!(pqc_kp.public_key.len(), 1184);
    assert_eq!(pqc_kp.private_key.len(), 2400);
    
    Ok(())
}

/// Test that Hybrid suite info is preserved across save/load
#[test]
fn test_hybrid_state_persistence() -> EngineResult<()> {
    let engine = MlsEngine::new()?;
    let temp_dir = tempfile::tempdir().expect("Failed to create temp directory");
    let state_path = temp_dir.path().join("hybrid_group.json");
    let state_path_str = state_path.to_str().unwrap();
    
    // Create a group with Hybrid suite
    let group_state = engine.create_group_with_suite(
        b"hybrid-persistence-test",
        b"Alice",
        CryptoSuite::HybridKem,
    )?;
    
    // Save and load state
    group_state.save(state_path_str)?;
    let loaded_state = GroupState::load(state_path_str)?;
    
    // Verify suite and keypair
    assert_eq!(loaded_state.suite, CryptoSuite::HybridKem);
    assert!(loaded_state.pqc_keypair.is_some());
    
    let hybrid_kp = loaded_state.pqc_keypair.as_ref().unwrap();
    assert_eq!(hybrid_kp.public_key.len(), 1216);
    assert_eq!(hybrid_kp.private_key.len(), 2432);
    
    Ok(())
}

// =============================================================================
// Regression Tests (Classic suite should still work)
// =============================================================================

/// Regression test: Classic suite lifecycle still works
#[test]
fn test_classic_regression_lifecycle() -> EngineResult<()> {
    let engine = MlsEngine::new()?;
    
    // Using create_group (delegates to Classic suite)
    let mut alice_state = engine.create_group(b"classic-regression", b"Alice")?;
    assert_eq!(alice_state.suite, CryptoSuite::Classic);
    assert!(alice_state.pqc_keypair.is_none());
    
    // Using generate_key_package (delegates to Classic suite)
    let bob_kp_data = engine.generate_key_package(b"Bob")?;
    assert_eq!(bob_kp_data.suite, CryptoSuite::Classic);
    assert!(bob_kp_data.pqc_keypair.is_none());
    
    // Full lifecycle
    let (welcome_bytes, _) = engine.add_member(&mut alice_state, &bob_kp_data.key_package_bytes)?;
    let mut bob_state = engine.process_welcome(&welcome_bytes, bob_kp_data)?;
    
    let msg = b"Classic message test";
    let ct = engine.encrypt_message(&mut alice_state, msg)?;
    let pt = engine.decrypt_message(&mut bob_state, &ct)?;
    assert_eq!(pt, msg.to_vec());
    
    Ok(())
}
