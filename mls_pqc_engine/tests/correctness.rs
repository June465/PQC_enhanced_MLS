//! Integration tests for MLS engine correctness
//!
//! These tests verify the correct operation of the MLS engine,
//! including group creation, member management, and secure messaging.

use mls_pqc_engine::engine::{MlsEngine, GroupState};
use mls_pqc_engine::error::EngineResult;
use tempfile::tempdir;

/// Test that Alice can create a group successfully
#[test]
fn test_create_group() -> EngineResult<()> {
    let engine = MlsEngine::new()?;
    let group_state = engine.create_group(b"test-group-1", b"Alice")?;
    
    assert_eq!(group_state.group_id_string(), "test-group-1");
    assert_eq!(group_state.epoch(), 0);
    
    Ok(())
}

/// Test the full member addition flow
/// Alice creates a group, Bob generates a key package, Alice adds Bob
#[test]
fn test_add_member() -> EngineResult<()> {
    let engine = MlsEngine::new()?;
    
    // Alice creates a group
    let mut alice_state = engine.create_group(b"test-group-2", b"Alice")?;
    assert_eq!(alice_state.epoch(), 0);
    
    // Bob generates a key package
    let bob_kp_data = engine.generate_key_package(b"Bob")?;
    
    // Alice adds Bob to the group
    let (welcome_bytes, _commit_bytes) = engine.add_member(&mut alice_state, &bob_kp_data.key_package_bytes)?;
    
    // After adding Bob, Alice's epoch should advance
    assert_eq!(alice_state.epoch(), 1);
    assert!(!welcome_bytes.is_empty());
    
    Ok(())
}

/// Test convergence: Both Alice and Bob should have the same epoch after Bob joins
#[test]
fn test_convergence_alice_and_bob() -> EngineResult<()> {
    let engine = MlsEngine::new()?;
    
    // Alice creates a group
    let mut alice_state = engine.create_group(b"convergence-test", b"Alice")?;
    
    // Bob generates a key package
    let bob_kp_data = engine.generate_key_package(b"Bob")?;
    
    // Alice adds Bob
    let (welcome_bytes, _commit_bytes) = engine.add_member(&mut alice_state, &bob_kp_data.key_package_bytes)?;
    
    // Bob processes the welcome message to join
    let bob_state = engine.process_welcome(&welcome_bytes, bob_kp_data)?;
    
    // Verify convergence: Both should be at epoch 1
    assert_eq!(alice_state.epoch(), 1, "Alice should be at epoch 1");
    assert_eq!(bob_state.epoch(), 1, "Bob should be at epoch 1");
    
    // Verify they're in the same group
    assert_eq!(
        alice_state.group.group_id(),
        bob_state.group.group_id(),
        "Both should be in the same group"
    );
    
    Ok(())
}

/// Test full lifecycle: create, add member, encrypt, decrypt
#[test]
fn test_lifecycle_encrypt_decrypt() -> EngineResult<()> {
    let engine = MlsEngine::new()?;
    
    // Alice creates a group
    let mut alice_state = engine.create_group(b"lifecycle-test", b"Alice")?;
    
    // Bob generates a key package
    let bob_kp_data = engine.generate_key_package(b"Bob")?;
    
    // Alice adds Bob
    let (welcome_bytes, _commit_bytes) = engine.add_member(&mut alice_state, &bob_kp_data.key_package_bytes)?;
    
    // Bob joins the group
    let mut bob_state = engine.process_welcome(&welcome_bytes, bob_kp_data)?;
    
    // Alice encrypts a message
    let plaintext = b"Hello, Bob! This is a secret message.";
    let ciphertext = engine.encrypt_message(&mut alice_state, plaintext)?;
    
    // Bob decrypts the message
    let decrypted = engine.decrypt_message(&mut bob_state, &ciphertext)?;
    
    // Verify the message matches
    assert_eq!(decrypted, plaintext.to_vec(), "Decrypted message should match original");
    
    Ok(())
}

/// Test bidirectional messaging: Both Alice and Bob can send/receive
#[test]
fn test_bidirectional_messaging() -> EngineResult<()> {
    let engine = MlsEngine::new()?;
    
    // Setup: Alice creates group, Bob joins
    let mut alice_state = engine.create_group(b"bidir-test", b"Alice")?;
    let bob_kp_data = engine.generate_key_package(b"Bob")?;
    let (welcome_bytes, _) = engine.add_member(&mut alice_state, &bob_kp_data.key_package_bytes)?;
    let mut bob_state = engine.process_welcome(&welcome_bytes, bob_kp_data)?;
    
    // Alice sends to Bob
    let msg1 = b"Message 1 from Alice";
    let ct1 = engine.encrypt_message(&mut alice_state, msg1)?;
    let pt1 = engine.decrypt_message(&mut bob_state, &ct1)?;
    assert_eq!(pt1, msg1.to_vec());
    
    // Bob sends to Alice
    let msg2 = b"Message 2 from Bob";
    let ct2 = engine.encrypt_message(&mut bob_state, msg2)?;
    let pt2 = engine.decrypt_message(&mut alice_state, &ct2)?;
    assert_eq!(pt2, msg2.to_vec());
    
    Ok(())
}

/// Test group state persistence (save/load)
#[test]
fn test_state_persistence() -> EngineResult<()> {
    let engine = MlsEngine::new()?;
    let temp_dir = tempdir().expect("Failed to create temp directory");
    let state_path = temp_dir.path().join("test_group.json");
    let state_path_str = state_path.to_str().unwrap();
    
    // Create a group
    let group_state = engine.create_group(b"persistence-test", b"Alice")?;
    let original_group_id = group_state.group_id_string();
    
    // Save state
    group_state.save(state_path_str)?;
    
    // Load state
    let loaded_state = GroupState::load(state_path_str)?;
    
    // Verify the loaded state matches
    assert_eq!(loaded_state.group_id_string(), original_group_id);
    
    Ok(())
}

/// Test adding multiple members sequentially
#[test]
fn test_add_multiple_members() -> EngineResult<()> {
    let engine = MlsEngine::new()?;
    
    // Alice creates a group
    let mut alice_state = engine.create_group(b"multi-member-test", b"Alice")?;
    assert_eq!(alice_state.epoch(), 0);
    
    // Add Bob
    let bob_kp_data = engine.generate_key_package(b"Bob")?;
    let (welcome_bob, _) = engine.add_member(&mut alice_state, &bob_kp_data.key_package_bytes)?;
    let _bob_state = engine.process_welcome(&welcome_bob, bob_kp_data)?;
    assert_eq!(alice_state.epoch(), 1);
    
    // Add Charlie
    let charlie_kp_data = engine.generate_key_package(b"Charlie")?;
    let (welcome_charlie, _) = engine.add_member(&mut alice_state, &charlie_kp_data.key_package_bytes)?;
    let _charlie_state = engine.process_welcome(&welcome_charlie, charlie_kp_data)?;
    assert_eq!(alice_state.epoch(), 2);
    
    Ok(())
}

// ============================================================================
// Phase 7: Welcome/Join Flow + State Versioning Tests
// ============================================================================

use mls_pqc_engine::engine::{KeyPackageData, SerializedKeyPackageData, CURRENT_SCHEMA_VERSION};

/// Test that KeyPackageData can be serialized and deserialized correctly
#[test]
fn test_serialized_key_package_data_roundtrip() -> EngineResult<()> {
    let temp_dir = tempdir().expect("Failed to create temp directory");
    let data_path = temp_dir.path().join("kp_data.json");
    let data_path_str = data_path.to_str().unwrap();
    
    let engine = MlsEngine::new()?;
    
    // Generate a key package
    let kp_data = engine.generate_key_package(b"TestMember")?;
    let original_suite = kp_data.suite;
    
    // Serialize
    let serialized = kp_data.to_serialized()?;
    assert_eq!(serialized.schema_version, CURRENT_SCHEMA_VERSION);
    
    // Save to file
    serialized.save(data_path_str)?;
    
    // Load from file
    let loaded = SerializedKeyPackageData::load(data_path_str)?;
    assert_eq!(loaded.schema_version, CURRENT_SCHEMA_VERSION);
    assert_eq!(loaded.suite, original_suite);
    
    // Reconstruct KeyPackageData
    let reconstructed = KeyPackageData::from_serialized(loaded)?;
    assert_eq!(reconstructed.suite, original_suite);
    
    Ok(())
}

/// Test that join group works correctly using serialized KeyPackageData
/// 
/// NOTE: Due to OpenMLS storing key package private keys in the provider's storage,
/// the serialized data can only be used within the SAME process/provider instance.
/// For a true cross-process CLI flow, a persistent storage provider would be needed.
/// 
/// This test verifies the serialization/deserialization machinery works correctly
/// by simulating the in-memory scenario where the original provider is still available.
#[test]
fn test_join_group_with_serialized_data() -> EngineResult<()> {
    let temp_dir = tempdir().expect("Failed to create temp directory");
    let data_path = temp_dir.path().join("bob_kp_data.json");
    let data_path_str = data_path.to_str().unwrap();
    
    let engine = MlsEngine::new()?;
    
    // Alice creates a group
    let mut alice_state = engine.create_group(b"serialized-join-test", b"Alice")?;
    
    // Bob generates a key package
    let bob_kp_data = engine.generate_key_package(b"Bob")?;
    let kp_bytes = bob_kp_data.key_package_bytes.clone();
    
    // Serialize Bob's KeyPackageData (simulating CLI save)
    let serialized = bob_kp_data.to_serialized()?;
    serialized.save(data_path_str)?;
    
    // Verify serialized data can be loaded and has correct values
    let loaded = SerializedKeyPackageData::load(data_path_str)?;
    assert_eq!(loaded.schema_version, CURRENT_SCHEMA_VERSION);
    assert_eq!(loaded.suite, bob_kp_data.suite);
    
    // Alice adds Bob using key package bytes
    let (welcome_bytes, _commit) = engine.add_member(&mut alice_state, &kp_bytes)?;
    
    // Bob joins using the ORIGINAL KeyPackageData (provider has the private keys)
    // In a real CLI scenario, this would need persistent storage
    let mut bob_state = engine.process_welcome(&welcome_bytes, bob_kp_data)?;
    
    // Verify convergence
    assert_eq!(alice_state.epoch(), 1);
    assert_eq!(bob_state.epoch(), 1);
    
    // Verify messaging works
    let msg = b"Hello from Alice to Bob!";
    let ct = engine.encrypt_message(&mut alice_state, msg)?;
    let pt = engine.decrypt_message(&mut bob_state, &ct)?;
    assert_eq!(pt, msg.to_vec());
    
    Ok(()
    )
}

/// Test that saved state files contain schema_version field
#[test]
fn test_state_schema_version_present() -> EngineResult<()> {
    let temp_dir = tempdir().expect("Failed to create temp directory");
    let state_path = temp_dir.path().join("version_test.json");
    let state_path_str = state_path.to_str().unwrap();
    
    let engine = MlsEngine::new()?;
    
    // Create and save a group
    let group_state = engine.create_group(b"version-test", b"Alice")?;
    group_state.save(state_path_str)?;
    
    // Read the JSON file directly to verify schema_version
    use std::fs::File;
    use std::io::BufReader;
    let file = File::open(state_path_str).expect("Failed to open state file");
    let reader = BufReader::new(file);
    let json: serde_json::Value = serde_json::from_reader(reader).expect("Failed to parse JSON");
    
    // Verify schema_version field exists and equals current version
    let version = json.get("schema_version")
        .expect("schema_version field missing")
        .as_u64()
        .expect("schema_version should be a number");
    
    assert_eq!(version as u32, CURRENT_SCHEMA_VERSION);
    
    // Verify state can be loaded
    let loaded = GroupState::load(state_path_str)?;
    assert_eq!(loaded.group_id_string(), "version-test");
    
    Ok(())
}

