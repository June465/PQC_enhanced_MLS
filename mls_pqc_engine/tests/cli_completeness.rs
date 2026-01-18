//! CLI completeness tests for Phase 10
//!
//! These tests verify the new member lookup and removal functionality.

use mls_pqc_engine::engine::{MlsEngine, CryptoSuite};
use mls_pqc_engine::error::EngineResult;

// =============================================================================
// Member Lookup Tests
// =============================================================================

/// Test listing members in a group
#[test]
fn test_list_members_format() -> EngineResult<()> {
    let engine = MlsEngine::new()?;
    
    // Alice creates group
    let mut alice_state = engine.create_group(b"list-members-test", b"Alice")?;
    assert_eq!(alice_state.list_members().len(), 1);
    assert_eq!(alice_state.list_members()[0].identity, "Alice");
    assert_eq!(alice_state.list_members()[0].leaf_index, 0);
    
    // Add Bob
    let bob_kp_data = engine.generate_key_package(b"Bob")?;
    let (welcome_bob, _) = engine.add_member(&mut alice_state, &bob_kp_data.key_package_bytes)?;
    
    // Alice's view should show 2 members
    let alice_members = alice_state.list_members();
    assert_eq!(alice_members.len(), 2);
    assert_eq!(alice_members[0].identity, "Alice");
    assert_eq!(alice_members[0].leaf_index, 0);
    assert_eq!(alice_members[1].identity, "Bob");
    assert_eq!(alice_members[1].leaf_index, 1);
    
    // Add Charlie
    let charlie_kp_data = engine.generate_key_package(b"Charlie")?;
    let (_, _) = engine.add_member(&mut alice_state, &charlie_kp_data.key_package_bytes)?;
    
    // Alice's view should now show 3 members
    let alice_members = alice_state.list_members();
    assert_eq!(alice_members.len(), 3);
    assert_eq!(alice_members[2].identity, "Charlie");
    assert_eq!(alice_members[2].leaf_index, 2);
    
    Ok(())
}

/// Test finding a member by identity
#[test]
fn test_find_member_by_identity() -> EngineResult<()> {
    let engine = MlsEngine::new()?;
    
    // Alice creates group
    let mut alice_state = engine.create_group(b"find-member-test", b"Alice")?;
    
    // Add Bob and Charlie
    let bob_kp_data = engine.generate_key_package(b"Bob")?;
    let (_, _) = engine.add_member(&mut alice_state, &bob_kp_data.key_package_bytes)?;
    
    let charlie_kp_data = engine.generate_key_package(b"Charlie")?;
    let (_, _) = engine.add_member(&mut alice_state, &charlie_kp_data.key_package_bytes)?;
    
    // Test find_member for each member
    assert_eq!(alice_state.find_member("Alice"), Some(0));
    assert_eq!(alice_state.find_member("Bob"), Some(1));
    assert_eq!(alice_state.find_member("Charlie"), Some(2));
    
    Ok(())
}

/// Test that finding a non-existent member returns None
#[test]
fn test_find_nonexistent_member_returns_none() -> EngineResult<()> {
    let engine = MlsEngine::new()?;
    
    // Alice creates group with Bob
    let mut alice_state = engine.create_group(b"find-none-test", b"Alice")?;
    let bob_kp_data = engine.generate_key_package(b"Bob")?;
    let (_, _) = engine.add_member(&mut alice_state, &bob_kp_data.key_package_bytes)?;
    
    // Try to find Mallory who was never added
    assert_eq!(alice_state.find_member("Mallory"), None);
    assert_eq!(alice_state.find_member("Dave"), None);
    assert_eq!(alice_state.find_member(""), None);
    
    Ok(())
}

// =============================================================================
// Remove Member By Identity Tests  
// =============================================================================

/// Test removing a member by identity using find_member + remove_member
#[test]
fn test_remove_member_by_identity() -> EngineResult<()> {
    let engine = MlsEngine::new()?;
    
    // Create group with Alice, Bob, Charlie
    let mut alice_state = engine.create_group(b"remove-by-id-test", b"Alice")?;
    
    let bob_kp_data = engine.generate_key_package(b"Bob")?;
    let (_, _) = engine.add_member(&mut alice_state, &bob_kp_data.key_package_bytes)?;
    
    let charlie_kp_data = engine.generate_key_package(b"Charlie")?;
    let (_, _) = engine.add_member(&mut alice_state, &charlie_kp_data.key_package_bytes)?;
    
    assert_eq!(alice_state.list_members().len(), 3);
    let epoch_before = alice_state.epoch();
    
    // Find Bob's leaf index
    let bob_leaf_index = alice_state.find_member("Bob").expect("Bob should exist");
    assert_eq!(bob_leaf_index, 1);
    
    // Remove Bob
    let _commit = engine.remove_member(&mut alice_state, bob_leaf_index)?;
    
    // Verify removal
    assert_eq!(alice_state.epoch(), epoch_before + 1, "Epoch should advance after removal");
    assert_eq!(alice_state.list_members().len(), 2, "Should have 2 members after removal");
    
    // Verify Bob is gone
    assert_eq!(alice_state.find_member("Bob"), None, "Bob should no longer be found");
    
    // Verify Alice and Charlie still exist
    assert!(alice_state.find_member("Alice").is_some(), "Alice should still exist");
    assert!(alice_state.find_member("Charlie").is_some(), "Charlie should still exist");
    
    Ok(())
}

/// Test full lifecycle with removal - verifies forward secrecy still works
#[test]
fn test_full_lifecycle_with_removal() -> EngineResult<()> {
    let engine = MlsEngine::new()?;
    
    // Step 1: Alice creates group
    let mut alice_state = engine.create_group(b"lifecycle-removal-test", b"Alice")?;
    
    // Step 2: Add Bob
    let bob_kp_data = engine.generate_key_package(b"Bob")?;
    let (welcome_bob, _) = engine.add_member(&mut alice_state, &bob_kp_data.key_package_bytes)?;
    let mut bob_state = engine.process_welcome(&welcome_bob, bob_kp_data)?;
    
    // Step 3: Add Charlie
    let charlie_kp_data = engine.generate_key_package(b"Charlie")?;
    let (welcome_charlie, commit_charlie) = engine.add_member(&mut alice_state, &charlie_kp_data.key_package_bytes)?;
    let mut charlie_state = engine.process_welcome(&welcome_charlie, charlie_kp_data)?;
    
    // Bob syncs to epoch 2
    engine.process_commit(&mut bob_state, &commit_charlie)?;
    
    // Step 4: Alice and Bob communicate
    let msg1 = b"Hello Bob!";
    let ct1 = engine.encrypt_message(&mut alice_state, msg1)?;
    let pt1 = engine.decrypt_message(&mut bob_state, &ct1)?;
    assert_eq!(pt1, msg1.to_vec());
    
    // Step 5: Find and remove Bob by identity
    let bob_leaf = alice_state.find_member("Bob").expect("Bob should exist");
    let remove_commit = engine.remove_member(&mut alice_state, bob_leaf)?;
    
    // Charlie syncs removal
    engine.process_commit(&mut charlie_state, &remove_commit)?;
    
    // Step 6: Bob is NOT synced and tries to decrypt new messages - should fail (forward secrecy)
    let msg2 = b"Secret after Bob removed";
    let ct2 = engine.encrypt_message(&mut alice_state, msg2)?;
    
    // Bob at old epoch cannot decrypt
    let bob_result = engine.decrypt_message(&mut bob_state, &ct2);
    assert!(bob_result.is_err(), "Bob should not decrypt after removal (forward secrecy)");
    
    // Charlie can decrypt
    let pt2 = engine.decrypt_message(&mut charlie_state, &ct2)?;
    assert_eq!(pt2, msg2.to_vec());
    
    Ok(())
}

// =============================================================================
// Export State Tests
// =============================================================================

/// Test that export-related methods work correctly
#[test]
fn test_export_state_contains_expected_fields() -> EngineResult<()> {
    let engine = MlsEngine::new()?;
    
    // Create group with Hybrid suite
    let mut alice_state = engine.create_group_with_suite(
        b"export-test",
        b"Alice",
        CryptoSuite::HybridKem,
    )?;
    
    // Add Bob
    let bob_kp_data = engine.generate_key_package_with_suite(b"Bob", CryptoSuite::HybridKem)?;
    let (_, _) = engine.add_member(&mut alice_state, &bob_kp_data.key_package_bytes)?;
    
    // Verify all fields needed for export are accessible
    assert_eq!(alice_state.group_id_string(), "export-test");
    assert_eq!(alice_state.suite, CryptoSuite::HybridKem);
    assert_eq!(alice_state.epoch(), 1);
    
    let members = alice_state.list_members();
    assert_eq!(members.len(), 2);
    assert_eq!(members[0].identity, "Alice");
    assert_eq!(members[1].identity, "Bob");
    
    Ok(())
}
