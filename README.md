# PQC-Enhanced MLS Engine

A Post-Quantum Cryptography (PQC) enhanced implementation of the Messaging Layer Security (MLS) protocol in Rust.

## Overview

This project provides a secure group messaging engine with support for:
- **Classic MLS** - Standard X25519/Ed25519 cryptography
- **PQC KEM** - Post-quantum security using ML-KEM 768 (FIPS 203)
- **Hybrid KEM** - Defense-in-depth combining X25519 + ML-KEM 768

## Project Status

✅ **All Phases Complete** - The project is feature-complete with comprehensive test coverage.

| Phase | Description | Status |
|-------|-------------|--------|
| Phase 0 | Project Scaffolding | ✅ Done |
| Phase 1 | Baseline Engine (Classic MLS) | ✅ Done |
| Phase 2 | Correctness Tests | ✅ Done |
| Phase 3 | PQC Primitives (ML-KEM 768) | ✅ Done |
| Phase 4 | Hybrid KEM (X25519 + ML-KEM) | ✅ Done |
| Phase 5 | PQC/Hybrid Integration | ✅ Done |
| Phase 6 | Security Tests | ✅ Done |

**Test Coverage:** 57 tests covering correctness, negative cases, PQC integration, and security properties.


## Project Structure

```
PQC_enhanced_MLS/
├── mls_pqc_engine/     # Core engine library
│   ├── src/
│   │   ├── engine/     # MLS operations, state, suite
│   │   ├── provider/   # PQC/Hybrid KEM providers
│   │   └── error.rs    # Error types
│   └── tests/          # Integration tests
├── mls_pqc_cli/        # Command-line interface
└── phases/             # Implementation documentation
```

## Building

```powershell
# Build entire workspace
cargo build --workspace

# Run tests
cargo test --workspace
```

## CLI Usage

### Cryptographic Suites

The `--suite` flag selects the cryptographic suite:

| Suite | Description | Security Level |
|-------|-------------|----------------|
| `classic` | Standard X25519/Ed25519 | Classical |
| `pqc-kem` | ML-KEM 768 only | Post-Quantum |
| `hybrid-kem` | X25519 + ML-KEM 768 | Defense-in-Depth |

### Commands

#### Create a New Group

```powershell
# Classic suite (default)
cargo run -p mls_pqc_cli -- init-group -g "my-group" -m "Alice"

# With PQC suite
cargo run -p mls_pqc_cli -- --suite pqc-kem init-group -g "quantum-secure" -m "Alice"

# With Hybrid suite
cargo run -p mls_pqc_cli -- --suite hybrid-kem init-group -g "hybrid-secure" -m "Alice"
```

**Output:**
```json
{"command":"init-group","status":"success","suite":"pqc_kem","group_id":"quantum-secure","message":"Group created by Alice with Post-Quantum KEM (ML-KEM 768) suite"}
```

#### Generate Key Package

```powershell
# Generate key package for a new member
cargo run -p mls_pqc_cli -- key-package -m "Bob" -o bob_kp.bin
```

#### Add Member to Group

```powershell
# Add member using their key package
cargo run -p mls_pqc_cli -- add-member -g "my-group" -k bob_kp.bin
```

#### Encrypt Message

```powershell
# Encrypt a message for the group
cargo run -p mls_pqc_cli -- encrypt -g "my-group" -p "Hello, secure world!"
```

**Output:**
```json
{"command":"encrypt","status":"success","suite":"pqc_kem","group_id":"my-group","result_data":"<base64-encoded-ciphertext>"}
```

#### Decrypt Message

```powershell
# Decrypt received ciphertext
cargo run -p mls_pqc_cli -- decrypt -g "my-group" -c "<base64-ciphertext>"
```

### Global Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--suite` | `-s` | Crypto suite | `classic` |
| `--state-dir` | `-d` | State directory | `.mls_state` |
| `--output-format` | `-o` | Output format | `jsonl` |

### Complete Workflow Example: Secure Team Communication

This example demonstrates a complete secure group communication workflow using the Hybrid KEM suite (X25519 + ML-KEM 768) for defense-in-depth security.

#### Scenario
Alice wants to create a quantum-resistant secure group and add Bob. They will then exchange encrypted messages.

```powershell
# ============================================
# STEP 1: Alice creates a quantum-resistant group
# ============================================
# The --suite hybrid-kem flag enables X25519 + ML-KEM 768 protection
# This provides security against both classical and quantum attacks

cargo run -p mls_pqc_cli -- --suite hybrid-kem init-group -g "project-alpha" -m "Alice"

# Output:
# {"command":"init-group","status":"success","suite":"hybrid_kem","group_id":"project-alpha",
#  "message":"Group created by Alice with Hybrid KEM (X25519 + ML-KEM 768) suite"}

# ============================================
# STEP 2: Bob generates his key package
# ============================================
# A key package contains Bob's public keys for joining groups
# This is saved to a file that Alice will use to add him

cargo run -p mls_pqc_cli -- --suite hybrid-kem key-package -m "Bob" -o bob_keypackage.bin

# Output:
# {"command":"key-package","status":"success","suite":"hybrid_kem","member_id":"Bob"}
# Key package saved to: bob_keypackage.bin

# ============================================
# STEP 3: Alice adds Bob to the group
# ============================================
# Alice imports Bob's key package and adds him to the group
# This generates a Welcome message for Bob and updates the group epoch

cargo run -p mls_pqc_cli -- add-member -g "project-alpha" -k bob_keypackage.bin

# Output:
# {"command":"add-member","status":"success","suite":"hybrid_kem","group_id":"project-alpha",
#  "message":"Member added successfully. Welcome saved."}

# ============================================
# STEP 4: Alice sends an encrypted message
# ============================================
# The message is encrypted using the group's current keys
# Only current group members can decrypt it

cargo run -p mls_pqc_cli -- encrypt -g "project-alpha" -p "Meeting at 3pm in the secure room"

# Output:
# {"command":"encrypt","status":"success","suite":"hybrid_kem","group_id":"project-alpha",
#  "result_data":"<base64-encoded-ciphertext>"}

# ============================================
# STEP 5: Bob decrypts the message
# ============================================
# Bob uses his group state to decrypt the ciphertext
# Replace <ciphertext> with the actual base64 data from Step 4

cargo run -p mls_pqc_cli -- decrypt -g "project-alpha" -c "<base64-ciphertext>"

# Output:
# {"command":"decrypt","status":"success","suite":"hybrid_kem","group_id":"project-alpha",
#  "message":"Meeting at 3pm in the secure room"}
```

#### Understanding the Workflow

| Step | What Happens | Security Property |
|------|--------------|-------------------|
| 1. Init Group | Creates MlsGroup, generates identity keys | Group isolation |
| 2. Key Package | Pre-key bundle for async group joining | Forward secrecy setup |
| 3. Add Member | Commit + Welcome message generated | Authenticated membership |
| 4. Encrypt | Application message encrypted with epoch key | Confidentiality + Authenticity |
| 5. Decrypt | Epoch key used to decrypt and verify sender | Message integrity |

#### Suite Comparison Example

```powershell
# Classic (standard security - vulnerable to quantum attacks)
cargo run -p mls_pqc_cli -- init-group -g "classic-group" -m "Alice"

# PQC-only (quantum-resistant but no classical fallback)
cargo run -p mls_pqc_cli -- --suite pqc-kem init-group -g "pqc-group" -m "Alice"

# Hybrid (recommended - defense-in-depth)
cargo run -p mls_pqc_cli -- --suite hybrid-kem init-group -g "hybrid-group" -m "Alice"
```


## Key Sizes

| Component | PQC (ML-KEM 768) | Hybrid |
|-----------|------------------|--------|
| Public Key | 1,184 bytes | 1,216 bytes |
| Private Key | 2,400 bytes | 2,432 bytes |
| Ciphertext | 1,088 bytes | 1,120 bytes |
| Shared Secret | 32 bytes | 32 bytes |

## Security

- **ML-KEM 768**: NIST FIPS 203 compliant, providing ~192-bit quantum security
- **Hybrid Mode**: Combines classical and PQC for defense-in-depth
- **Key Derivation**: HKDF-SHA256 for combining shared secrets

## License

See LICENSE file for details.
