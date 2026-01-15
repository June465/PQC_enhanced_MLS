# PQC-Enhanced MLS Engine

A Post-Quantum Cryptography (PQC) enhanced implementation of the Messaging Layer Security (MLS) protocol in Rust.

## Overview

This project provides a secure group messaging engine with support for:
- **Classic MLS** - Standard X25519/Ed25519 cryptography
- **PQC KEM** - Post-quantum security using ML-KEM 768 (FIPS 203)
- **Hybrid KEM** - Defense-in-depth combining X25519 + ML-KEM 768

## Project Status

✅ **Phase 8 Complete** - Benchmark-ready JSONL metrics implemented.

| Phase | Description | Status |
|-------|-------------|--------|
| Phase 0 | Project Scaffolding | ✅ Done |
| Phase 1 | Baseline Engine (Classic MLS) | ✅ Done |
| Phase 2 | Correctness Tests | ✅ Done |
| Phase 3 | PQC Primitives (ML-KEM 768) | ✅ Done |
| Phase 4 | Hybrid KEM (X25519 + ML-KEM) | ✅ Done |
| Phase 5 | PQC/Hybrid Integration | ✅ Done |
| Phase 6 | Security Tests | ✅ Done |
| Phase 7 | Welcome/Join Flow + State Versioning | ✅ Done |
| Phase 8 | Benchmark-Ready JSONL Metrics | ✅ Done |
| Phase 9 | Deterministic Artifact Persistence | ⏳ Pending |
| Phase 10 | CLI Completeness | ⏳ Pending |
| Phase 11 | Documentation Polish | ⏳ Pending |

**Test Coverage:** 65 tests covering correctness, negative cases, PQC integration, security properties, join flow, and benchmark output.


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

**Output (JSONL):**
```json
{"schema_version":1,"ts_ms":1736930167000,"suite":"pqc_kem","op":"init_group","group_id":"quantum-secure","member_id":"Alice","group_size":1,"epoch_after":0,"ok":true,"time_ms":42}
```

#### Generate Key Package

```powershell
# Generate key package for a new member
cargo run -p mls_pqc_cli -- key-package -m "Bob" -o bob_kp.bin
```

**Output (JSONL):**
```json
{"schema_version":1,"ts_ms":1736930168000,"suite":"classic","op":"key_package","member_id":"Bob","ok":true,"time_ms":15,"artifact_bytes":{"key_package":625}}
```

> **Note:** This creates two files:
> - `bob_kp.bin` - The public key package (share with group creator)
> - `bob_kp_data.json` - Private data needed for `join-group` (keep secure)

#### Add Member to Group

```powershell
# Add member using their key package (generates Welcome message)
cargo run -p mls_pqc_cli -- add-member -g "my-group" -k bob_kp.bin
```

**Output (JSONL):**
```json
{"schema_version":1,"ts_ms":1736930169000,"suite":"classic","op":"add_member","group_id":"my-group","group_size":2,"epoch_before":0,"epoch_after":1,"ok":true,"time_ms":35,"bytes_in":625,"artifact_bytes":{"welcome":1234,"commit":567}}
```

#### Join Group (New Member)

```powershell
# Bob joins using Welcome message and his key package data
cargo run -p mls_pqc_cli -- join-group -g "my-group" -m "Bob" --welcome welcome.bin --key-package-data bob_kp_data.json
```

**Output (JSONL):**
```json
{"schema_version":1,"ts_ms":1736930170000,"suite":"classic","op":"join_group","group_id":"my-group","member_id":"Bob","group_size":2,"epoch_after":1,"ok":true,"time_ms":28,"bytes_in":1234}
```

#### Encrypt Message

```powershell
# Encrypt a message for the group
cargo run -p mls_pqc_cli -- encrypt -g "my-group" -p "Hello, secure world!"
```

**Output (JSONL):**
```json
{"schema_version":1,"ts_ms":1736930171000,"suite":"pqc_kem","op":"encrypt","group_id":"my-group","group_size":2,"epoch_before":1,"epoch_after":1,"ok":true,"time_ms":5,"bytes_in":20,"bytes_out":1280,"artifact_bytes":{"ciphertext":1280}}
```

> **Note:** The ciphertext is output to stderr while JSONL metrics go to stdout for easy parsing.

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

# Output (JSONL):
# {"schema_version":1,"ts_ms":1736930167000,"suite":"hybrid_kem","op":"init_group",
#  "group_id":"project-alpha","member_id":"Alice","group_size":1,"epoch_after":0,
#  "ok":true,"time_ms":42}

# ============================================
# STEP 2: Bob generates his key package
# ============================================
# A key package contains Bob's public keys for joining groups
# Creates bob_keypackage.bin (public) and bob_keypackage_data.json (private)

cargo run -p mls_pqc_cli -- --suite hybrid-kem key-package -m "Bob" -o bob_keypackage.bin

# Output (JSONL):
# {"schema_version":1,"ts_ms":1736930168000,"suite":"hybrid_kem","op":"key_package",
#  "member_id":"Bob","ok":true,"time_ms":15,"artifact_bytes":{"key_package":2100}}

# ============================================
# STEP 3: Alice adds Bob to the group
# ============================================
# Alice imports Bob's key package and adds him to the group
# This generates a Welcome message for Bob and updates the group epoch

cargo run -p mls_pqc_cli -- add-member -g "project-alpha" -k bob_keypackage.bin

# Output (JSONL):
# {"schema_version":1,"ts_ms":1736930169000,"suite":"hybrid_kem","op":"add_member",
#  "group_id":"project-alpha","group_size":2,"epoch_before":0,"epoch_after":1,
#  "ok":true,"time_ms":35,"bytes_in":2100,"artifact_bytes":{"welcome":4500,"commit":890}}

# ============================================
# STEP 4: Alice sends an encrypted message
# ============================================
# The message is encrypted using the group's current keys
# Only current group members can decrypt it

cargo run -p mls_pqc_cli -- encrypt -g "project-alpha" -p "Meeting at 3pm in the secure room"

# Ciphertext output to stderr: <base64-encoded-ciphertext>
# JSONL output to stdout:
# {"schema_version":1,"ts_ms":1736930170000,"suite":"hybrid_kem","op":"encrypt",
#  "group_id":"project-alpha","group_size":2,"epoch_before":1,"epoch_after":1,
#  "ok":true,"time_ms":5,"bytes_in":34,"bytes_out":1450,"artifact_bytes":{"ciphertext":1450}}

# ============================================
# STEP 5: Bob decrypts the message
# ============================================
# Bob uses his group state to decrypt the ciphertext
# Replace <ciphertext> with the actual base64 data from Step 4

cargo run -p mls_pqc_cli -- decrypt -g "project-alpha" -c "<base64-ciphertext>"

# Plaintext output to stderr: Meeting at 3pm in the secure room
# JSONL output to stdout:
# {"schema_version":1,"ts_ms":1736930171000,"suite":"hybrid_kem","op":"decrypt",
#  "group_id":"project-alpha","group_size":2,"epoch_before":1,"epoch_after":1,
#  "ok":true,"time_ms":3,"bytes_in":1450,"bytes_out":34}
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
