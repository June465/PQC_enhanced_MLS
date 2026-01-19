# PQC-Enhanced MLS Engine

A Post-Quantum Cryptography (PQC) enhanced implementation of the Messaging Layer Security (MLS) protocol in Rust.

## Overview

This project provides a secure group messaging engine with support for:
- **Classic MLS** - Standard X25519/Ed25519 cryptography
- **PQC KEM** - Post-quantum security using ML-KEM 768 (FIPS 203)
- **Hybrid KEM** - Defense-in-depth combining X25519 + ML-KEM 768

> [!IMPORTANT]
> **Current PQC Scope**: This implementation replaces KEM (key encapsulation) with post-quantum algorithms (ML-KEM 768). Signature schemes remain classical (Ed25519). ML-DSA signatures are planned for future iterations.

## Project Status

✅ **Phase 11 Complete** - Documentation Polish implemented.

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
| Phase 9 | Deterministic Artifact Persistence | ✅ Done |
| Phase 10 | CLI Completeness | ✅ Done |
| Phase 11 | Documentation Polish | ✅ Done |

**Test Coverage:** 82 tests covering correctness, negative cases, PQC integration, security properties, join flow, benchmark output, artifact persistence, and CLI completeness.


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

## State Directory Layout

The CLI stores all state and artifacts in `.mls_state/` (configurable via `--state-dir`):

```
.mls_state/
├── <group_id>.json              # Group state for creator
├── <group_id>_<member_id>.json  # Joined member state
├── <group_id>/
│   └── artifacts/
│       ├── welcome/
│       │   └── <ts>_<member>.bin    # Welcome messages
│       ├── commit/
│       │   └── <ts>_epoch<N>.bin    # Commit messages
│       └── ciphertext/
│           └── <ts>_<seq>.bin       # Encrypted messages
└── key_packages/
    ├── <member_id>.bin              # Public key package
    └── <member_id>_data.json        # Private key package data
```

When using `--run-id`, artifacts are isolated under `.mls_state/<run_id>/`.

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

### Command Reference

| Command | Description | Required Args | Optional Args |
|---------|-------------|---------------|---------------|
| `init-group` | Create new group | `-g`, `-m` | `--suite` |
| `key-package` | Generate key package | `-m`, `-o` | `--suite` |
| `add-member` | Add member to group | `-g`, `-k` | |
| `join-group` | Join via Welcome | `-g`, `-m`, `--welcome`, `--key-package-data` | |
| `encrypt` | Encrypt message | `-g`, `-p` | |
| `decrypt` | Decrypt message | `-g`, `-c` | |
| `remove-member` | Remove member | `-g`, `-m` | |
| `commit` | Commit proposals | `-g` | |
| `export-state` | Export group info | `-g` | `-o` |

### Global Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--suite` | `-s` | Crypto suite | `classic` |
| `--state-dir` | `-d` | State directory | `.mls_state` |
| `--output-format` | `-o` | Output format | `jsonl` |
| `--run-id` | | Experiment isolation ID | None |

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
cargo run -p mls_pqc_cli -- join-group -g "my-group" -m "Bob" --welcome .mls_state/my-group/artifacts/welcome/<timestamp>_bob_kp.bin --key-package-data bob_kp_data.json
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

#### Remove Member from Group

```powershell
# Remove a member by identity
cargo run -p mls_pqc_cli -- remove-member -g "my-group" -m "Bob"
```

**Output (JSONL):**
```json
{"schema_version":1,"ts_ms":1736930172000,"suite":"classic","op":"remove_member","group_id":"my-group","member_id":"Bob","group_size":1,"epoch_before":1,"epoch_after":2,"ok":true,"time_ms":25,"artifact_bytes":{"commit":456}}
```

> **Note:** The removed member can no longer decrypt messages sent after their removal (forward secrecy).

#### Export Group State

```powershell
# Export group state to stdout
cargo run -p mls_pqc_cli -- export-state -g "my-group"

# Export group state to file
cargo run -p mls_pqc_cli -- export-state -g "my-group" -o group_info.json
```

**Output (to stderr for stdout, JSONL to stdout):**
```json
{
  "schema_version": 1,
  "group_id": "my-group",
  "suite": "classic",
  "epoch": 2,
  "member_count": 2,
  "members": [
    {"leaf_index": 0, "identity": "Alice"},
    {"leaf_index": 2, "identity": "Charlie"}
  ],
  "exported_at_ms": 1736930173000
}
```

#### Commit Pending Proposals

```powershell
# Commit any pending proposals (validates current state)
cargo run -p mls_pqc_cli -- commit -g "my-group"
```

> **Note:** In our flow, `add-member` auto-commits, so this command primarily validates and re-saves the state.

---

## Complete Workflow Example

This example demonstrates a complete secure group communication workflow using the Hybrid KEM suite for defense-in-depth security, including member joining, bidirectional messaging, and member removal with forward secrecy.

### Scenario
Alice creates a quantum-resistant secure group, adds Bob, they exchange messages, then Alice removes Bob to demonstrate forward secrecy.

```powershell
# ============================================
# STEP 1: Alice creates a quantum-resistant group
# ============================================
cargo run -p mls_pqc_cli -- --suite hybrid-kem init-group -g "project-alpha" -m "Alice"

# Output: {"schema_version":1,"suite":"hybrid_kem","op":"init_group","group_id":"project-alpha",
#          "member_id":"Alice","group_size":1,"epoch_after":0,"ok":true,"time_ms":42}

# ============================================
# STEP 2: Bob generates his key package
# ============================================
cargo run -p mls_pqc_cli -- --suite hybrid-kem key-package -m "Bob" -o bob_keypackage.bin

# Creates: bob_keypackage.bin (public) and bob_keypackage_data.json (private)

# ============================================
# STEP 3: Alice adds Bob to the group
# ============================================
cargo run -p mls_pqc_cli -- add-member -g "project-alpha" -k bob_keypackage.bin

# Output: {"suite":"hybrid_kem","op":"add_member","epoch_before":0,"epoch_after":1,
#          "artifact_bytes":{"welcome":4500,"commit":890},...}

# ============================================
# STEP 4: Bob joins the group using the Welcome message
# ============================================
# Find the welcome file in artifacts directory
$welcome = Get-ChildItem .mls_state/project-alpha/artifacts/welcome/*.bin | Select-Object -First 1

cargo run -p mls_pqc_cli -- join-group -g "project-alpha" -m "Bob" --welcome $welcome.FullName --key-package-data bob_keypackage_data.json

# Output: {"suite":"hybrid_kem","op":"join_group","group_id":"project-alpha",
#          "member_id":"Bob","group_size":2,"epoch_after":1,"ok":true}

# ============================================
# STEP 5: Alice sends an encrypted message
# ============================================
cargo run -p mls_pqc_cli -- encrypt -g "project-alpha" -p "Meeting at 3pm in the secure room"

# Ciphertext output to stderr, JSONL metrics to stdout
# Save the ciphertext for Bob to decrypt

# ============================================
# STEP 6: Bob decrypts the message
# ============================================
# Use Bob's state file (project-alpha_Bob.json)
cargo run -p mls_pqc_cli -- -d .mls_state decrypt -g "project-alpha_Bob" -c "<base64-ciphertext>"

# Plaintext output to stderr: Meeting at 3pm in the secure room

# ============================================
# STEP 7: Alice removes Bob from the group
# ============================================
cargo run -p mls_pqc_cli -- remove-member -g "project-alpha" -m "Bob"

# Output: {"op":"remove_member","epoch_before":1,"epoch_after":2,"group_size":1,...}

# ============================================
# STEP 8: Forward Secrecy - Bob cannot decrypt new messages
# ============================================
# Alice sends a message after Bob's removal
cargo run -p mls_pqc_cli -- encrypt -g "project-alpha" -p "Secret post-removal message"

# Bob tries to decrypt with his old state (epoch 1) - FAILS
# This demonstrates forward secrecy: removed members cannot read future messages
```

### Understanding the Workflow

| Step | What Happens | Security Property |
|------|--------------|-------------------|
| 1. Init Group | Creates MlsGroup, generates identity keys | Group isolation |
| 2. Key Package | Pre-key bundle for async group joining | Forward secrecy setup |
| 3. Add Member | Commit + Welcome message generated | Authenticated membership |
| 4. Join Group | Process Welcome, sync to group epoch | Group consensus |
| 5. Encrypt | Application message encrypted with epoch key | Confidentiality + Authenticity |
| 6. Decrypt | Epoch key used to decrypt and verify sender | Message integrity |
| 7. Remove Member | Commit updates group, advances epoch | Revocation |
| 8. Forward Secrecy | Old epoch keys cannot decrypt new messages | Post-compromise security |

---

## Running Benchmarks

The CLI outputs JSONL with timing and size metrics suitable for benchmarking and research.

### Using Run IDs for Experiment Isolation

```powershell
# Run experiment with isolated state directory
cargo run -p mls_pqc_cli -- --run-id exp1 --suite hybrid-kem init-group -g grp1 -m Alice

# All artifacts stored under .mls_state/exp1/
```

### Collecting Metrics

```powershell
# Extract timing from operations
cargo run -p mls_pqc_cli -- encrypt -g grp1 -p "test" 2>$null | ConvertFrom-Json | Select-Object time_ms

# Compare suites
@("classic", "pqc-kem", "hybrid-kem") | ForEach-Object {
    cargo run -p mls_pqc_cli -- --run-id "bench_$_" --suite $_ init-group -g test -m Alice 2>$null
}
```

### Metrics Schema

| Field | Type | Description |
|-------|------|-------------|
| `schema_version` | u32 | Output schema version (currently 1) |
| `ts_ms` | u64 | Unix timestamp in milliseconds |
| `suite` | string | Crypto suite (classic, pqc_kem, hybrid_kem) |
| `op` | string | Operation name |
| `group_id` | string | Group identifier |
| `member_id` | string | Member identifier (when applicable) |
| `group_size` | u32 | Number of members in group |
| `epoch_before` | u64 | Epoch before operation |
| `epoch_after` | u64 | Epoch after operation |
| `ok` | bool | Operation success |
| `time_ms` | u64 | Operation duration in milliseconds |
| `bytes_in` | u64 | Input size in bytes |
| `bytes_out` | u64 | Output size in bytes |
| `artifact_bytes` | object | Size of generated artifacts |
| `err` | string | Error message (when ok=false) |

---

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
- **Forward Secrecy**: Removed members cannot decrypt messages sent after removal

## License

See LICENSE file for details.
