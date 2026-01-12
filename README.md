# PQC-Enhanced MLS Engine

A Post-Quantum Cryptography (PQC) enhanced implementation of the Messaging Layer Security (MLS) protocol in Rust.

## Overview

This project provides a secure group messaging engine with support for:
- **Classic MLS** - Standard X25519/Ed25519 cryptography
- **PQC KEM** - Post-quantum security using ML-KEM 768 (FIPS 203)
- **Hybrid KEM** - Defense-in-depth combining X25519 + ML-KEM 768

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

### Full Example: Secure Group Communication

```powershell
# Step 1: Alice creates a group with hybrid security
cargo run -p mls_pqc_cli -- --suite hybrid-kem init-group -g "secure-team" -m "Alice"

# Step 2: Bob generates a key package
cargo run -p mls_pqc_cli -- key-package -m "Bob" -o bob.kp

# Step 3: Alice adds Bob to the group
cargo run -p mls_pqc_cli -- add-member -g "secure-team" -k bob.kp

# Step 4: Alice sends encrypted message
cargo run -p mls_pqc_cli -- encrypt -g "secure-team" -p "Project kickoff at 3pm"

# Step 5: Bob decrypts the message (from his perspective)
# Bob would need the welcome message and his own state to decrypt
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
