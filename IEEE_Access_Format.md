# A Post-Quantum Cryptography Enhanced Messaging Layer Security (MLS) Protocol

**Abstract**— The advent of large-scale quantum computers poses a severe threat to classical public-key cryptography, which currently underpins secure communication protocols on the Internet. The Messaging Layer Security (MLS) protocol was recently standardized by the IETF for secure group messaging, providing features such as forward secrecy and post-compromise security. However, classical MLS relies on algorithms like X25519 that are vulnerable to Shor's algorithm. This paper presents a Post-Quantum Cryptography (PQC) enhanced implementation of the MLS engine in Rust. We integrate the ML-KEM 768 (FIPS 203) Key Encapsulation Mechanism alongside standard X25519/Ed25519 implementations to create a secure group messaging engine. We support Classic MLS, PQC-only KEM, and a Hybrid KEM mode for defense-in-depth. We additionally present a quantum threat simulation using Qiskit to contextualize the vulnerability of classical schemes. Finally, we provide performance benchmarks detailing computation times and storage overheads of the quantum-resistant suites compared to classical configurations.

**Index Terms**— Post-Quantum Cryptography, Messaging Layer Security, ML-KEM, Quantum Threat, Cryptography Benchmarking.

---

## I. Introduction

Secure group messaging has become an essential component of modern digital communications, motivating the development of the Messaging Layer Security (MLS) protocol. MLS [1] is designed to provide efficient and secure communications for dynamic groups, offering security guarantees such as Forward Secrecy and Post-Compromise Security. It achieves these properties efficiently through a structure called asynchronous ratcheting trees (ART) and treeKEM. However, MLS traditionally relies on classical public-key cryptographic primitives, particularly elliptic curve Diffie-Hellman protocols like X25519 for key exchange and Ed25519 for signatures.

With the rapid advancement in quantum computing, specifically the potential realization of a cryptographically relevant quantum computer (CRQC), these classical algorithms are at risk. Shor's algorithm [2] can break discrete-logarithm and integer-factorization-based cryptography in polynomial time, rendering current internet communications liable to "harvest now, decrypt later" attacks. 

In this paper, we address this vulnerability by introducing a Post-Quantum Cryptography (PQC) enhanced MLS engine. We leverage ML-KEM-768, standardized under NIST FIPS 203 [3], to construct a quantum-resistant key encapsulation mechanism (KEM). To maintain compliance and provide defense-in-depth, we also introduce a hybrid key exchange mechanism combining classical X25519 with ML-KEM. The project is implemented in Rust, maximizing memory safety and execution speed.

The remainder of this paper is structured as follows: Section II discusses the background and related work. Section III details the system architecture and our PQC enhancements. Section IV describes our quantum threat simulation framework. Section V analyzes our experimental performance outcomes. Finally, Section VI concludes the paper.

---

## II. Background

### A. The MLS Protocol
The Messaging Layer Security (MLS) protocol standardizes end-to-end encryption for continuous group messaging. Its core innovation resides in the utilization of TreeKEM, enabling group operations (such as member additions and removals) scaling logarithmically $O(\log n)$ rather than linearly with the group size $n$. This solves the bottleneck encountered in pairwise continuous key agreement protocols like the Signal protocol when scaled to large groups.

### B. Post-Quantum Cryptography (PQC)
In response to the quantum threat, the National Institute of Standards and Technology (NIST) initiated a normalization process for post-quantum cryptographic primitives. ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism), originally submitted as CRYSTALS-Kyber, was formally published as FIPS 203. It relies on the hardness of the Module Learning with Errors (M-LWE) problem. ML-KEM 768 is targeted at security level III, equivalent to AES-192, and has been deemed the standard choice for general-purpose encryption applications.

---

## III. System Architecture and Implementation

Our engine is engineered as a secure group messaging core in Rust (`mls_pqc_engine`) accompanied by a fully-featured command-line interface (`mls_pqc_cli`). 

### A. Cryptographic Suites Supported
We introduced a configurable provider model that allows operators to swap cryptographic suites at runtime. The engine natively supports three security paradigms:
1. **Classic Suite**: Relies entirely on classical primitives (X25519 key encapsulation and Ed25519 signatures).
2. **PQC KEM Suite**: Swaps the classical KEM for ML-KEM-768 for strict post-quantum security in key encapsulation.
3. **Hybrid KEM Suite**: Combines the output of X25519 and ML-KEM-768 using a secure Key Derivation Function (HKDF-SHA256). This provides a defense-in-depth approach where the shared secret remains secure as long as either the classical or the post-quantum scheme is unbroken. 

*Note*: As the current primary threat is "harvest now, decrypt later," we prioritized replacing the KEM. Continuous authentication properties rely on Ed25519 signatures; integrating ML-DSA (FIPS 204) is planned for future phases.

### B. Group State and Artifact Management
The protocol necessitates robust, persistent state tracking. Group metadata, cryptographic ratchets, and member identities are seamlessly serialized to persistent storage formats (`JSON` for declarative data, `bin` for artifacts). The system enforces strict forward secrecy during operations such as `remove-member`, guaranteeing that evicted entities mathematically cannot decrypt future ciphertexts. 

Operations handled by the engine include:
- `init-group`: Root creation of the `MlsGroup`.
- `key-package`: Generation of pre-key bundles for asynchronous joins.
- `add-member` / `join-group`: Inclusion of members via `Welcome` messages and consensus validation.
- `encrypt` / `decrypt`: Generation and reading of ciphertexts verified by epoch keys.

---

## IV. Quantum Threat Showcase

To contextualize the necessity of these PQC additions, our framework includes a localized quantum risk simulator utilizing Qiskit. This module theoretically and practically isolates the threat model:

1. **Simulation of Shor's Algorithm**: Utilizing local `qiskit-aer` or live IBM Quantum Hardware (via QPU API tokens), we simulate Shor's algorithm on smaller integers to showcase factorization periodicity finding.
2. **Impact Visualization**: By calculating theoretical attack complexities, the module outputs comparative visual data contrasting the exponentially diminishing time-to-decay of classical elliptic curves against lattice-based methods. This grounds the PQC MLS implementation within verifiable quantum vulnerability bounds.

---

## V. Evaluation and Benchmarking

We conducted extensive automated benchmarks to quantify the impacts of transitioning from Classical MLS to our PQC and Hybrid models. Our continuous integration workflow utilizes JSONL logs to aggregate and plot timing and size data across epochs.

### A. Storage Overheads
The transition to lattice-based cryptography introduces significant changes to key material payload sizes, which affects network bandwidth requirements.
* **Classic**: Negligible public/private key sizes (32 bytes).
* **ML-KEM 768**: Public key requires 1,184 bytes; private key requires 2,400 bytes. Ciphertexts expand to 1,088 bytes.
* **Hybrid**: Combines both primitives resulting in 1,216 bytes for public keys and 2,432 bytes for private keys, with a combined ciphertext size of 1,120 bytes.
Despite proportional increases, these sizes fit efficiently within standard MTU constraints, avoiding severe fragmentation in standard messaging payload routing.

### B. Computation Overheads
Timing evaluations reflect the execution durations for key encapsulation during group initialization, message encryption, and decryption endpoints. Thanks to the highly optimized execution bounds of ML-KEM, the symmetric matrix operations introduce remarkably low processing latencies despite generating larger payloads. The `Hybrid KEM` suite demonstrates trivial overhead beyond the baseline classical times, proving it practically viable for mobile and constrained environments.

---

## VI. Conclusion

Migrating secure communication protocols to a quantum-resistant foundation is a mandatory engineering challenge for long-term data security. In this study, we outlined the design, integration, and evaluation of a Post-Quantum Cryptography-enhanced Messaging Layer Security protocol. By natively accommodating a Hybrid KEM architecture composed of X25519 and ML-KEM-768, our implementation provides necessary defense-in-depth guarantees against adversarial quantum hardware capabilities without severely degrading computational performance. Future extensions will incorporate ML-DSA to achieve complete post-quantum authentication across the lifecycle of the MLS session.

---

## References
[1] R. Barnes, B. Beurdouche, J. Millican, E. Omara, K. Cohn-Gordon, and R. Robert, "The Messaging Layer Security (MLS) Protocol," RFC 9420, IETF, July 2023.
[2] P. W. Shor, "Algorithms for quantum computation: discrete logarithms and factoring," *Proceedings 35th Annual Symposium on Foundations of Computer Science*, IEEE, 1994, pp. 124-134.
[3] National Institute of Standards and Technology (NIST), "Module-Lattice-Based Key-Encapsulation Mechanism Standard," FIPS PUB 203, August 2024.
