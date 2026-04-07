# Quantum Showcase for PQC-Enhanced MLS

This directory contains an executable research showcase that highlights the cryptographic necessity of transitioning to PQC-Enhanced Message Layer Security (MLS).

## The Qiskit Threat Demonstration
The Python script `run_showcase.py` utilizes **IBM Qiskit** to construct and simulate the period-finding portion of **Shor's Algorithm**.
Shor's algorithm famously provides an exponential speedup in integer factorization, which allows a sufficiently powerful quantum computer to easily break widely deployed classical public-key cryptography, such as RSA and Elliptic Curve Cryptography (ECC).

Running this script connects to IBM Quantum Resources (or an AerSimulator) and generates measure counts for evaluating period `r`. With `r`, classical primes are extracted. This demonstration serves as the theoretical and practical foundation proving why purely classical MLS relies on fundamentally threatened techniques.

---

## Transitional Timeline Strategy: Hybrid > PQC > Modern

PQC (Post-Quantum Cryptography) algorithms—such as NIST's selected Kyber for Key Encapsulation and Dilithium for Digital Signatures—offer structural resistance to Shor's algorithm. 
However, deploying PQC directly creates temporary systemic risks during transitioning phases. Therefore, the implementation methodology within this project recognizes the optimal roadmap:

### 1. Modern (Classical) - *Present Status Quo*
- Algorithms like ECDH, ECDSA, and standard RSA.
- **Vulnerability:** Unconditionally broken by a Cryptographically Relevant Quantum Computer (CRQC). The `run_showcase.py` explicitly proves the mathematical breakdown.
- **Risk:** "Store-Now-Decrypt-Later" attacks.

### 2. PQC - *The Desired Future*
- Purely lattice-based or hash-based cryptography.
- **Vulnerability:** Being mathematically novel, newer algorithms could potentially suffer from undiscovered *classical* cryptanalysis vulnerabilities or subtle implementation attacks.
- **Risk:** Placing all trust in purely PQC parameters might expose early adopters to zero-day mathematical attacks.

### 3. Hybrid Encryption - *The Ideal Transition Strategy*
- Computes both classical (e.g. ECDH) and PQC (e.g. Kyber) components simultaneously, binding and combining their shared secrets (often via a dual-KEM approach).
- **Security Guarantee:** The system remains completely secure as long as *at least one* of the underlying schemes remains unbroken. If a quantum computer arises, the PQC layer holds. If a flaw is found in Kyber, the classical layer holds.
- **Why it's better for MLS:** Message Layer Security governs continuous operational continuity in messaging channels. Dropping classical encryption abruptly could jeopardize ongoing TreeKEM integrity. Through Hybrid parameters, PQC-Enhanced MLS provides immediate forward quantum secrecy while retaining proven legacy assurance.

---

### Executing the Showcase
1. To run on a quantum simulator effortlessly:
   ```bash
   # From bench/quantum_showcase/
   python run_showcase.py
   ```
2. To run on **Real IBM Quantum Hardware**:
   - Create an IBM Quantum account at [https://quantum.ibm.com/](https://quantum.ibm.com/)
   - Extract your API Token.
   - Run the following in Python to save it to your local environment:
     ```python
     from qiskit_ibm_runtime import QiskitRuntimeService
     QiskitRuntimeService.save_account(channel='ibm_quantum_platform', token='YOUR_TOKEN_HERE')
     ```
   - Run `python run_showcase.py` again. Ensure you have the patience to wait for the cloud quantum queue.
