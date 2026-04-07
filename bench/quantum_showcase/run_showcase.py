import sys
import os

# Explicitly force console output to be UTF-8 compatible
sys.stdout.reconfigure(encoding='utf-8')

import numpy as np
from qiskit import QuantumCircuit, QuantumRegister, ClassicalRegister
from qiskit.transpiler.preset_passmanagers import generate_preset_pass_manager
from qiskit_ibm_runtime import QiskitRuntimeService, SamplerV2 as Sampler
from qiskit_aer import AerSimulator

def c_amod15(a, power):
    """Controlled multiplication by a mod 15"""
    if a not in [2, 4, 7, 8, 11, 13]:
        raise ValueError("'a' must be 2,4,7,8,11 or 13")
    U = QuantumCircuit(4)        
    for iteration in range(power):
        if a in [2,13]:
            U.swap(2,3)
            U.swap(1,2)
            U.swap(0,1)
        if a in [7, 8]:
            U.swap(0,1)
            U.swap(1,2)
            U.swap(2,3)
        if a in [4, 11]:
            U.swap(1,3)
            U.swap(0,2)
        if a in [7, 11, 13]:
            for q in range(4):
                U.x(q)
    U = U.to_gate()
    U.name = f"{a}^{power} mod 15"
    c_U = U.control()
    return c_U

def qft_dagger(n):
    """n-qubit QFTdagger the first n qubits in circuit"""
    qc = QuantumCircuit(n)
    for qubit in range(n//2):
        qc.swap(qubit, n-qubit-1)
    for j in range(n):
        for m in range(j):
            qc.cp(-np.pi/float(2**(j-m)), m, j)
        qc.h(j)
    qc.name = "QFT_dagger"
    return qc

def run_hardware_showcase(force_hardware=True):
    print("=== Starting PQC-Enhanced MLS Quantum Threat Showcase ===")
    print("This execution runs Shor's period-finding component on Qiskit.\n")
    
    n_count = 3  # number of counting qubits
    a = 7
    
    q_reg = QuantumRegister(n_count+4, 'q')
    c_reg = ClassicalRegister(n_count, 'meas')
    qc = QuantumCircuit(q_reg, c_reg)
    
    # Initialize counting qubits
    for q in range(n_count):
        qc.h(q)
        
    # Auxiliary register in state |1>
    qc.x(n_count)
    
    # Apply controlled unitaries
    for q in range(n_count):
        # We append the c_U to counting qubit q and target the 4 auxiliary qubits
        qc.append(c_amod15(a, 2**q), [q] + [i+n_count for i in range(4)])
        
    # Apply inverse QFT
    qc.append(qft_dagger(n_count), range(n_count))
    
    # Measure
    qc.measure(range(n_count), range(n_count))
    
    print("Circuit constructed successfully!")
    print(qc.draw(output='text'))
    
    backend = None
    # Authentication Check
    try:
        print("\nAttempting to connect to IBM Quantum hardware...")
        # Will fail if token isn't saved or in QISKIT_IBM_TOKEN env var
        service = QiskitRuntimeService()
        if force_hardware:
            try:
                backend = service.least_busy(operational=True, simulator=False, min_num_qubits=7)
                print(f"Targeting real IBM Quantum Backend: {backend.name}")
            except Exception as e_backend:
                print(f"[ERROR] Could not find a real backend: {e_backend}")
                print("Falling back to IBM cloud simulator...")
                backend = service.get_backend('ibmq_qasm_simulator')
        else:
            backend = AerSimulator()
            
    except Exception as e:
        print("\n[WARNING] Could not load IBM Quantum account. Defaulting to local Aer Simulator.")
        print(f"Details: {e}")
        print("\nTo run on real hardware: \n 1. Get your API token from https://quantum.ibm.com/ \n 2. Run the following python code once:")
        print("    from qiskit_ibm_runtime import QiskitRuntimeService")
        print("    QiskitRuntimeService.save_account(channel='ibm_quantum_platform', token='<YOUR_TOKEN>')")
        print(" 3. Run this script again.")
        backend = AerSimulator()
        
    # Transpile the circuit
    print("\nTranspiling circuit for backend optimization...")
    pm = generate_preset_pass_manager(backend=backend, optimization_level=1)
    isa_circuit = pm.run(qc)
    
    print("Transpilation [OK]. Running sampling...")
    
    # Sampler Setup
    sampler = Sampler(mode=backend)
    
    try:
        sampler.options.default_shots = 1000
    except AttributeError:
        # Fallback if standard sampler used
        pass
        
    # Execute
    job = sampler.run([isa_circuit])
    print(f"Job submitted! Job ID is {job.job_id()}")
    print("Waiting for job to complete (this may take a few minutes if queued on real hardware)...")
    
    pub_result = job.result()[0]
    counts = pub_result.data.meas.get_counts()
    print(f"\nMeasurement Counts (Period Finding Output): {counts}")
    
    # Save the output to be consumed by the dashboard script
    import json
    with open("qiskit_counts.json", "w") as f:
        json.dump(counts, f)
    print("Saved Qiskit distribution to qiskit_counts.json for dashboard integration.")
    
    print("\n[SUCCESS] Quantum simulation complete!")
    print("The above outputs map directly to period `r`. Since `r` is found efficiently via")
    print("quantum mechanics, classical cryptography (RSA) relying on Prime Factorization is broken.")
    print("This explicitly demonstrates why transitioning to Hybrid and pure PQC (Kyber/Dilithium)")
    print("within MLS architectures is practically necessary, mitigating immediate data capture risks.")

if __name__ == '__main__':
    run_hardware_showcase()
