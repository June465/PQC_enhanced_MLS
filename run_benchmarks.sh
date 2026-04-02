#!/bin/bash

STATE_DIR=".mls_bench"
RESULTS="results.jsonl"

rm -f $RESULTS alice_kp.bin bob_kp.bin bob_kp_data.json

suites=("classic" "pqc-kem" "hybrid-kem")

for suite in "${suites[@]}"
do
    echo "Running benchmark for $suite"

    # reset state for clean experiment
    rm -rf $STATE_DIR

    cargo run -p mls_pqc_cli -- --suite $suite \
    -d $STATE_DIR key-package \
    --member-id Alice --output alice_kp.bin >> $RESULTS

    cargo run -p mls_pqc_cli -- --suite $suite \
    -d $STATE_DIR init-group \
    --group-id g1 --member-id Alice >> $RESULTS

    cargo run -p mls_pqc_cli -- --suite $suite \
    -d $STATE_DIR key-package \
    --member-id Bob --output bob_kp.bin >> $RESULTS

    cargo run -p mls_pqc_cli -- --suite $suite \
    -d $STATE_DIR add-member \
    --group-id g1 --key-package bob_kp.bin >> $RESULTS


    welcome=$(ls $STATE_DIR/g1/artifacts/welcome/*.bin | head -n 1)

    cargo run -p mls_pqc_cli -- --suite $suite \
    -d $STATE_DIR \
    join-group \
    --member-id Bob \
    --welcome $welcome \
    --key-package-data bob_kp_data.json \
    g1 >> $RESULTS
    # multiple encryption runs for averaging
    # Encrypt message and capture ciphertext (first output line)
        cargo run -q -p mls_pqc_cli -- --suite $suite \
    -d $STATE_DIR \
    encrypt \
    --group-id g1 \
    --plaintext "benchmark message" >> $RESULTS

    # Get latest ciphertext file
    ct_file=$(ls $STATE_DIR/g1/artifacts/ciphertext/*.bin | tail -n 1)

    # Convert ciphertext file to base64
    ct=$(base64 < "$ct_file" | tr -d '\n')

    # Decrypt
    cargo run -q -p mls_pqc_cli -- --suite $suite \
    -d $STATE_DIR \
    decrypt \
    --group-id g1_Bob \
    --ciphertext "$ct" >> $RESULTS

done

echo "Benchmark finished. Results stored in $RESULTS"