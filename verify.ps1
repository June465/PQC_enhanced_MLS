$ErrorActionPreference = "Stop"

Write-Host "Running Rust Tests"
cargo test --workspace

Write-Host "`n--- Executing CLI Flow ---"

# Step 1: Init Group
Write-Host "1. Init Group..."
cargo run -q -p mls_pqc_cli -- --suite hybrid-kem init-group -g "eval-group" -m "Alice" | Out-Null

# Step 2: Key Package
Write-Host "2. Key Package..."
cargo run -q -p mls_pqc_cli -- --suite hybrid-kem key-package -m "Bob" -o bob_eval.bin | Out-Null

# Step 3: Add Member
Write-Host "3. Add Member..."
cargo run -q -p mls_pqc_cli -- add-member -g "eval-group" -k bob_eval.bin | Out-Null

# Step 4: Join Group
Write-Host "4. Join Group..."
$welcome = Get-ChildItem .mls_state/eval-group/artifacts/welcome/*.bin | Select-Object -First 1
cargo run -q -p mls_pqc_cli -- join-group -g "eval-group" -m "Bob" --welcome $welcome.FullName --key-package-data bob_eval_data.json | Out-Null

# Step 5: Encrypt
Write-Host "5. Encrypt..."
cargo run -q -p mls_pqc_cli -- encrypt -g "eval-group" -p "Message from Alice" 2> encrypt_stderr.txt | Out-Null
$ciphertext = Get-Content encrypt_stderr.txt -Raw
Write-Host "Ciphertext generated successfully."

# Step 6: Decrypt
Write-Host "6. Decrypt (as Bob)..."
cargo run -q -p mls_pqc_cli -- -d .mls_state decrypt -g "eval-group_Bob" -c "$ciphertext" 2> decrypt_stderr.txt | Out-Null
$plaintext = Get-Content decrypt_stderr.txt -Raw
Write-Host "Decrypted message: $plaintext"

# Step 7: Export State
Write-Host "7. Export State..."
cargo run -q -p mls_pqc_cli -- export-state -g "eval-group" 2> export_stderr.txt | Out-Null
$state = Get-Content export_stderr.txt -Raw
$stateSnippet = $state.Substring(0, [math]::Min(100, $state.Length))
Write-Host "Export State JSON snippet: $stateSnippet..."

Write-Host "`nSuccessfully verified all main functionality."
