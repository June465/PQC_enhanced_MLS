@echo off
echo Running Rust Tests
cargo test --workspace

echo.
echo --- Executing CLI Flow ---

echo 1. Init Group...
cargo run -q -p mls_pqc_cli -- --suite hybrid-kem init-group -g "eval-group" -m "Alice"

echo 2. Key Package...
cargo run -q -p mls_pqc_cli -- key-package -m "Bob" -o bob_eval.bin

echo 3. Add Member...
cargo run -q -p mls_pqc_cli -- add-member -g "eval-group" -k bob_eval.bin

echo 4. Join Group...
for /f "delims=" %%I in ('dir /b /s ".mls_state\eval-group\artifacts\welcome\*.bin"') do set WELCOME_BIN=%%I
if defined WELCOME_BIN (
    echo Found welcome bin: %WELCOME_BIN%
    cargo run -q -p mls_pqc_cli -- join-group -g "eval-group" -m "Bob" --welcome "%WELCOME_BIN%" --key-package-data bob_eval_data.json
) else (
    echo Failed to find welcome bin!
)

echo 5. Encrypt...
cargo run -q -p mls_pqc_cli -- encrypt -g "eval-group" -p "Message from Alice" 2> encrypt_stderr.txt
set /p CIPHERTEXT=<encrypt_stderr.txt
echo Ciphertext: %CIPHERTEXT%

echo 6. Decrypt...
cargo run -q -p mls_pqc_cli -- -d .mls_state decrypt -g "eval-group_Bob" -c "%CIPHERTEXT%" 2> decrypt_stderr.txt
set /p PLAINTEXT=<decrypt_stderr.txt
echo Decrypted: %PLAINTEXT%

echo 7. Export State...
cargo run -q -p mls_pqc_cli -- export-state -g "eval-group" 2> export_stderr.txt

echo.
echo Check results done.
