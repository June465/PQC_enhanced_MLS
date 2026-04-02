import json
import pandas as pd
import matplotlib.pyplot as plt

data = []

with open("results.jsonl") as f:
    for line in f:
        try:
            data.append(json.loads(line))
        except:
            pass

df = pd.DataFrame(data)

# Encryption time
encrypt = df[df["op"] == "encrypt"]

plt.figure(figsize=(6,4))
plt.bar(encrypt["suite"], encrypt["time_ms"])
plt.title("Encryption Time Comparison")
plt.ylabel("Time (ms)")
plt.xlabel("Suite")
plt.grid(axis="y")
plt.savefig("encrypt_time.png")

# Decryption time
decrypt = df[df["op"] == "decrypt"]

if not decrypt.empty:
    plt.figure(figsize=(6,4))
    plt.bar(decrypt["suite"], decrypt["time_ms"])
    plt.title("Decryption Time Comparison")
    plt.ylabel("Time (ms)")
    plt.xlabel("Suite")
    plt.grid(axis="y")
    plt.savefig("decrypt_time.png")

# Ciphertext size
size = encrypt

if "bytes_out" in size.columns:
    plt.figure(figsize=(6,4))
    plt.bar(size["suite"], size["bytes_out"])
    plt.title("Ciphertext Size Comparison")
    plt.ylabel("Bytes")
    plt.xlabel("Suite")
    plt.grid(axis="y")
    plt.savefig("ciphertext_size.png")

print("Graphs generated from benchmark results!")