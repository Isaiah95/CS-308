import os

# Generate a random 16-byte key
key = os.urandom(16)

# Convert the key to hexadecimal format for printing
key_hex = key.hex()

print("Randomly generated key:", key_hex)

# Generate a random 16-byte IV
iv = os.urandom(16)

# Convert the IV to hexadecimal format for printing
iv_hex = iv.hex()

print("Randomly generated IV:", iv_hex)
