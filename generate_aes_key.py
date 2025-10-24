#!/usr/bin/env python3

import os

KEY_FILE = "aes_key.txt"

def main():
    # Generate 32 bytes = 256-bit AES key
    key = os.urandom(32)
    with open(KEY_FILE, "w") as f:
        f.write(key.hex())
    print(f"[+] AES-256 key generated and saved to {KEY_FILE}")

if __name__ == "__main__":
    main()
