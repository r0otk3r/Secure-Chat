# 🔐 SecureChat v2.0  
### AES-256 Encrypted Chat & File Transfer System

SecureChat v2.0 is a professional, end-to-end encrypted communication system built with Python 3.  
It provides **real-time encrypted chat** and **secure file transfer** between a server and a client over TCP.  
Designed for ethical use, testing, and educational purposes only.

---

## ⚠️ Legal Disclaimer

This project is intended strictly for educational, ethical, and research purposes only.  
Do not use SecureChat for unauthorized communication interception or illegal data transmission.  
The author is not responsible for any misuse or damages resulting from this software.

---

## 📦 Features

- **AES-256 Encryption (AES-GCM)** — Confidentiality for messages and files.  
- **HMAC-SHA256 Integrity** — Ensures packet authenticity and prevents tampering.  
- **Cross-Platform** — Works on Linux, macOS, and Windows.  
- **Real-Time Messaging** — Interactive send/receive console.  
- **Secure File Transfer** — Send files with progress reporting.  
- **Professional CLI Interface** — Clean console for easy readability.  
- **Key Management** — `generate_aes_key.py` produces `aes_key.txt` (hex).

---

## ⚡ Requirements

- Python 3.8+  
- `cryptography`  
- `tqdm`

Install dependencies:

```bash
python3 -m venv venv
source venv/bin/activate
pip install cryptography tqdm
```
## 🚀 Quick Start

### 1 Generate AES Key
```bash
python3 generate_aes_key.py
# -> aes_key.txt (hex, 32 bytes for AES-256)
```
Copy aes_key.txt securely to both server and client machines.

### 2 Start Server
```bash
python3 server.py --host 0.0.0.0 --port 9999
```
### 3 Start Client
```bash
python3 client.py --host <server_ip> --port 9999
```
---
### 4 Chat & Transfer Files

- Send messages by typing and pressing Enter.

- Send a file: /sendfile /path/to/file → recipient saves as received_<filename>.

- Exit client: /quit.

## 🔎 How it Works

- Key Generation: generate_aes_key.py creates a random 32-byte AES-256 key in aes_key.txt.

- Encryption: AES-GCM with 12-byte random nonces encrypts message/file payloads.

- Integrity: HMAC-SHA256 computed per packet over JSON data.

- Packet Structure:
```json
{
  "hmac": "<hex-hmac>",
  "data": {
    "type": "message" | "file",
    "payload": { "nonce": "<b64>", "cipher": "<b64>" },
    "filename": "optional"
  }
}
```
## 📝 Example Session

### Server terminal
```vbnet
Server listening on 0.0.0.0:9999
[+] Client connected.
client: Hello, server!
You:
Received file 'received_secret.zip' (153421 bytes)
```
### Client terminal
```bash
Connected to 127.0.0.1:9999
You: Hello, server!
You: /sendfile ./secret.zip
Sending secret.zip: 100%|██████████| 150k/150k [00:00<00:00, 1.23MB/s]
File sent.
```
## 📜 License & Attribution

This project is intended for educational, ethical, and internal use.
No warranty is provided. Attribution appreciated if reused

---
## Official Channels

- [Telegram @r0otk3r](https://t.me/r0otk3r)
- [X @r0otk3r](https://x.com/r0otk3r)
