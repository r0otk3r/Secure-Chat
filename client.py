#!/usr/bin/env python3
import socket, threading, json, os, base64, sys, argparse, hmac, hashlib
from tqdm import tqdm
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_FILE="aes_key.txt"

# Load AES key
def load_key():
    if not os.path.exists(KEY_FILE):
        raise FileNotFoundError("Run generate_aes_key.py first")
    with open(KEY_FILE,"r") as f:
        key=bytes.fromhex(f.read().strip())
    if len(key) not in (16,24,32):
        raise ValueError("AES key must be 16,24,32 bytes")
    return key

# AES-GCM encrypt/decrypt
def aes_encrypt(key: bytes, plaintext: bytes) -> dict:
    aesgcm=AESGCM(key)
    nonce=os.urandom(12)
    ct=aesgcm.encrypt(nonce,plaintext,None)
    return {"nonce":base64.b64encode(nonce).decode(),
            "cipher":base64.b64encode(ct).decode()}

def aes_decrypt(key: bytes, payload: dict) -> bytes:
    aesgcm=AESGCM(key)
    nonce=base64.b64decode(payload["nonce"])
    ct=base64.b64decode(payload["cipher"])
    return aesgcm.decrypt(nonce,ct,None)

# HMAC functions
def compute_hmac(key: bytes, data: bytes) -> str:
    return hmac.new(key,data,hashlib.sha256).hexdigest()

def verify_hmac(key: bytes, data: bytes, tag: str) -> bool:
    expected = hmac.new(key,data,hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected,tag)

# Socket wrapper
class Connection:
    def __init__(self,sock):
        self.sock=sock
        self.buf=b""
        self.lock=threading.Lock()
    def send_json(self,obj):
        raw=json.dumps(obj).encode()
        tag=compute_hmac(load_key(),raw)
        packet={"hmac":tag,"data":obj}
        with self.lock: self.sock.sendall((json.dumps(packet)+"\n").encode())
    def recv_json(self):
        while b"\n" not in self.buf:
            chunk=self.sock.recv(4096)
            if not chunk: return None
            self.buf+=chunk
        line,_,self.buf=self.buf.partition(b"\n")
        packet=json.loads(line.decode())
        if "hmac" not in packet or "data" not in packet: return None
        if not verify_hmac(load_key(), json.dumps(packet["data"]).encode(), packet["hmac"]):
            print("[!] HMAC verification failed!"); return None
        return packet["data"]
    def send_bytes(self,data:bytes):
        with self.lock:self.sock.sendall(data)
    def close(self):
        try:self.sock.shutdown(socket.SHUT_RDWR)
        except: pass
        self.sock.close()

# Receiver thread
def receiver(conn,key):
    try:
        while True:
            obj=conn.recv_json()
            if obj is None: break
            if obj.get("type")=="message":
                msg=aes_decrypt(key,obj["payload"]).decode()
                print(f"\nserver: {msg}\nYou: ",end="",flush=True)
            elif obj.get("type")=="file":
                filename=obj.get("filename","unknown")
                data=aes_decrypt(key,obj["payload"])
                with open(f"received_{filename}","wb") as f: f.write(data)
                print(f"\nReceived file 'received_{filename}' ({len(data)} bytes)\nYou: ",end="",flush=True)
    except Exception as e: print("[!] Receiver error:",e)

# Input loop to send messages/files in chunks
def input_loop(conn, key):
    try:
        while True:
            msg = input("You: ").strip()
            if not msg:
                continue
            if msg.lower() == "/quit":
                break

            # Send file in chunks
            if msg.startswith("/sendfile "):
                path = msg.split(" ", 1)[1]
                if not os.path.exists(path):
                    print("File not found.")
                    continue

                filename = os.path.basename(path)
                chunk_size = 64 * 1024  # 64 KB per chunk
                file_size = os.path.getsize(path)
                total_chunks = (file_size + chunk_size - 1) // chunk_size

                with open(path, "rb") as f:
                    for chunk_index in range(total_chunks):
                        chunk_data = f.read(chunk_size)
                        payload = aes_encrypt(key, chunk_data)
                        packet = {
                            "type": "file_chunk",
                            "filename": filename,
                            "chunk_index": chunk_index,
                            "total_chunks": total_chunks,
                            "payload": payload
                        }

                        conn.send_json(packet)

                        # Progress bar
                        print(f"\rSending {filename} ({chunk_index + 1}/{total_chunks})", end="", flush=True)

                print(f"\nFile '{filename}' sent successfully.")
                continue

            # Send normal message
            payload = aes_encrypt(key, msg.encode())
            conn.send_json({"type": "message", "payload": payload})

    finally:
        conn.close()

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--host",required=True,help="Server IP")
    parser.add_argument("--port",type=int,default=9999)
    args=parser.parse_args()

    key=load_key()
    sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    try: sock.connect((args.host,args.port))
    except Exception as e: print(f"[!] Could not connect: {e}"); sys.exit(1)
    print(f"Connected to {args.host}:{args.port}")
    conn=Connection(sock)
    threading.Thread(target=receiver,args=(conn,key),daemon=True).start()
    input_loop(conn,key)

if __name__=="__main__":
    main()
