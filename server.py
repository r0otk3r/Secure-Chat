#!/usr/bin/env python3
import socket, threading, json, os, base64, signal, sys, argparse, hmac, hashlib
from tqdm import tqdm
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_FILE="aes_key.txt"

# Load AES key
def load_key():
    if not os.path.exists(KEY_FILE):
        raise FileNotFoundError("Run generate_aes_key.py first")
    with open(KEY_FILE,"r") as f:
        key = bytes.fromhex(f.read().strip())
    if len(key) not in (16,24,32):
        raise ValueError("AES key must be 16,24,32 bytes")
    return key

# Encrypt with AES-GCM
def aes_encrypt(key: bytes, plaintext: bytes) -> dict:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return {"nonce": base64.b64encode(nonce).decode(),
            "cipher": base64.b64encode(ct).decode()}

# Decrypt AES-GCM
def aes_decrypt(key: bytes, payload: dict) -> bytes:
    aesgcm = AESGCM(key)
    nonce = base64.b64decode(payload["nonce"])
    ct = base64.b64decode(payload["cipher"])
    return aesgcm.decrypt(nonce, ct, None)

# Compute HMAC for integrity
def compute_hmac(key: bytes, data: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()

# Verify HMAC
def verify_hmac(key: bytes, data: bytes, tag: str) -> bool:
    expected = hmac.new(key, data, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, tag)

# Socket wrapper
class Connection:
    def __init__(self, sock):
        self.sock = sock
        self.buf = b""
        self.lock = threading.Lock()

    def send_json(self, obj):
        # Add HMAC tag for integrity
        raw = json.dumps(obj).encode()
        tag = compute_hmac(load_key(), raw)
        packet = {"hmac": tag, "data": obj}
        with self.lock:
            self.sock.sendall((json.dumps(packet)+"\n").encode())

    def recv_json(self):
        while b"\n" not in self.buf:
            chunk = self.sock.recv(4096)
            if not chunk: return None
            self.buf += chunk
        line,_,self.buf = self.buf.partition(b"\n")
        packet = json.loads(line.decode())
        if "hmac" not in packet or "data" not in packet:
            return None
        # Verify HMAC
        if not verify_hmac(load_key(), json.dumps(packet["data"]).encode(), packet["hmac"]):
            print("[!] HMAC verification failed!")
            return None
        return packet["data"]

    def send_bytes(self,data:bytes):
        with self.lock: self.sock.sendall(data)

    def close(self):
        try:self.sock.shutdown(socket.SHUT_RDWR)
        except: pass
        self.sock.close()

# Receive messages/files in chunks
def receive_loop(conn, key):
    try:
        # Track open files being received
        open_files = {}  # filename -> file object

        while True:
            obj = conn.recv_json()
            if obj is None:
                break

            if obj.get("type") == "message":
                msg = aes_decrypt(key, obj["payload"]).decode()
                print(f"\nclient: {msg}\nYou: ", end="", flush=True)

            elif obj.get("type") == "file_chunk":
                filename = obj.get("filename", "unknown")
                chunk_index = obj.get("chunk_index", 0)
                total_chunks = obj.get("total_chunks", 1)
                payload = obj.get("payload")

                # Decrypt chunk
                data = aes_decrypt(key, payload)

                # Open file if first chunk
                if filename not in open_files:
                    open_files[filename] = open(f"received_{filename}", "wb")

                # Write chunk
                open_files[filename].write(data)

                # Progress display
                print(f"\rReceiving {filename} ({chunk_index + 1}/{total_chunks})", end="", flush=True)

                # Close file if last chunk
                if chunk_index + 1 == total_chunks:
                    open_files[filename].close()
                    del open_files[filename]
                    print(f"\nReceived file 'received_{filename}' ({total_chunks} chunks)\nYou: ", end="", flush=True)

    except Exception as e:
        print(f"[!] Receive error: {e}")


# Input loop to send messages/files
def input_loop(conn,key):
    try:
        while True:
            msg=input("You: ").strip()
            if not msg: continue
            if msg.lower()=="/quit": break
            if msg.startswith("/sendfile "):
                path=msg.split(" ",1)[1]
                if not os.path.exists(path): print("File not found."); continue
                filename=os.path.basename(path)
                with open(path,"rb") as f: data=f.read()
                payload=aes_encrypt(key,data)
                blob = {"type":"file","filename":filename,"payload":payload}
                # Show progress bar while sending
                with tqdm(total=len(json.dumps(blob).encode()), unit="B", unit_scale=True, desc=f"Sending {filename}") as pbar:
                    conn.send_json(blob)
                    pbar.update(len(json.dumps(blob).encode()))
                print("File sent."); continue
            payload = aes_encrypt(key,msg.encode())
            conn.send_json({"type":"message","payload":payload})
    finally:
        conn.close()

# Handle a client connection
def handle_client(conn,key):
    print("[+] Client connected.")
    threading.Thread(target=receive_loop,args=(conn,key),daemon=True).start()
    input_loop(conn,key)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host",default="0.0.0.0",help="Host to bind")
    parser.add_argument("--port",type=int,default=9999,help="Port to listen")
    args=parser.parse_args()

    key=load_key()
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    s.bind((args.host,args.port))
    s.listen(1)
    print(f"Server listening on {args.host}:{args.port}")

    # Graceful shutdown
    def shutdown(sig,frame):
        print("\n[!] Shutting down server.")
        try:s.close()
        finally: sys.exit(0)
    signal.signal(signal.SIGINT,shutdown)
    signal.signal(signal.SIGTERM,shutdown)

    try:
        conn_sock,_ = s.accept()
        conn = Connection(conn_sock)
        handle_client(conn,key)
    finally:
        s.close()

if __name__=="__main__":
    main()
