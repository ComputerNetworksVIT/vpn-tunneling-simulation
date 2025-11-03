# client.py
import socket
import threading
import json
import sys
from utils import make_packet, parse_packet, make_fernet_from_password, fernet_from_base64

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 9000

# default salt for demo; use same for both clients if you press Enter
DEFAULT_SALT = bytes.fromhex("00112233445566778899aabbccddeeff")

def recv_thread(conn, fernet):
    """Background thread: receive meta then payload, decrypt and print."""
    while True:
        try:
            meta_raw = conn.recv(4096)
            if not meta_raw:
                print("[*] Server closed connection")
                break
            meta = json.loads(meta_raw.decode())
            if meta.get("type") == "ROUTE":
                payload_len = meta.get("len")
                payload = b''
                while len(payload) < payload_len:
                    chunk = conn.recv(payload_len - len(payload))
                    if not chunk:
                        break
                    payload += chunk
                # try to decrypt and parse packet
                try:
                    decrypted = fernet.decrypt(payload)
                    src, dst, ptype, data = parse_packet(decrypted)
                    print(f"\n[{src} -> {dst}] {data.decode()}\n> ", end='', flush=True)
                except Exception:
                    print("\n[!] Unable to decrypt incoming payload.\n> ", end='', flush=True)
            else:
                # other meta (errors, etc.)
                print("\n[SERVER META]:", meta, "\n> ", end='', flush=True)
        except Exception as e:
            print("\n[Receive thread error]:", e)
            break

def main():
    username = input("Username: ").strip()
    password = input("Password: ").strip()

    # ==== KEY SETUP (direct key OR password+salt) ====
    key_b64 = input("Enter Fernet key (leave blank to use password+salt): ").strip()

    if key_b64:
        # User provided a direct Fernet key
        fernet = fernet_from_base64(key_b64)
    else:
        # Derive key from password + salt
        enc_password = input("Encryption password (shared secret): ").strip()
        salt_hex = input("Salt hex (press Enter to use default): ").strip()
        salt = DEFAULT_SALT if salt_hex == "" else bytes.fromhex(salt_hex)
        fernet = make_fernet_from_password(enc_password, salt)

    # connect to server
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((SERVER_HOST, SERVER_PORT))
    except Exception as e:
        print("Could not connect to server:", e)
        return

    # send auth JSON
    auth = {"username": username, "password": password}
    s.send(json.dumps(auth).encode())
    resp_raw = s.recv(4096)
    resp = json.loads(resp_raw.decode())
    if resp.get("status") != "ok":
        print("Authentication failed:", resp)
        s.close()
        return
    print("[*] Authenticated with server.")

    # start receiving thread
    threading.Thread(target=recv_thread, args=(s, fernet), daemon=True).start()

    print("Enter messages in format: dst_username: message")
    try:
        while True:
            line = input("> ").strip()
            if not line:
                continue
            if line.lower() in ("quit", "exit"):
                s.send(json.dumps({"type":"LOGOUT"}).encode())
                break
            if ":" not in line:
                print("Use format: dst: message")
                continue
            dst, msg = line.split(":", 1)
            dst = dst.strip()
            msg = msg.strip()
            pkt = make_packet(username, dst, "MSG", msg.encode())
            encrypted = fernet.encrypt(pkt)
            meta = {"type":"ROUTE", "dst": dst, "len": len(encrypted)}
            # send meta then payload
            s.send(json.dumps(meta).encode())
            s.send(encrypted)
    except KeyboardInterrupt:
        pass
    finally:
        s.close()

if __name__ == "__main__":
    main()
