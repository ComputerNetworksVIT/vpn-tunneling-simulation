# hacker_client.py — connects as 'hacker' and prints captured encrypted payloads
import socket
import json
import sys
from utils import make_fernet_from_password, parse_packet

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 9000
DEFAULT_SALT = bytes.fromhex("00112233445566778899aabbccddeeff")


def recv_loop(conn, fernet=None):
    """Receive routing meta + encrypted payloads and display ciphertext."""
    try:
        while True:
            meta_raw = conn.recv(4096)
            if not meta_raw:
                print("[hacker] Connection closed by server.")
                break

            # meta is JSON (unencrypted routing header)
            try:
                meta = json.loads(meta_raw.decode())
            except Exception:
                print("[hacker] Received non-JSON meta; skipping.")
                continue

            if meta.get("type") == "ROUTE":
                payload_len = meta.get("len", 0)
                payload = b''
                while len(payload) < payload_len:
                    chunk = conn.recv(payload_len - len(payload))
                    if not chunk:
                        break
                    payload += chunk

                print("\n==== Hacker captured ENCRYPTED payload (bytes) ====")
                print(repr(payload[:300]))
                print("==== end captured payload ====\n")

                # Optional: if hacker supplied a key, try to decrypt
                if fernet:
                    try:
                        dec = fernet.decrypt(payload)
                        src, dst, ptype, data = parse_packet(dec)
                        print("[HACKER] DECRYPTED payload:", data.decode(errors="replace"))
                    except Exception:
                        print("[HACKER] cannot decrypt payload (no key / wrong key).")
            else:
                print("[HACKER META]:", meta)
    except Exception as e:
        print("[hacker] recv_loop exception:", e)


def main():
    username = "hacker"
    password = "hackpass"

    enc_password = input("Enter encryption password to try decrypt (or press Enter to skip): ").strip()
    salt_input = input("Salt hex (press Enter for default): ").strip()
    salt = DEFAULT_SALT if salt_input == "" else bytes.fromhex(salt_input)

    fernet = None
    if enc_password:
        try:
            fernet = make_fernet_from_password(enc_password, salt)
        except Exception:
            fernet = None

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((SERVER_HOST, SERVER_PORT))
    except Exception as e:
        print(f"[hacker] Could not connect to server {SERVER_HOST}:{SERVER_PORT} -> {e}")
        return

    try:
        s.send(json.dumps({"username": username, "password": password}).encode())
        resp_raw = s.recv(4096)
        resp = json.loads(resp_raw.decode())
    except Exception as e:
        print("[hacker] Authentication exchange failed:", e)
        s.close()
        return

    if resp.get("status") != "ok":
        print("[hacker] Auth failed:", resp)
        s.close()
        return

    print("[Hacker] connected. Waiting for mirrored encrypted packets...")
    try:
        recv_loop(s, fernet)
    except KeyboardInterrupt:
        print("\n[Hacker] Stopped by user.")
    finally:
        try:
            s.close()
        except:
            pass


if __name__ == "__main__":
    main()
