# gui_client.py
"""
GUI client for VPN-messenger (Login window + Chat window).
Depends on utils.py (make_packet, parse_packet, make_fernet_from_password, fernet_from_base64).
Run: python gui_client.py

UI behavior:
 - Login window asks: username, password (for server auth), then either Fernet key OR password+salt to derive key.
 - On successful login it opens the chat window.
 - Chat window: Recipient field, messages display (read-only), message entry, Send button.
 - Incoming packets are decrypted and displayed.
"""
import socket
import threading
import json
import queue
import time
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

from utils import make_packet, parse_packet, make_fernet_from_password, fernet_from_base64

SERVER_HOST = "172.20.130.181"
SERVER_PORT = 9000
DEFAULT_SALT = bytes.fromhex("00112233445566778899aabbccddeeff")

# UI constants
WINDOW_TITLE = "VPN Messenger (GUI)"


class GuiClient:
    def __init__(self, root):
        self.root = root
        self.root.title(WINDOW_TITLE)
        self.sock = None
        self.fernet = None
        self.username = None
        self.recv_queue = queue.Queue()
        self.running = False

        self._build_login()

    # -------------------------
    # Login UI
    # -------------------------
    def _build_login(self):
        self.login_frame = ttk.Frame(self.root, padding=12)
        self.login_frame.grid(sticky="nsew")

        ttk.Label(self.login_frame, text="Login to VPN Messenger", font=("Segoe UI", 14)).grid(column=0, row=0, columnspan=2, pady=(0, 10))

        ttk.Label(self.login_frame, text="Username:").grid(column=0, row=1, sticky="e")
        self.username_entry = ttk.Entry(self.login_frame, width=30)
        self.username_entry.grid(column=1, row=1, sticky="w")

        ttk.Label(self.login_frame, text="Password:").grid(column=0, row=2, sticky="e")
        self.password_entry = ttk.Entry(self.login_frame, width=30, show="*")
        self.password_entry.grid(column=1, row=2, sticky="w")

        ttk.Separator(self.login_frame, orient="horizontal").grid(column=0, row=3, columnspan=2, sticky="ew", pady=8)

        ttk.Label(self.login_frame, text="Enter Fernet key (optional):").grid(column=0, row=4, sticky="e")
        self.key_entry = ttk.Entry(self.login_frame, width=45)
        self.key_entry.grid(column=1, row=4, sticky="w")

        ttk.Label(self.login_frame, text="Or Password for key:").grid(column=0, row=5, sticky="e")
        self.encpass_entry = ttk.Entry(self.login_frame, width=30, show="*")
        self.encpass_entry.grid(column=1, row=5, sticky="w")

        ttk.Label(self.login_frame, text="Salt hex (press Enter for default):").grid(column=0, row=6, sticky="e")
        self.salt_entry = ttk.Entry(self.login_frame, width=45)
        self.salt_entry.grid(column=1, row=6, sticky="w")

        self.login_status = ttk.Label(self.login_frame, text="", foreground="red")
        self.login_status.grid(column=0, row=7, columnspan=2, pady=(8, 0))

        self.login_button = ttk.Button(self.login_frame, text="Login", command=self.on_login_clicked)
        self.login_button.grid(column=0, row=8, columnspan=2, pady=(10, 0))

        # make Enter press trigger login via a safe handler
        self.root.bind("<Return>", self._enter_login_handler)

    def _enter_login_handler(self, event):
        """Only trigger login if the login frame still exists (prevents calling destroyed widgets)."""
        try:
            if hasattr(self, "login_frame") and self.login_frame.winfo_exists():
                self.on_login_clicked()
        except Exception:
            # swallow errors — safer than crashing the UI
            pass

    # -------------------------
    # Networking & login
    # -------------------------
    def on_login_clicked(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if not username or not password:
            self.login_status.config(text="Username and password required")
            return

        # build Fernet object from direct key or password+salt
        key_b64 = self.key_entry.get().strip()
        if key_b64:
            try:
                self.fernet = fernet_from_base64(key_b64)
            except Exception as e:
                self.login_status.config(text=f"Invalid Fernet key: {e}")
                return
        else:
            encpwd = self.encpass_entry.get().strip()
            salt_hex = self.salt_entry.get().strip()
            if not encpwd:
                self.login_status.config(text="Either Fernet key or password required")
                return
            try:
                salt = DEFAULT_SALT if salt_hex == "" else bytes.fromhex(salt_hex)
                self.fernet = make_fernet_from_password(encpwd, salt)
            except Exception as e:
                self.login_status.config(text=f"Key derivation error: {e}")
                return

        # attempt to connect & authenticate (in background thread to avoid freezing UI)
        self.login_status.config(text="Connecting...")
        self.login_button.config(state="disabled")
        threading.Thread(target=self._connect_and_auth, args=(username, password), daemon=True).start()

    def _connect_and_auth(self, username, password):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((SERVER_HOST, SERVER_PORT))
        except Exception as e:
            self._safe_gui(lambda: self._on_login_failed(f"Connect failed: {e}"))
            return

        # send auth JSON
        try:
            s.sendall(json.dumps({"username": username, "password": password}).encode())
            resp_raw = s.recv(4096)
            resp = json.loads(resp_raw.decode())
        except Exception as e:
            try:
                s.close()
            except:
                pass
            self._safe_gui(lambda: self._on_login_failed(f"Auth exchange failed: {e}"))
            return

        if resp.get("status") != "ok":
            try:
                s.close()
            except:
                pass
            self._safe_gui(lambda: self._on_login_failed(f"Auth failed: {resp.get('reason','unknown')}"))
            return

        # success
        self.sock = s
        self.username = username
        self.running = True

        # start receiver thread
        threading.Thread(target=self._recv_loop, args=(self.sock, self.fernet), daemon=True).start()

        # switch to chat UI on main thread
        self._safe_gui(self._open_chat_window)

    def _on_login_failed(self, msg):
        self.login_status.config(text=msg)
        self.login_button.config(state="normal")

    # -------------------------
    # Chat UI
    # -------------------------
    def _open_chat_window(self):
        # unbind Enter so it doesn't trigger deleted login widgets
        try:
            self.root.unbind("<Return>")
        except Exception:
            pass

        # destroy login frame
        try:
            self.login_frame.destroy()
        except Exception:
            pass

        # main chat frame
        self.chat_frame = ttk.Frame(self.root, padding=8)
        self.chat_frame.grid(sticky="nsew")

        # top: status
        self.status_label = ttk.Label(self.chat_frame, text=f"Logged in as: {self.username}", font=("Segoe UI", 10))
        self.status_label.grid(column=0, row=0, sticky="w", columnspan=3)

        # recipient field
        ttk.Label(self.chat_frame, text="Recipient:").grid(column=0, row=1, sticky="e")
        self.recipient_entry = ttk.Entry(self.chat_frame, width=20)
        self.recipient_entry.grid(column=1, row=1, sticky="w")
        self.recipient_entry.insert(0, "bob")  # default during demo

        # logout button
        self.logout_button = ttk.Button(self.chat_frame, text="Logout", command=self._on_logout)
        self.logout_button.grid(column=2, row=1, sticky="e")

        # messages area (read-only scrolled text)
        self.msg_area = scrolledtext.ScrolledText(self.chat_frame, width=70, height=20, state=tk.DISABLED, wrap=tk.WORD)
        self.msg_area.grid(column=0, row=2, columnspan=3, pady=(8, 8))

        # message entry + send button
        self.msg_entry = ttk.Entry(self.chat_frame, width=55)
        self.msg_entry.grid(column=0, row=3, columnspan=2, sticky="w")
        self.msg_entry.bind("<Return>", lambda ev: self._on_send_clicked())

        self.send_button = ttk.Button(self.chat_frame, text="Send", command=self._on_send_clicked)
        self.send_button.grid(column=2, row=3, sticky="e")

        # Start a periodic poll to fetch incoming messages from queue
        self._poll_incoming()

    def _on_logout(self):
        # send LOGOUT meta then close
        try:
            if self.sock:
                self.sock.sendall(json.dumps({"type": "LOGOUT"}).encode())
        except:
            pass
        self.running = False
        try:
            if self.sock:
                self.sock.close()
        except:
            pass
        self.root.destroy()

    # -------------------------
    # Sending messages
    # -------------------------
    def _on_send_clicked(self):
        text = self.msg_entry.get().strip()
        if not text:
            return
        dst = self.recipient_entry.get().strip()
        if not dst:
            messagebox.showwarning("No recipient", "Please enter a recipient username (e.g. bob).")
            return

        # we will send a simple text message packet
        pkt = make_packet(self.username, dst, "MSG", text.encode())
        try:
            encrypted = self.fernet.encrypt(pkt)
            meta = {"type": "ROUTE", "dst": dst, "len": len(encrypted)}
            self.sock.sendall(json.dumps(meta).encode())
            # small pause can help ordering on some systems (not strictly required)
            time.sleep(0.01)
            self.sock.sendall(encrypted)
        except Exception as e:
            messagebox.showerror("Send failed", f"Failed to send message: {e}")
            return

        # locally show message
        self._append_message(f"[You -> {dst}] {text}")
        self.msg_entry.delete(0, tk.END)

    # -------------------------
    # Receiving packets (background)
    # -------------------------
    def _recv_loop(self, conn, fernet):
        """Background thread: receive meta then payload, decrypt and queue for UI."""
        try:
            while self.running:
                meta_raw = conn.recv(4096)
                if not meta_raw:
                    # connection closed
                    self.recv_queue.put(("status", "Server closed connection"))
                    break
                try:
                    meta = json.loads(meta_raw.decode())
                except Exception:
                    # skip unexpected bytes
                    continue

                if meta.get("type") == "ROUTE":
                    payload_len = meta.get("len", 0)
                    payload = b''
                    while len(payload) < payload_len:
                        chunk = conn.recv(payload_len - len(payload))
                        if not chunk:
                            break
                        payload += chunk
                    # try decrypt
                    try:
                        decrypted = fernet.decrypt(payload)
                        src, dst, ptype, data = parse_packet(decrypted)
                        # queue message for UI thread
                        self.recv_queue.put(("msg", src, dst, ptype, data))
                    except Exception:
                        # if can't decrypt, just queue the ciphertext notice
                        self.recv_queue.put(("cipher", repr(payload[:200])))
                else:
                    # other meta (errors etc.)
                    self.recv_queue.put(("meta", meta))
        except Exception as e:
            self.recv_queue.put(("status", f"Receiver error: {e}"))
        finally:
            self.running = False

    # -------------------------
    # UI helpers
    # -------------------------
    def _poll_incoming(self):
        """Periodically check queue and update UI (called on main thread)."""
        try:
            while True:
                item = self.recv_queue.get_nowait()
                if not item:
                    continue
                tag = item[0]
                if tag == "msg":
                    _, src, dst, ptype, data = item
                    # display the message
                    text = data.decode(errors="replace")
                    self._append_message(f"[{src} -> {dst}] {text}")
                elif tag == "cipher":
                    _, txt = item
                    self._append_message(f"[Hacker captured ciphertext] {txt}")
                elif tag == "meta":
                    _, meta = item
                    self._append_message(f"[META] {meta}")
                elif tag == "status":
                    _, st = item
                    self._append_message(f"[STATUS] {st}")
        except queue.Empty:
            pass
        # schedule next poll
        if self.running:
            self.root.after(100, self._poll_incoming)
        else:
            # if not running, close UI after short delay
            self.root.after(500, lambda: self.root.quit())

    def _append_message(self, text):
        self.msg_area.config(state=tk.NORMAL)
        ts = time.strftime("%H:%M:%S")
        self.msg_area.insert(tk.END, f"[{ts}] {text}\n")
        self.msg_area.see(tk.END)
        self.msg_area.config(state=tk.DISABLED)

    def _safe_gui(self, fn):
        """Run a small function on the main thread via after()."""
        self.root.after(0, fn)


def main():
    root = tk.Tk()
    # Make the window nicely resizable
    root.columnconfigure(0, weight=1)
    root.rowconfigure(0, weight=1)
    app = GuiClient(root)
    root.mainloop()


if __name__ == "__main__":
    main()
