# sniffer.py — simple TCP payload sniffer for port 9000
# Requires: scapy + libpcap (Npcap on Windows)
# Run as Administrator on Windows (or with sudo on Linux/macOS)

from scapy.all import sniff, TCP, Raw
import argparse
import sys

def pkt_callback(pkt):
    # We check packet has TCP layer and raw payload
    if TCP in pkt and Raw in pkt:
        payload = bytes(pkt[Raw].load)
        # print a short preview (first 300 bytes) so console is readable
        print("---- captured payload (raw bytes) ----")
        # use repr to show non-printable bytes clearly
        print(repr(payload[:300]))
        print("-------------------------------------\n")

def main():
    parser = argparse.ArgumentParser(description="Simple sniffer for VPN messenger (TCP port 9000).")
    parser.add_argument("--iface", default=None, help="Interface to sniff on (optional).")
    parser.add_argument("--port", type=int, default=9000, help="TCP port to filter (default: 9000).")
    args = parser.parse_args()

    bpf_filter = f"tcp port {args.port}"
    print(f"Starting sniffer on filter: '{bpf_filter}'  (iface={args.iface})")
    print("Press Ctrl-C to stop. You should see encrypted payloads (ciphertext) captured.")
    try:
        sniff(filter=bpf_filter, prn=pkt_callback, store=False, iface=args.iface)
    except RuntimeError as e:
        # Common on Windows when Npcap/WinPcap isn't installed or usable
        print("\nERROR: sniff() failed:", e)
        print("On Windows you must install Npcap (https://nmap.org/npcap/) and enable loopback support")
        print("— or run the mirror-hacker approach (no driver install) provided in the project.")
        print("If you already installed Npcap, run this script from an elevated (Administrator) PowerShell.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nSniffer stopped by user.")
    except Exception as e:
        print("\nUnexpected error in sniffer:", e)
        sys.exit(1)

if __name__ == "__main__":
    main()
