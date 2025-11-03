# Secure VPN-Style Encrypted Messenger (Computer Networks Project)

This project implements a secure, end-to-end encrypted messaging system using Python sockets, VPN-style tunneling concepts, GUI clients, a relay server, a hacker/MITM simulation, and a packet sniffer. It demonstrates how encrypted communication protects users from packet sniffing and interception, aligning with core topics of the Computer Networks course.

## 🔐 Project Overview
The system enables two clients to communicate securely over a TCP network using Fernet (AES + HMAC) encryption. A relay server forwards encrypted packets without decrypting them. A hacker module and a packet sniffer attempt to capture messages but only receive ciphertext, proving end-to-end confidentiality. This project visually demonstrates VPN tunneling, encrypted communication, and real-world network attack scenarios.

## ✅ Features
- End-to-end encrypted messaging  
- VPN-style secure tunneling simulation  
- User authentication (client-side + server-side)  
- GUI chat application using Tkinter  
- Custom JSON-based packet structure  
- Sender-side encryption & receiver-side decryption  
- Relay server that forwards ciphertext only  
- Hacker client for MITM demonstration  
- Packet sniffer using Scapy to view raw encrypted traffic  
- Multi-threaded communication for real-time chatting  

## ✅ System Architecture
Client A (Encrypt) → Relay Server (Forward Ciphertext) → Client B (Decrypt)  
                     ↘  
                Hacker Client (Ciphertext Only)  
Packet Sniffer (Scapy) ←——————————— Network Traffic

## ✅ Components

### 1. Relay Server
- Authenticates users using a simple database  
- Forwards encrypted packets to the correct user  
- Mirrors packets to the hacker client for demonstration  
- Operates as a zero-knowledge server (never decrypts messages)

### 2. GUI Chat Clients
- Login screen with username, password, and key configuration  
- Fernet key derived using PBKDF2 or provided directly  
- Encrypts outgoing packets  
- Decrypts incoming ciphertext  
- Displays messages with timestamps in a GUI  

### 3. Hacker Client (MITM Simulator)
- Connects as an unauthorized listener  
- Receives mirrored encrypted packets  
- Attempts to decrypt (fails without correct key)  
- Shows ciphertext-only interception  

### 4. Packet Sniffer (Scapy)
- Captures TCP packets on port 9000  
- Displays raw packet payloads  
- Confirms that intercepted data is unreadable ciphertext  

## ✅ Encryption Details
- Algorithm: Fernet (AES-128 + HMAC-SHA256)  
- Key Derivation: PBKDF2 with salt (390,000 iterations)  
- Data Integrity: Every encrypted packet contains authentication tags  
- Zero Plaintext Exposure: Server and attacker never see decrypted messages  

## ✅ Packet Structure
All messages are converted into a JSON packet and then encrypted:

{
  "header": "VPNv1",
  "src": "<sender>",
  "dst": "<receiver>",
  "type": "MSG",
  "timestamp": <time>,
  "len": <data_length>,
  "data": "<message>"
}

The entire packet is encrypted before transmission.

## ✅ How the System Demonstrates CN Concepts
- Socket programming (TCP)  
- Client-server architecture  
- Packet forwarding & routing  
- Encapsulation & tunneling  
- Application-layer encryption  
- Man-in-the-middle (MITM) attack simulation  
- Packet sniffing using Scapy  
- Multi-threading for full-duplex communication  

## ✅ How to Run the Project

1. Start the relay server:
python server.py

2. Start Client 1:
python gui_client.py

3. Start Client 2:
python gui_client.py

4. (Optional) Start Hacker client:
python hacker_client.py

5. (Optional) Run the packet sniffer (admin required):
python sniffer.py

## ✅ Applications
- Secure chat applications  
- VPN tunnel simulation  
- Cybersecurity demonstration  
- CN laboratories & networking projects  
- Encrypted communication research  

## ✅ Future Enhancements
- RSA-based automatic key exchange  
- File transfer encryption  
- Group chat support  
- Advanced GUI (PyQt or web interface)  
- Database storage of encrypted message history  

## ✅ Project Status
✅ Fully Working  
✅ Tested across devices  
✅ Demonstrates encryption, routing, and network-level security  

## ✅ Author
Your Name  
B.Tech CSE  
Computer Networks Semester Project  

## ✅ License
This project is for academic and educational purposes.
