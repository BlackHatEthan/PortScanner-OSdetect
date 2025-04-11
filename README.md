# PortScanner-OSDetect

⚡ A high-performance Python port scanner that detects open ports, suggests known exploits, and provides OS fingerprinting hints.

## 🚀 Features

- Multi-threaded scanning for speed
- OS detection via ping TTL analysis
- Known exploit identification for common ports (e.g. EternalBlue on port 445)
- Clean terminal output with summaries

## 🧠 How it works

The scanner connects to a target IP and scans the most common 1024 ports using sockets.  
It tries to detect the host OS by sending an ICMP ping and checking the TTL.  
If a port is known to be associated with a historical exploit, the name is listed.

## 🔧 Requirements

```bash
pip install socket
pip install threading
pip install queue
pip install time
```
## 🚨 But here are a few things to watch out for:
Raw Sockets (for OS detection):
On Windows, you must run it as Administrator.
On Linux/Mac, you must use sudo python3 scanner.py.
Firewall / Antivirus:
Can block the scanner or cause some open ports to look closed.
May flag the script, especially if packaged into an .exe.
