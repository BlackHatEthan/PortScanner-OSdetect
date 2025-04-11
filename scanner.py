import socket
import threading
from queue import Queue
import time

# Common exploits per port
EXPLOITS = {
    21: ["FTP Bounce"],
    22: ["Brute Force SSH"],
    23: ["Telnet Credential Leak"],
    25: ["SMTP Open Relay"],
    53: ["DNS Cache Poisoning"],
    80: ["Directory Traversal", "XSS", "Shellshock (if CGI)"],
    110: ["POP3 Overflow"],
    135: ["MSRPC DCOM Exploit"],
    139: ["NetBIOS Enumeration"],
    143: ["IMAP Buffer Overflow"],
    443: ["Heartbleed", "SSL Stripping"],
    445: ["EternalBlue (MS17-010)"],
    3306: ["MySQL Authentication Bypass"],
    3389: ["RDP Credential Theft", "BlueKeep (CVE-2019-0708)"]
}

# Queue of ports to scan
q = Queue()
open_ports = []

# OS Detection based on TTL value (basic method)
def detect_os(ip):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(2)
        sock.sendto(b'\x08\x00\x00\x00\x00\x00\x00\x00', (ip, 1))
        data, addr = sock.recvfrom(1024)
        ttl = data[8]
        if ttl <= 64:
            return "Linux/Unix (TTL ~64)"
        elif ttl <= 128:
            return "Windows (TTL ~128)"
        else:
            return "Unknown OS"
    except Exception:
        return "OS Detection Failed"

def scan_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
                print(f"[+] Port {port} is open")
    except Exception:
        pass

def threader(ip):
    while not q.empty():
        port = q.get()
        scan_port(ip, port)
        q.task_done()

def run_scanner(ip, port_range=range(1, 1025)):
    print(f"[*] Scanning {ip}...")
    os_hint = detect_os(ip)
    print(f"[*] OS Hint: {os_hint}")

    for port in port_range:
        q.put(port)

    thread_count = 100
    threads = []

    for _ in range(thread_count):
        t = threading.Thread(target=threader, args=(ip,))
        t.daemon = True
        t.start()
        threads.append(t)

    q.join()
    print("\n[+] Scan Complete.\n")
    for port in sorted(open_ports):
        print(f"  [PORT {port}]")
        if port in EXPLOITS:
            for exploit in EXPLOITS[port]:
                print(f"     └── Possible exploit: {exploit}")
        else:
            print("     └── No known exploits listed.")

if __name__ == "__main__":
    target_ip = input("Enter target IP: ")
    start = time.time()
    run_scanner(target_ip)
    print(f"\nScan finished in {round(time.time() - start, 2)} seconds.")
