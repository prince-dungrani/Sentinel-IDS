import socket
import time

# CHANGE THIS to your actual Wireless LAN IP address (from ipconfig)
TARGET = "192.168.50.143" 

def simulate_port_scan():
    print(f"[!] Simulating Port Scan on {TARGET}...")
    for port in range(1024, 1040):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.1)
        s.connect_ex((TARGET, port)) # connect_ex doesn't throw errors
        s.close()
    print("[+] Done.")

def simulate_sqli():
    print(f"[!] Simulating SQL Injection on {TARGET}...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((TARGET, 80))
        # This string must match your rules.json regex
        payload = "GET /search?id=1%20OR%201=1%20union%20select%20null%20-- HTTP/1.1\r\nHost: localhost\r\n\r\n"
        s.send(payload.encode())
        s.close()
        print("[+] Payload sent.")
    except Exception as e:
        print(f"[-] SQLi failed: {e}. (Is the dummy server running on port 80?)")

if __name__ == "__main__":
    simulate_port_scan()
    time.sleep(2)
    simulate_sqli()
