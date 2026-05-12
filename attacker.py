import time
import socket
import urllib.request
import urllib.error

TARGET_IP = "127.0.0.1"
TARGET_PORT = 5000
BASE_URL = f"http://{TARGET_IP}:{TARGET_PORT}"

def print_step(msg):
    print(f"\n[+] {msg}")
    time.sleep(1)

def send_http(path, headers=None):
    url = f"{BASE_URL}{path}"
    print(f"    -> Sending HTTP Request: {url}")
    try:
        req = urllib.request.Request(url, headers=headers or {})
        urllib.request.urlopen(req, timeout=2)
    except urllib.error.URLError:
        pass # We don't care if the server returns 404 or 500 (since the payload is just testing the IDS)
    except Exception as e:
        pass

def test_sql_injection():
    print_step("Simulating SQL Injection...")
    send_http("/?search=union%20select%20*%20from%20users")
    send_http("/login?user=admin'%20or%201=1--")

def test_xss():
    print_step("Simulating XSS Attack...")
    send_http("/?q=%3Cscript%3Ealert('xss')%3C/script%3E")

def test_command_injection():
    print_step("Simulating Command Injection...")
    send_http("/?cmd=whoami")

def test_sqlmap():
    print_step("Simulating SQLMap Scanner...")
    send_http("/", headers={"User-Agent": "sqlmap/1.4.12.8#dev (http://sqlmap.org)"})

def test_suspicious_ports():
    print_step("Simulating Suspicious Port Access (22, 23, 445)...")
    for port in [22, 23, 445]:
        print(f"    -> Probing {TARGET_IP}:{port}")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect((TARGET_IP, port))
            s.close()
        except:
            pass

def test_port_scan():
    print_step("Simulating Port Scan...")
    print("    -> Probing 20 random ports quickly...")
    for port in range(8000, 8020): 
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)
            s.connect((TARGET_IP, port))
            s.close()
        except:
            pass

def test_syn_flood():
    print_step("Simulating SYN Flood (Using Scapy)...")
    try:
        from scapy.all import IP, TCP, send
        print("    -> Firing 30 SYN packets...")
        packets = [IP(dst=TARGET_IP)/TCP(dport=TARGET_PORT, flags="S") for _ in range(30)]
        send(packets, verbose=False)
    except Exception as e:
        print(f"    -> Scapy error: {e}")

if __name__ == "__main__":
    print("=========================================")
    print(f"   STARTING IDS ATTACK SIMULATOR")
    print(f"   Target: {TARGET_IP}")
    print("=========================================")
    
    test_sql_injection()
    test_xss()
    test_command_injection()
    test_sqlmap()
    test_suspicious_ports()
    test_port_scan()
    test_syn_flood()
    
    print("\n[*] Attack simulation complete! Check your SOC Dashboard.")
