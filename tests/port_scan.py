from scapy.all import *

for port in range(1,100):

    send(
        IP(dst="TARGET_IP")/
        TCP(dport=port, flags="S")
    )