from scapy.all import *

for i in range(100):

    send(
        IP(dst="TARGET_IP")/
        TCP(dport=80, flags="S")
    )