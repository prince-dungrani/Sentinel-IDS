import os
import time
import json
import re
import uuid
from datetime import datetime
from collections import defaultdict

RULES_FILE = "data/rules.json"
SURICATA_FILE = "data/suricata.rules"

RULES = []
last_rules_mtime = 0

def load_suricata_rules(filepath=SURICATA_FILE):
    global RULES
    if not os.path.exists(filepath):
        return
        
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
                
            try:
                header, options = line.split("(", 1)
                options = options.rstrip(")")
                
                parts = header.split()
                if len(parts) < 7: continue
                
                protocol = parts[1].upper()
                dst_port_str = parts[6]
                
                rule = {
                    "name": "Suricata Rule",
                    "severity": "HIGH",
                    "group": "Suricata",
                    "protocol": protocol,
                    "threshold": 1,
                    "status": "enabled"
                }
                
                if dst_port_str.isdigit():
                    rule["port"] = int(dst_port_str)
                    
                opt_pairs = options.split(";")
                for opt in opt_pairs:
                    opt = opt.strip()
                    if not opt: continue
                    
                    if ":" in opt:
                        key, val = opt.split(":", 1)
                        key = key.strip()
                        val = val.strip().strip('"')
                        
                        if key == "msg":
                            rule["name"] = val
                        elif key == "content":
                            rule["content"] = val
                        elif key == "sid":
                            rule["sid"] = val
                    elif opt == "nocase":
                        rule["nocase"] = True
                        
                RULES.append(rule)
            except Exception as e:
                pass

def reload_rules_if_needed():
    global RULES, last_rules_mtime
    try:
        current_mtime = os.path.getmtime(RULES_FILE)
        if current_mtime > last_rules_mtime:
            with open(RULES_FILE) as f:
                loaded_rules = json.load(f)
                RULES = [r for r in loaded_rules if r.get("status", "enabled").lower() != "disabled"]
            load_suricata_rules()
            last_rules_mtime = current_mtime
            print("[*] Rules dynamically reloaded by Engine.")
    except Exception as e:
        # Ignore if file is temporarily inaccessible
        pass

# Flow tracking
packet_count = defaultdict(int)
port_access = defaultdict(set)
last_seen = defaultdict(float)

rule_hits = defaultdict(int)

TIME_WINDOW = 10
DDOS_THRESHOLD = 20
PORT_SCAN_THRESHOLD = 10
SUSPICIOUS_PORTS = [22, 23, 445]

def match_rule(features, rule):
    protocol = features.get("protocol")
    dst_port = features.get("dst_port")

    if rule.get("protocol") and protocol != rule["protocol"]:
        return False

    if "port" in rule and dst_port != rule["port"]:
        return False

    if "ports" in rule and dst_port not in rule["ports"]:
        return False

    target_field = rule.get("field", "payload")

    if target_field == "payload" and "reassembled_payload" in features:
        value = str(features["reassembled_payload"])
    else:
        value = str(features.get(target_field, ""))

    if "content" in rule:
        if rule.get("nocase"):
            if rule["content"].lower() not in value.lower():
                return False
        else:
            if rule["content"] not in value:
                return False

    if "regex" in rule:
        if not re.search(rule["regex"], value):
            return False

    if "length_gt" in rule:
        if len(value) <= rule["length_gt"]:
            return False

    return True

def create_alert_obj(features, attack_type, severity, rule_name, engine):
    """Generates the professional JSON logging structure."""
    
    payload = str(features.get("payload", ""))
    payload_preview = payload[:100] + "..." if len(payload) > 100 else payload

    return {
        "id": f"ALERT-{str(uuid.uuid4())[:8].upper()}",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "traffic_type": "MALICIOUS" if severity.upper() in ["HIGH", "CRITICAL"] else "SUSPICIOUS",
        "attack_type": attack_type,
        "severity": severity,
        "src_ip": features.get("src_ip", "Unknown"),
        "dst_ip": features.get("dst_ip", "Unknown"),
        "src_port": features.get("src_port", "*"),
        "dst_port": features.get("dst_port", "*"),
        "protocol": features.get("protocol", "Unknown"),
        "packet_size": features.get("packet_size", len(payload)),
        "flags": features.get("flags", ""),
        "status": "ACTIVE",
        "rule": rule_name,
        "payload_preview": payload_preview,
        "engine": engine
    }

def detect(features):
    alerts = []
    reload_rules_if_needed()

    src_ip = features.get("src_ip")
    dst_port = features.get("dst_port")
    current_time = time.time()
    flags = features.get("flags", "")

    if current_time - last_seen[src_ip] > TIME_WINDOW:
        packet_count[src_ip] = 0
        port_access[src_ip].clear()

    last_seen[src_ip] = current_time
    packet_count[src_ip] += 1
    if dst_port:
        port_access[src_ip].add(dst_port)

    # 1. RULE ENGINE
    for rule in RULES:
        if match_rule(features, rule):
            rule_hits[rule["name"]] += 1
            if rule_hits[rule["name"]] >= rule.get("threshold", 1):
                alerts.append(create_alert_obj(
                    features, 
                    rule["group"], 
                    rule["severity"], 
                    rule["name"], 
                    "Signature Engine"
                ))

    # 2. FLOW DETECTION
    if packet_count[src_ip] > DDOS_THRESHOLD and flags == "S":
        alerts.append(create_alert_obj(
            features, "SYN Flood", "HIGH", "Possible SYN Flood", "Heuristic Engine"
        ))

    if len(port_access[src_ip]) > PORT_SCAN_THRESHOLD:
        alerts.append(create_alert_obj(
            features, "Port Scan", "MEDIUM", "Possible Port Scan", "Heuristic Engine"
        ))

    if dst_port in SUSPICIOUS_PORTS:
        alerts.append(create_alert_obj(
            features, "Suspicious Access", "HIGH", f"Access to port {dst_port}", "Heuristic Engine"
        ))

    if dst_port == 53:
        query = features.get("dns_query", "")
        if len(query) > 50:
            alerts.append(create_alert_obj(
                features, "DNS Tunneling", "MEDIUM", "Possible DNS Tunneling", "Heuristic Engine"
            ))

    return alerts