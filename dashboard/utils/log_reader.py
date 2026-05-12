import json
import os
import datetime
import uuid

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))

def get_log_file_path():
    config_path = os.path.join(BASE_DIR, 'config', 'config.json')
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
            rel_path = config.get('log_file', 'logs/alerts.json')
            return os.path.join(BASE_DIR, rel_path)
    except Exception:
        return os.path.join(BASE_DIR, 'logs', 'alerts.json')

def parse_logs(limit=1000):
    log_path = get_log_file_path()
    fallback_path = log_path + '.5'
    
    alerts = []
    file_to_read = log_path
    
    if not os.path.exists(file_to_read) or os.path.getsize(file_to_read) == 0:
        if os.path.exists(fallback_path):
            file_to_read = fallback_path
        else:
            return []

    try:
        with open(file_to_read, 'r') as f:
            lines = f.readlines()
            
            for line in reversed(lines):
                if len(alerts) >= limit:
                    break
                    
                line = line.strip()
                if not line: continue
                    
                try:
                    alert = json.loads(line)
                    
                    # --- Backward Compatibility for Old Logs ---
                    if 'id' not in alert:
                        alert['id'] = f"ALERT-{str(uuid.uuid4())[:8].upper()}"
                    if 'timestamp' not in alert:
                        alert['timestamp'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    if 'traffic_type' not in alert:
                        alert['traffic_type'] = "SUSPICIOUS" if alert.get("severity", "LOW").upper() != "LOW" else "NORMAL"
                    if 'attack_type' not in alert:
                        alert['attack_type'] = alert.get("message", "Unknown Event")
                    if 'dst_ip' not in alert:
                        alert['dst_ip'] = "Unknown"
                    if 'src_port' not in alert:
                        alert['src_port'] = "*"
                    if 'protocol' not in alert:
                        port = alert.get('dst_port', 0)
                        if port == 443: alert['protocol'] = "TCP"
                        elif port == 80: alert['protocol'] = "TCP"
                        else: alert['protocol'] = "Unknown"
                    if 'status' not in alert:
                        alert['status'] = "ACTIVE"
                    if 'engine' not in alert:
                        alert['engine'] = "Legacy System"
                    if 'rule' not in alert:
                        alert['rule'] = alert.get("message", "N/A")
                    if 'payload_preview' not in alert:
                        alert['payload_preview'] = "No payload recorded."
                    if 'flags' not in alert:
                        alert['flags'] = ""
                    if 'packet_size' not in alert:
                        alert['packet_size'] = 0
                        
                    alerts.append(alert)
                except json.JSONDecodeError:
                    pass
                    
        return alerts
    except Exception as e:
        print(f"Error reading logs: {e}")
        return []

def get_alert_by_id(alert_id):
    """Fetch a specific alert by its ID for the details page."""
    alerts = parse_logs(limit=5000)
    for alert in alerts:
        if alert.get("id") == alert_id:
            return alert
    return None
