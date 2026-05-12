from flask import Flask, render_template, jsonify, request
import sys
import os
import json
import uuid

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from dashboard.utils.log_reader import parse_logs, get_alert_by_id
from dashboard.utils.stats import calculate_dashboard_stats

app = Flask(__name__)

# --- View Routes ---

@app.route('/')
def dashboard_overview():
    return render_template('dashboard.html', active_page='dashboard')

@app.route('/alerts')
def alerts_view():
    return render_template('alerts.html', active_page='alerts')

@app.route('/alert/<alert_id>')
def alert_detail(alert_id):
    alert = get_alert_by_id(alert_id)
    if not alert:
        return "Alert not found", 404
    return render_template('alert_detail.html', active_page='alerts', alert=alert)

@app.route('/threat-intel')
def threat_intel_view():
    return render_template('threat_intel.html', active_page='intel')

@app.route('/rules')
def rules_view():
    return render_template('rules.html', active_page='rules')

@app.route('/settings')
def settings_view():
    return render_template('settings.html', active_page='settings')


# --- API Routes ---

@app.route('/api/alerts')
def api_alerts():
    # Fetch logs but only return SUSPICIOUS/MALICIOUS to the main table
    alerts = parse_logs(limit=1000)
    filtered = [a for a in alerts if a.get('traffic_type', '').upper() != 'NORMAL']
    return jsonify({"status": "success", "data": filtered})

@app.route('/api/stats')
def api_stats():
    alerts = parse_logs(limit=5000)
    stats = calculate_dashboard_stats(alerts)
    return jsonify({"status": "success", "data": stats})

@app.route('/api/intel')
def api_intel():
    alerts = parse_logs(limit=5000)
    true_alerts = [a for a in alerts if a.get('traffic_type', '').upper() != 'NORMAL']
    
    # Calculate IOC scores based on frequency and severity
    ip_scores = {}
    mitre_counts = {
        "Initial Access": 0,
        "Execution": 0,
        "Discovery": 0,
        "Command and Control": 0,
        "Exfiltration": 0,
        "Denial of Service": 0
    }
    
    for a in true_alerts:
        ip = a.get('src_ip', 'Unknown')
        severity = a.get('severity', 'LOW').upper()
        
        # Calculate IP Threat Score
        points = 1
        if severity == 'MEDIUM': points = 5
        if severity == 'HIGH': points = 10
        if severity == 'CRITICAL': points = 20
        
        ip_scores[ip] = ip_scores.get(ip, 0) + points
        
        # Calculate MITRE mappings
        attack_type = a.get('attack_type', '').upper()
        rule = a.get('rule', '').upper()
        
        if 'SQL' in attack_type or 'SQL' in rule or 'XSS' in attack_type or 'COMMAND' in rule:
            mitre_counts["Initial Access"] += 1
        elif 'PORT SCAN' in attack_type or 'PORT SCAN' in rule or 'SUSPICIOUS ACCESS' in rule:
            mitre_counts["Discovery"] += 1
        elif 'DNS TUNNELING' in attack_type or 'TUNNELING' in rule:
            mitre_counts["Command and Control"] += 1
        elif 'SYN FLOOD' in attack_type or 'DOS' in rule:
            mitre_counts["Denial of Service"] += 1
        else:
            mitre_counts["Execution"] += 1
            
    # Sort IOCs by score
    sorted_iocs = sorted(ip_scores.items(), key=lambda x: x[1], reverse=True)[:5]
    
    # Format for JSON
    iocs = [{"ip": k, "score": min(v, 100), "raw_score": v} for k, v in sorted_iocs]
    
    return jsonify({
        "status": "success",
        "data": {
            "iocs": iocs,
            "mitre": mitre_counts
        }
    })

# --- Rules API ---

def get_rules_path():
    return os.path.join(BASE_DIR, 'data', 'rules.json')

@app.route('/api/rules', methods=['GET', 'POST', 'PUT'])
def api_rules():
    rules_path = get_rules_path()
    
    if request.method == 'GET':
        try:
            with open(rules_path, 'r') as f:
                rules = json.load(f)
            # Ensure all rules have IDs for frontend manipulation
            for r in rules:
                if 'id' not in r:
                    r['id'] = str(uuid.uuid4())
            return jsonify({"status": "success", "data": rules})
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

    elif request.method == 'POST':
        # Add new rule
        try:
            new_rule = request.json
            new_rule['id'] = str(uuid.uuid4())
            new_rule['status'] = 'enabled'
            
            with open(rules_path, 'r') as f:
                rules = json.load(f)
            
            rules.append(new_rule)
            
            with open(rules_path, 'w') as f:
                json.dump(rules, f, indent=2)
                
            return jsonify({"status": "success", "message": "Rule added"})
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

    elif request.method == 'PUT':
        # Toggle rule enable/disable or update
        try:
            update_data = request.json
            rule_id = update_data.get('id')
            
            with open(rules_path, 'r') as f:
                rules = json.load(f)
                
            for rule in rules:
                if rule.get('id') == rule_id:
                    if 'status' in update_data:
                        rule['status'] = update_data['status']
                    # Could update other fields here
                    break
                    
            with open(rules_path, 'w') as f:
                json.dump(rules, f, indent=2)
                
            return jsonify({"status": "success", "message": "Rule updated"})
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/rules/<rule_id>', methods=['DELETE'])
def api_delete_rule(rule_id):
    rules_path = get_rules_path()
    try:
        with open(rules_path, 'r') as f:
            rules = json.load(f)
            
        rules = [r for r in rules if r.get('id') != rule_id]
        
        with open(rules_path, 'w') as f:
            json.dump(rules, f, indent=2)
            
        return jsonify({"status": "success", "message": "Rule deleted"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


if __name__ == '__main__':
    print("Starting Advanced SOC Platform...")
    app.run(host='0.0.0.0', port=5000, debug=True)
