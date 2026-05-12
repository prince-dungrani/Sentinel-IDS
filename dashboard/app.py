"""
dashboard/app.py
================
Sentinel-IDS — Enterprise SOC Dashboard Backend

API Endpoints:
  GET  /                          Dashboard overview
  GET  /alerts                    Alert event monitor
  GET  /alert/<id>                Alert detail view
  GET  /threat-intel              Live attack map & threat intelligence
  GET  /rules                     Rule management
  GET  /settings                  ML settings & system config
  GET  /knowledge                 Cybersecurity knowledge center

  GET  /api/alerts                Paginated alert log
  GET  /api/stats                 Dashboard statistics
  GET  /api/intel                 IOC scores + MITRE mapping
  GET  /api/geoip                 GeoIP-enriched alerts for attack map
  GET  /api/top-countries         Attack source country aggregation
  GET  /api/system-stats          CPU / RAM / packet rate metrics

  GET  /api/ml-config             Read ML tuning parameters
  POST /api/ml-config             Write ML tuning parameters
  GET  /api/ml-stats              ML engine status and recent predictions

  GET  /api/rules                 List all detection rules
  POST /api/rules                 Create new rule
  PUT  /api/rules                 Update / toggle rule
  DEL  /api/rules/<id>            Delete rule

  GET  /api/alerts/export/csv     Export alerts as CSV
  GET  /api/alerts/export/json    Export alerts as JSON

  GET  /api/ioc                   IOC list
  POST /api/ioc/blacklist         Blacklist an IP
  POST /api/ioc/whitelist         Whitelist an IP
"""

from flask import Flask, render_template, jsonify, request, Response
from flask_cors import CORS
import sys
import os
import json
import uuid
import csv
import io
import time
import logging

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from dashboard.utils.log_reader import parse_logs, get_alert_by_id
from dashboard.utils.stats import calculate_dashboard_stats
from dashboard.utils.geoip_resolver import enrich_alert_with_geo, resolve_ip

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(name)s: %(message)s")
log = logging.getLogger("sentinel.dashboard")

app = Flask(__name__)
CORS(app)

# =========================================================
# Path Helpers
# =========================================================
def _path(relative: str) -> str:
    return os.path.join(BASE_DIR, relative)


ML_CONFIG_PATH = _path("config/ml_config.json")
RULES_PATH = _path("data/rules.json")
IOC_PATH = _path("data/ioc_list.json")


def _load_json(path: str, default=None):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return default if default is not None else {}


def _save_json(path: str, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


# =========================================================
# View Routes
# =========================================================
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


@app.route('/knowledge')
def knowledge_view():
    return render_template('knowledge.html', active_page='knowledge')


# =========================================================
# Core Data APIs
# =========================================================
@app.route('/api/alerts')
def api_alerts():
    limit = int(request.args.get('limit', 500))
    severity = request.args.get('severity', '').upper()
    protocol = request.args.get('protocol', '').upper()
    attack_type = request.args.get('attack_type', '')
    src_ip = request.args.get('src_ip', '')

    alerts = parse_logs(limit=limit * 3)  # over-fetch for filtering
    filtered = [a for a in alerts if a.get('traffic_type', '').upper() != 'NORMAL']

    if severity:
        filtered = [a for a in filtered if a.get('severity', '').upper() == severity]
    if protocol:
        filtered = [a for a in filtered if a.get('protocol', '').upper() == protocol]
    if attack_type:
        filtered = [a for a in filtered if attack_type.lower() in a.get('attack_type', '').lower()]
    if src_ip:
        filtered = [a for a in filtered if src_ip in a.get('src_ip', '')]

    return jsonify({"status": "success", "data": filtered[:limit], "total": len(filtered)})


@app.route('/api/stats')
def api_stats():
    alerts = parse_logs(limit=5000)
    stats = calculate_dashboard_stats(alerts)
    return jsonify({"status": "success", "data": stats})


@app.route('/api/intel')
def api_intel():
    alerts = parse_logs(limit=5000)
    true_alerts = [a for a in alerts if a.get('traffic_type', '').upper() != 'NORMAL']

    ip_scores = {}
    mitre_counts = {
        "Initial Access": 0, "Execution": 0, "Discovery": 0,
        "Command and Control": 0, "Exfiltration": 0,
        "Denial of Service": 0, "Lateral Movement": 0, "Impact": 0,
        "Credential Access": 0,
    }

    for a in true_alerts:
        ip = a.get('src_ip', 'Unknown')
        severity = a.get('severity', 'LOW').upper()
        risk_score = a.get('risk_score', 0)

        # Use stored risk_score if available, else compute from severity
        points = risk_score if risk_score > 0 else {"CRITICAL": 20, "HIGH": 10, "MEDIUM": 5, "LOW": 1}.get(severity, 1)
        ip_scores[ip] = ip_scores.get(ip, 0) + points

        # Use stored MITRE tactic if available
        tactic = a.get('mitre_tactic', '')
        if tactic and tactic in mitre_counts:
            mitre_counts[tactic] += 1
        else:
            # Fallback keyword mapping
            combined = f"{a.get('attack_type', '')} {a.get('rule', '')}".upper()
            if 'SQL' in combined or 'XSS' in combined:
                mitre_counts["Initial Access"] += 1
            elif 'PORT SCAN' in combined:
                mitre_counts["Discovery"] += 1
            elif 'DNS' in combined:
                mitre_counts["Command and Control"] += 1
            elif 'SYN FLOOD' in combined or 'DOS' in combined:
                mitre_counts["Impact"] += 1
            else:
                mitre_counts["Execution"] += 1

    sorted_iocs = sorted(ip_scores.items(), key=lambda x: x[1], reverse=True)[:10]
    iocs = [{"ip": k, "score": min(v, 100), "raw_score": v} for k, v in sorted_iocs]

    return jsonify({"status": "success", "data": {"iocs": iocs, "mitre": mitre_counts}})


# =========================================================
# GeoIP Attack Map API
# =========================================================
@app.route('/api/geoip')
def api_geoip():
    """Return recent alerts enriched with GeoIP for the live attack map."""
    limit = int(request.args.get('limit', 100))
    alerts = parse_logs(limit=limit * 2)
    threats = [a for a in alerts if a.get('traffic_type', '').upper() != 'NORMAL'][:limit]

    enriched = []
    for alert in threats:
        a = enrich_alert_with_geo(dict(alert))
        enriched.append({
            "id": a.get("id"),
            "src_ip": a.get("src_ip"),
            "dst_ip": a.get("dst_ip"),
            "attack_type": a.get("attack_type"),
            "severity": a.get("severity"),
            "risk_score": a.get("risk_score", 0),
            "engine": a.get("engine"),
            "timestamp": a.get("timestamp"),
            "rule": a.get("rule"),
            "lat": a.get("geo_lat"),
            "lon": a.get("geo_lon"),
            "country": a.get("geo_country"),
            "city": a.get("geo_city"),
            "country_code": a.get("geo_country_code"),
            "asn": a.get("geo_asn"),
            "isp": a.get("geo_isp"),
        })

    return jsonify({"status": "success", "data": enriched})


@app.route('/api/top-countries')
def api_top_countries():
    """Aggregate attack source countries."""
    alerts = parse_logs(limit=2000)
    threats = [a for a in alerts if a.get('traffic_type', '').upper() != 'NORMAL']
    country_counts = {}
    for a in threats:
        geo = resolve_ip(a.get("src_ip", "Unknown"))
        country = geo.get("country", "Unknown")
        country_counts[country] = country_counts.get(country, 0) + 1

    sorted_countries = sorted(country_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    return jsonify({
        "status": "success",
        "data": [{"country": c, "count": n} for c, n in sorted_countries]
    })


# =========================================================
# System Metrics API
# =========================================================
@app.route('/api/system-stats')
def api_system_stats():
    """Return CPU, RAM, and packet metrics via psutil."""
    try:
        import psutil  # type: ignore
        cpu = psutil.cpu_percent(interval=0.1)
        ram = psutil.virtual_memory()
        net = psutil.net_io_counters()
        return jsonify({
            "status": "success",
            "data": {
                "cpu_percent": cpu,
                "ram_percent": ram.percent,
                "ram_used_gb": round(ram.used / 1e9, 2),
                "ram_total_gb": round(ram.total / 1e9, 2),
                "net_bytes_sent": net.bytes_sent,
                "net_bytes_recv": net.bytes_recv,
                "net_packets_sent": net.packets_sent,
                "net_packets_recv": net.packets_recv,
                "timestamp": int(time.time()),
            }
        })
    except ImportError:
        return jsonify({"status": "error", "message": "psutil not installed", "data": {
            "cpu_percent": 0, "ram_percent": 0, "timestamp": int(time.time())
        }})


# =========================================================
# ML Configuration API
# =========================================================
@app.route('/api/ml-config', methods=['GET', 'POST'])
def api_ml_config():
    if request.method == 'GET':
        config = _load_json(ML_CONFIG_PATH, {
            "alpha": 0.6, "beta": 0.4,
            "anomaly_threshold": 0.5, "confidence_threshold": 0.65,
            "sensitivity": "medium", "ml_enabled": True,
            "top_features_count": 5
        })
        return jsonify({"status": "success", "data": config})

    elif request.method == 'POST':
        try:
            new_config = request.json
            # Validate numeric bounds
            for k in ["alpha", "beta", "anomaly_threshold", "confidence_threshold"]:
                if k in new_config:
                    new_config[k] = max(0.0, min(1.0, float(new_config[k])))
            _save_json(ML_CONFIG_PATH, new_config)
            return jsonify({"status": "success", "message": "ML config updated. Hot-reload active."})
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/ml-stats')
def api_ml_stats():
    """Return ML engine status information."""
    try:
        from core.ml_engine import get_engine
        engine = get_engine()
        return jsonify({
            "status": "success",
            "data": {
                "ml_enabled": engine.enabled,
                "rf_loaded": engine.rf_model is not None,
                "iso_loaded": engine.iso_model is not None,
                "scaler_loaded": engine.scaler is not None,
                "config": engine.config,
            }
        })
    except Exception as e:
        return jsonify({"status": "success", "data": {
            "ml_enabled": False, "rf_loaded": False,
            "iso_loaded": False, "scaler_loaded": False, "config": {}
        }})


# =========================================================
# Rules API
# =========================================================
@app.route('/api/rules', methods=['GET', 'POST', 'PUT'])
def api_rules():
    if request.method == 'GET':
        try:
            rules = _load_json(RULES_PATH, [])
            for r in rules:
                if 'id' not in r:
                    r['id'] = str(uuid.uuid4())
            return jsonify({"status": "success", "data": rules})
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

    elif request.method == 'POST':
        try:
            new_rule = request.json
            new_rule['id'] = str(uuid.uuid4())
            new_rule['status'] = 'enabled'
            rules = _load_json(RULES_PATH, [])
            rules.append(new_rule)
            _save_json(RULES_PATH, rules)
            return jsonify({"status": "success", "message": "Rule added"})
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

    elif request.method == 'PUT':
        try:
            update_data = request.json
            rule_id = update_data.get('id')
            rules = _load_json(RULES_PATH, [])
            for rule in rules:
                if rule.get('id') == rule_id:
                    rule.update({k: v for k, v in update_data.items() if k != 'id'})
                    break
            _save_json(RULES_PATH, rules)
            return jsonify({"status": "success", "message": "Rule updated"})
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/rules/<rule_id>', methods=['DELETE'])
def api_delete_rule(rule_id):
    try:
        rules = _load_json(RULES_PATH, [])
        rules = [r for r in rules if r.get('id') != rule_id]
        _save_json(RULES_PATH, rules)
        return jsonify({"status": "success", "message": "Rule deleted"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# =========================================================
# Export APIs
# =========================================================
@app.route('/api/alerts/export/csv')
def export_csv():
    alerts = parse_logs(limit=5000)
    threats = [a for a in alerts if a.get('traffic_type', '').upper() != 'NORMAL']
    output = io.StringIO()
    if threats:
        fieldnames = ["id", "timestamp", "severity", "attack_type", "src_ip",
                      "dst_ip", "dst_port", "protocol", "rule", "engine", "risk_score"]
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(threats)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=sentinel_alerts.csv"}
    )


@app.route('/api/alerts/export/json')
def export_json():
    alerts = parse_logs(limit=5000)
    threats = [a for a in alerts if a.get('traffic_type', '').upper() != 'NORMAL']
    return Response(
        json.dumps(threats, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": "attachment;filename=sentinel_alerts.json"}
    )


# =========================================================
# IOC Management API
# =========================================================
def _load_ioc():
    return _load_json(IOC_PATH, {"blacklist": [], "whitelist": []})


@app.route('/api/ioc', methods=['GET'])
def api_ioc():
    return jsonify({"status": "success", "data": _load_ioc()})


@app.route('/api/ioc/blacklist', methods=['POST'])
def api_blacklist():
    ip = request.json.get("ip")
    ioc = _load_ioc()
    if ip and ip not in ioc["blacklist"]:
        ioc["blacklist"].append(ip)
        ioc["whitelist"] = [x for x in ioc["whitelist"] if x != ip]
        _save_json(IOC_PATH, ioc)
    return jsonify({"status": "success", "message": f"{ip} blacklisted"})


@app.route('/api/ioc/whitelist', methods=['POST'])
def api_whitelist():
    ip = request.json.get("ip")
    ioc = _load_ioc()
    if ip and ip not in ioc["whitelist"]:
        ioc["whitelist"].append(ip)
        ioc["blacklist"] = [x for x in ioc["blacklist"] if x != ip]
        _save_json(IOC_PATH, ioc)
    return jsonify({"status": "success", "message": f"{ip} whitelisted"})


@app.route('/api/ioc/<ip>', methods=['DELETE'])
def api_remove_ioc(ip):
    ioc = _load_ioc()
    ioc["blacklist"] = [x for x in ioc["blacklist"] if x != ip]
    ioc["whitelist"] = [x for x in ioc["whitelist"] if x != ip]
    _save_json(IOC_PATH, ioc)
    return jsonify({"status": "success", "message": f"{ip} removed from IOC list"})


# =========================================================
# Application Entry Point
# =========================================================
if __name__ == '__main__':
    log.info("🛡️  Sentinel-IDS SOC Dashboard starting on http://0.0.0.0:5000")
    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)
