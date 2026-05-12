from collections import Counter

def calculate_dashboard_stats(alerts):
    """
    Calculates summary statistics. Normal traffic is filtered out from 
    main alert metrics to maintain SOC realism.
    """
    
    # Filter out NORMAL traffic for true alerts
    true_alerts = [a for a in alerts if a.get('traffic_type', '').upper() != 'NORMAL']
    
    total_alerts = len(true_alerts)
    critical_alerts = sum(1 for a in true_alerts if a.get('severity', '').upper() in ['HIGH', 'CRITICAL'])
    
    # Calculate Attack Type Distribution
    attack_types = [a.get('attack_type', 'Unknown') for a in true_alerts]
    type_counts = dict(Counter(attack_types))
    
    # Calculate Top Attacker IPs
    src_ips = [a.get('src_ip', 'Unknown') for a in true_alerts]
    ip_counts = dict(Counter(src_ips).most_common(5))
    
    # Calculate Protocol Distribution
    protocols = [a.get('protocol', 'Unknown') for a in true_alerts]
    protocol_counts = dict(Counter(protocols))
    
    # Calculate Severity Distribution for new charts
    severities = [a.get('severity', 'LOW') for a in true_alerts]
    severity_counts = dict(Counter(severities))

    # Simulate or aggregate Live Metrics for dashboard realism
    # In a fully integrated system, these come from a shared memory block with main.py
    simulated_packets = 245000 + (len(alerts) * 15)
    simulated_connections = max(12, len(set([a.get('src_ip') for a in alerts[:100]])))

    return {
        "total_alerts": total_alerts,
        "critical_alerts": critical_alerts,
        "active_connections": simulated_connections,
        "packets_processed": f"{simulated_packets:,}",
        "type_distribution": type_counts,
        "top_ips": ip_counts,
        "protocol_distribution": protocol_counts,
        "severity_distribution": severity_counts
    }
