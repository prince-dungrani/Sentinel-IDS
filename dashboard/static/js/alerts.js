let allAlerts = [];

document.addEventListener("DOMContentLoaded", function() {
    fetchAlerts();
    
    // Auto refresh every 5 seconds
    setInterval(fetchAlerts, 5000);
    
    // Setup event listeners for filtering
    document.getElementById("tableSearch").addEventListener("keyup", renderTable);
    document.getElementById("severityFilter").addEventListener("change", renderTable);
});

function fetchAlerts() {
    fetch('/api/alerts')
        .then(response => response.json())
        .then(res => {
            if(res.status === 'success') {
                allAlerts = res.data;
                renderTable();
            }
        })
        .catch(err => console.error("Error fetching alerts:", err));
}

function getSeverityBadge(severity) {
    const s = severity.toUpperCase();
    if(s === 'HIGH' || s === 'CRITICAL') return `<span class="badge badge-high"><i class="fa-solid fa-fire me-1"></i>${s}</span>`;
    if(s === 'MEDIUM') return `<span class="badge badge-medium">${s}</span>`;
    return `<span class="badge badge-low">${s}</span>`;
}

function renderTable() {
    const tbody = document.getElementById("alertsTableBody");
    const searchTerm = document.getElementById("tableSearch").value.toLowerCase();
    const severityFilter = document.getElementById("severityFilter").value;
    
    tbody.innerHTML = '';
    
    if(allAlerts.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="text-center py-4 text-light">No alerts found in active log file.</td></tr>`;
        return;
    }
    
    let displayedCount = 0;
    
    for(let i=0; i<allAlerts.length; i++) {
        const alert = allAlerts[i];
        
        // Filtering Logic
        if(severityFilter !== 'ALL' && alert.severity.toUpperCase() !== severityFilter) continue;
        
        const searchString = `${alert.src_ip} ${alert.dst_ip} ${alert.message} ${alert.protocol}`.toLowerCase();
        if(searchTerm && !searchString.includes(searchTerm)) continue;
        
        // Create Row
        const tr = document.createElement("tr");
        tr.innerHTML = `
            <td class="ps-3 text-light small">${alert.timestamp}</td>
            <td>${getSeverityBadge(alert.severity)}</td>
            <td class="fw-bold text-light">${alert.attack_type || alert.rule || 'Unknown'}</td>
            <td class="font-monospace text-info">${alert.src_ip}:${alert.dst_port || '*'}</td>
            <td class="font-monospace text-light">${alert.dst_ip}</td>
            <td><span class="badge bg-secondary bg-opacity-25 text-light border border-secondary">${alert.protocol}</span></td>
            <td class="text-center">
                <a href="/alert/${alert.id}" class="btn btn-sm btn-outline-info rounded-circle" title="View Details">
                    <i class="fa-solid fa-eye"></i>
                </a>
            </td>
        `;
        tbody.appendChild(tr);
        displayedCount++;
    }
    
    if(displayedCount === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="text-center py-4 text-light">No alerts match your filter criteria.</td></tr>`;
    }
}
