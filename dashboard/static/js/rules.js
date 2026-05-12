document.addEventListener("DOMContentLoaded", function() {
    fetchRules();
});

function fetchRules() {
    fetch('/api/rules')
        .then(res => res.json())
        .then(data => {
            if(data.status === 'success') {
                renderRulesTable(data.data);
            }
        });
}

function getSeverityBadge(severity) {
    const s = severity.toUpperCase();
    if(s === 'HIGH' || s === 'CRITICAL') return `<span class="badge badge-high"><i class="fa-solid fa-fire me-1"></i>${s}</span>`;
    if(s === 'MEDIUM') return `<span class="badge badge-medium">${s}</span>`;
    return `<span class="badge badge-low">${s}</span>`;
}

function renderRulesTable(rules) {
    const tbody = document.getElementById("rulesTableBody");
    tbody.innerHTML = '';
    
    if(rules.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="text-center py-4 text-light">No rules configured.</td></tr>`;
        return;
    }
    
    rules.forEach(rule => {
        const isEnabled = rule.status !== 'disabled';
        const statusBadge = isEnabled 
            ? `<span class="badge bg-success bg-opacity-25 text-success border border-success"><i class="fa-solid fa-check"></i> Enabled</span>`
            : `<span class="badge bg-secondary bg-opacity-25 text-light border border-secondary"><i class="fa-solid fa-ban"></i> Disabled</span>`;
            
        const toggleIcon = isEnabled ? 'fa-toggle-on text-success' : 'fa-toggle-off text-secondary';
        
        const tr = document.createElement("tr");
        tr.innerHTML = `
            <td>${statusBadge}</td>
            <td class="fw-bold text-light">${rule.name}</td>
            <td>${getSeverityBadge(rule.severity || 'LOW')}</td>
            <td><span class="badge bg-dark border border-secondary">${rule.group || 'Custom'}</span></td>
            <td><span class="badge bg-secondary bg-opacity-25 text-light border border-secondary">${rule.protocol || 'ANY'}</span></td>
            <td class="font-monospace text-light">${rule.port || rule.ports || 'ANY'}</td>
            <td class="text-center">
                <div class="btn-group">
                    <button class="btn btn-sm btn-outline-secondary" onclick="toggleRule('${rule.id}', '${isEnabled ? 'disabled' : 'enabled'}')" title="${isEnabled ? 'Disable' : 'Enable'}">
                        <i class="fa-solid ${toggleIcon}"></i>
                    </button>
                    <button class="btn btn-sm btn-outline-danger" onclick="deleteRule('${rule.id}')" title="Delete Rule">
                        <i class="fa-solid fa-trash"></i>
                    </button>
                </div>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

function saveRule() {
    const name = document.getElementById("ruleName").value;
    const group = document.getElementById("ruleGroup").value;
    const severity = document.getElementById("ruleSeverity").value;
    const protocol = document.getElementById("ruleProtocol").value;
    const port = document.getElementById("rulePort").value;
    const content = document.getElementById("ruleContent").value;
    
    if(!name) {
        alert("Rule Name is required");
        return;
    }
    
    const ruleData = {
        name: name,
        group: group,
        severity: severity,
        protocol: protocol,
        field: "payload"
    };
    
    if(port) ruleData.port = parseInt(port);
    if(content) ruleData.content = content;
    
    fetch('/api/rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(ruleData)
    })
    .then(res => res.json())
    .then(data => {
        if(data.status === 'success') {
            const modalEl = document.getElementById('addRuleModal');
            const modal = bootstrap.Modal.getInstance(modalEl);
            modal.hide();
            
            document.getElementById("addRuleForm").reset();
            fetchRules();
        } else {
            alert("Error saving rule: " + data.message);
        }
    });
}

function deleteRule(id) {
    if(confirm("Are you sure you want to delete this rule? The engine will hot-reload immediately.")) {
        fetch(`/api/rules/${id}`, { method: 'DELETE' })
        .then(res => res.json())
        .then(data => {
            if(data.status === 'success') fetchRules();
        });
    }
}

function toggleRule(id, newStatus) {
    fetch('/api/rules', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: id, status: newStatus })
    })
    .then(res => res.json())
    .then(data => {
        if(data.status === 'success') fetchRules();
    });
}
