document.addEventListener("DOMContentLoaded", function() {
    fetchIntel();
    setInterval(fetchIntel, 5000);
});

function fetchIntel() {
    fetch('/api/intel')
        .then(res => res.json())
        .then(data => {
            if(data.status === 'success') {
                updateIOCs(data.data.iocs);
                updateMitre(data.data.mitre);
            }
        });
}

function updateIOCs(iocs) {
    const list = document.getElementById("iocList");
    list.innerHTML = '';
    
    if(iocs.length === 0) {
        list.innerHTML = '<li class="list-group-item bg-transparent text-light border-secondary text-center py-4">No active threats detected yet.</li>';
        return;
    }
    
    iocs.forEach(ioc => {
        let badgeClass = 'bg-success';
        let textClass = 'text-info';
        
        if(ioc.score > 70) { badgeClass = 'bg-danger'; textClass = 'text-danger'; }
        else if(ioc.score > 40) { badgeClass = 'bg-warning text-dark'; textClass = 'text-warning'; }
        
        const li = document.createElement('li');
        li.className = "list-group-item bg-transparent text-light border-secondary d-flex justify-content-between align-items-center";
        li.innerHTML = `
            <div>
                <span class="${textClass} fw-bold font-monospace">${ioc.ip}</span>
                <div class="small text-light">Aggregated Threat IP</div>
            </div>
            <span class="badge ${badgeClass}">Score: ${ioc.score}/100</span>
        `;
        list.appendChild(li);
    });
}

function updateMitre(mitreData) {
    const list = document.getElementById("mitreList");
    list.innerHTML = '';
    
    const categories = [
        { name: "Initial Access (TA0001)", key: "Initial Access" },
        { name: "Execution (TA0002)", key: "Execution" },
        { name: "Discovery (TA0007)", key: "Discovery" },
        { name: "Command and Control (TA0011)", key: "Command and Control" },
        { name: "Denial of Service (TA0049)", key: "Denial of Service" }
    ];
    
    categories.forEach(cat => {
        const count = mitreData[cat.key] || 0;
        let badge = '<span class="badge bg-success text-light fw-bold">Low Risk</span>';
        
        if(count > 10) badge = '<span class="badge bg-danger text-light fw-bold">High Risk</span>';
        else if(count > 0) badge = '<span class="badge bg-warning text-dark fw-bold">Medium Risk</span>';
        
        const div = document.createElement('div');
        div.className = "d-flex justify-content-between mb-3 border-bottom border-secondary pb-2";
        div.innerHTML = `
            <span class="text-light">${cat.name} <span class="text-light small ms-2">(${count} hits)</span></span>
            ${badge}
        `;
        list.appendChild(div);
    });
}
