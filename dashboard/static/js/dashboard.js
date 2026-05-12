// Chart.js global config for Dark Theme
Chart.defaults.color = '#94a3b8';
Chart.defaults.borderColor = '#2d3748';

let attackPieChart, topIpsChart, protocolChart;

document.addEventListener("DOMContentLoaded", function() {
    initCharts();
    fetchStats();
    // Refresh stats every 10 seconds
    setInterval(fetchStats, 10000);
});

function initCharts() {
    // 1. Attack Pie Chart
    const pieCtx = document.getElementById("attackPieChart");
    if(pieCtx) {
        attackPieChart = new Chart(pieCtx, {
            type: 'doughnut',
            data: { labels: [], datasets: [{ data: [], backgroundColor: ['#ef4444', '#f59e0b', '#3b82f6', '#10b981', '#8b5cf6'], borderWidth: 0 }] },
            options: { maintainAspectRatio: false, cutout: '75%', plugins: { legend: { position: 'right' } } }
        });
    }

    // 2. Top IPs Bar Chart
    const barCtx = document.getElementById("topIpsChart");
    if(barCtx) {
        topIpsChart = new Chart(barCtx, {
            type: 'bar',
            data: { labels: [], datasets: [{ label: 'Alerts', data: [], backgroundColor: '#3b82f6' }] },
            options: { maintainAspectRatio: false, scales: { y: { beginAtZero: true } }, plugins: { legend: { display: false } } }
        });
    }

    // 3. Protocol Doughnut Chart
    const protCtx = document.getElementById("protocolChart");
    if(protCtx) {
        protocolChart = new Chart(protCtx, {
            type: 'pie',
            data: { labels: [], datasets: [{ data: [], backgroundColor: ['#0ea5e9', '#6366f1', '#ec4899', '#f97316'], borderWidth: 0 }] },
            options: { maintainAspectRatio: false, plugins: { legend: { position: 'bottom' } } }
        });
    }
}

function fetchStats() {
    fetch('/api/stats')
        .then(response => response.json())
        .then(res => {
            if(res.status === 'success') {
                updateDashboard(res.data);
            }
        })
        .catch(err => console.error("Error fetching stats:", err));
}

function updateDashboard(data) {
    // Update top cards
    document.getElementById('metric-total-alerts').innerText = data.total_alerts.toLocaleString();
    document.getElementById('metric-critical-alerts').innerText = data.critical_alerts.toLocaleString();
    document.getElementById('metric-connections').innerText = data.active_connections;
    document.getElementById('metric-packets').innerText = "Packets: " + data.packets_processed;

    // Update Attack Distribution Chart
    if(attackPieChart && Object.keys(data.type_distribution).length > 0) {
        attackPieChart.data.labels = Object.keys(data.type_distribution);
        attackPieChart.data.datasets[0].data = Object.values(data.type_distribution);
        attackPieChart.update();
    }

    // Update Top IPs Chart
    if(topIpsChart && Object.keys(data.top_ips).length > 0) {
        topIpsChart.data.labels = Object.keys(data.top_ips);
        topIpsChart.data.datasets[0].data = Object.values(data.top_ips);
        topIpsChart.update();
    }

    // Update Protocol Chart
    if(protocolChart && Object.keys(data.protocol_distribution).length > 0) {
        protocolChart.data.labels = Object.keys(data.protocol_distribution);
        protocolChart.data.datasets[0].data = Object.values(data.protocol_distribution);
        protocolChart.update();
    }
}
