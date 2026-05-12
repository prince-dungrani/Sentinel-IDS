/**
 * dashboard/static/js/alerts.js
 * ================================
 * Sentinel-IDS — Enterprise Event Monitor
 *
 * Features: Live polling, multi-filter, risk bar, engine badges,
 * CSV/JSON export, toast notifications on new critical alerts.
 */

(function () {
    "use strict";

    const POLL_INTERVAL = 3000;
    let allAlerts = [];
    let prevAlertCount = 0;
    let isFirstLoad = true;

    // =========================================================
    // Severity → badge class
    // =========================================================
    function sevClass(severity) {
        const s = (severity || "").toUpperCase();
        if (s === "CRITICAL") return "sev-critical";
        if (s === "HIGH") return "sev-high";
        if (s === "MEDIUM") return "sev-medium";
        if (s === "LOW") return "sev-low";
        return "sev-info";
    }

    // =========================================================
    // Engine → badge class
    // =========================================================
    function engineClass(engine) {
        if (!engine) return "engine-sig";
        if (engine.toLowerCase().includes("signature")) return "engine-sig";
        if (engine.toLowerCase().includes("heuristic")) return "engine-heu";
        if (engine.toLowerCase().includes("ml")) return "engine-ml";
        return "engine-sig";
    }

    // =========================================================
    // Risk bar HTML
    // =========================================================
    function riskBar(score) {
        const s = parseInt(score) || 0;
        const color = s >= 80 ? "#dc2626" : s >= 60 ? "#f97316" : s >= 40 ? "#f59e0b" : "#3b82f6";
        return `
            <div class="risk-bar-container">
                <div class="risk-bar-bg"><div class="risk-bar-fill" style="width:${s}%;background:${color};"></div></div>
                <span class="risk-score-text" style="color:${color};">${s}</span>
            </div>
        `;
    }

    // =========================================================
    // Render Table
    // =========================================================
    function renderTable(alerts) {
        const tbody = document.getElementById("alertsTableBody");
        if (!tbody) return;

        if (alerts.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="10" style="text-align:center;padding:40px;color:var(--text-secondary);">
                        <i class="fa-solid fa-shield-check" style="font-size:28px;margin-bottom:10px;display:block;color:var(--accent-green);opacity:0.5;"></i>
                        No threats detected matching current filters
                    </td>
                </tr>`;
            return;
        }

        tbody.innerHTML = alerts.map((a) => {
            const mlBadge = a.ml_confidence && a.ml_confidence > 0
                ? `<span style="font-size:10px;font-family:var(--font-mono);color:var(--accent-cyan);">${(a.ml_confidence * 100).toFixed(0)}%</span>`
                : "";
            return `
                <tr>
                    <td class="td-mono" style="white-space:nowrap;font-size:11px;color:var(--text-secondary);">
                        ${a.timestamp || "--"}
                    </td>
                    <td>
                        <span class="sev-badge ${sevClass(a.severity)}">${a.severity || "?"}</span>
                    </td>
                    <td style="max-width:160px;">
                        <div style="font-weight:500;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;" title="${a.attack_type || ''}">
                            ${a.attack_type || "Unknown"}
                        </div>
                        ${a.mitre_technique ? `<div style="font-size:10px;color:var(--text-dim);font-family:var(--font-mono);">${a.mitre_technique}</div>` : ""}
                    </td>
                    <td class="td-mono" style="color:var(--sev-high);">${a.src_ip || "--"}</td>
                    <td class="td-mono" style="color:var(--text-secondary);">${a.dst_ip || "--"}</td>
                    <td class="td-mono" style="color:var(--text-secondary);">${a.dst_port || "*"}</td>
                    <td>
                        <span style="font-size:11px;font-weight:500;color:var(--accent-cyan);">${a.protocol || "--"}</span>
                    </td>
                    <td style="min-width:110px;">${riskBar(a.risk_score)}</td>
                    <td>
                        <div style="display:flex;flex-direction:column;gap:3px;">
                            <span class="engine-badge ${engineClass(a.engine)}">${a.engine || "?"}</span>
                            ${mlBadge}
                        </div>
                    </td>
                    <td>
                        <a href="/alert/${a.id}" class="btn-sentinel btn-outline-s" style="font-size:10px;padding:3px 8px;">
                            <i class="fa-solid fa-eye"></i>
                        </a>
                    </td>
                </tr>
            `;
        }).join("");
    }

    // =========================================================
    // Apply Filters
    // =========================================================
    function applyFilters() {
        const search = (document.getElementById("tableSearch")?.value || "").toLowerCase();
        const severity = document.getElementById("severityFilter")?.value || "ALL";
        const engine = document.getElementById("engineFilter")?.value || "ALL";
        const protocol = document.getElementById("protocolFilter")?.value || "ALL";

        let filtered = allAlerts;

        if (severity !== "ALL") filtered = filtered.filter((a) => (a.severity || "").toUpperCase() === severity);
        if (engine !== "ALL") filtered = filtered.filter((a) => (a.engine || "").includes(engine));
        if (protocol !== "ALL") filtered = filtered.filter((a) => (a.protocol || "").toUpperCase() === protocol);
        if (search) {
            filtered = filtered.filter((a) => JSON.stringify(a).toLowerCase().includes(search));
        }

        renderTable(filtered);

        const showing = document.getElementById("showing-count");
        const total = document.getElementById("total-count");
        if (showing) showing.textContent = filtered.length;
        if (total) total.textContent = allAlerts.length;
    }

    // =========================================================
    // Fetch Alerts
    // =========================================================
    function fetchAlerts() {
        fetch("/api/alerts?limit=500")
            .then((r) => r.json())
            .then((resp) => {
                if (resp.status !== "success") return;
                const alerts = resp.data || [];

                // Detect new critical alerts on subsequent loads
                if (!isFirstLoad && alerts.length > prevAlertCount) {
                    const newAlerts = alerts.slice(0, alerts.length - prevAlertCount);
                    const criticals = newAlerts.filter((a) => (a.severity || "").toUpperCase() === "CRITICAL");
                    if (criticals.length > 0 && window.showToast) {
                        showToast("danger", `🚨 ${criticals.length} Critical Alert(s)`,
                            `${criticals[0].attack_type} from ${criticals[0].src_ip}`);
                    }
                }

                prevAlertCount = alerts.length;
                allAlerts = alerts;
                isFirstLoad = false;

                applyFilters();
                updateStats(alerts);
            })
            .catch(() => {});
    }

    // =========================================================
    // Update Stats Strip
    // =========================================================
    function updateStats(alerts) {
        const total = document.getElementById("stat-total");
        const critical = document.getElementById("stat-critical");
        const ml = document.getElementById("stat-ml");

        if (total) total.textContent = alerts.length;
        if (critical) {
            const count = alerts.filter((a) => ["CRITICAL", "HIGH"].includes((a.severity || "").toUpperCase())).length;
            critical.textContent = count;
        }
        if (ml) {
            const count = alerts.filter((a) => (a.engine || "").includes("ML")).length;
            ml.textContent = count;
        }
    }

    // =========================================================
    // Export Functions
    // =========================================================
    window.exportCSV = function () {
        window.open("/api/alerts/export/csv", "_blank");
        if (window.showToast) showToast("success", "Export Started", "Downloading alerts as CSV");
    };

    window.exportJSON = function () {
        window.open("/api/alerts/export/json", "_blank");
        if (window.showToast) showToast("success", "Export Started", "Downloading alerts as JSON");
    };

    // =========================================================
    // Event Listeners
    // =========================================================
    ["tableSearch", "severityFilter", "engineFilter", "protocolFilter"].forEach((id) => {
        const el = document.getElementById(id);
        if (el) el.addEventListener("input", applyFilters);
    });

    // =========================================================
    // Initialize
    // =========================================================
    fetchAlerts();
    setInterval(fetchAlerts, POLL_INTERVAL);
})();
