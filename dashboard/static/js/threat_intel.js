/**
 * dashboard/static/js/threat_intel.js
 * =====================================
 * Sentinel-IDS — Threat Intelligence Data Loader
 *
 * Handles: IOC scoring table, MITRE mapping, country table, IOC management
 */

(function () {
    "use strict";

    const MITRE_ICONS = {
        "Initial Access": { icon: "fa-door-open", color: "#ef4444" },
        "Execution": { icon: "fa-terminal", color: "#f97316" },
        "Discovery": { icon: "fa-magnifying-glass", color: "#f59e0b" },
        "Command and Control": { icon: "fa-tower-broadcast", color: "#8b5cf6" },
        "Exfiltration": { icon: "fa-file-export", color: "#06b6d4" },
        "Denial of Service": { icon: "fa-server", color: "#dc2626" },
        "Lateral Movement": { icon: "fa-arrows-left-right", color: "#f59e0b" },
        "Impact": { icon: "fa-bomb", color: "#dc2626" },
        "Credential Access": { icon: "fa-key", color: "#f97316" },
    };

    // =========================================================
    // IOC Score Table
    // =========================================================
    function loadIOCScores() {
        fetch("/api/intel")
            .then((r) => r.json())
            .then((resp) => {
                if (resp.status !== "success") return;
                const iocs = resp.data?.iocs || [];
                const el = document.getElementById("iocList");
                if (!el) return;

                if (iocs.length === 0) {
                    el.innerHTML = '<li class="list-group-item text-center py-4" style="color:var(--text-secondary)">No threat actors detected</li>';
                    return;
                }

                el.innerHTML = iocs.map((ioc, i) => {
                    const score = Math.min(ioc.score, 100);
                    const pct = score;
                    const color = score >= 80 ? "#dc2626" : score >= 60 ? "#f97316" : score >= 40 ? "#f59e0b" : "#3b82f6";
                    const rank = ["🥇", "🥈", "🥉"][i] || `#${i + 1}`;
                    return `
                        <li class="list-group-item" style="background:transparent;border-color:var(--border);padding:12px 18px;">
                            <div style="display:flex;align-items:center;gap:12px;">
                                <span style="font-size:14px;">${rank}</span>
                                <code style="color:var(--text-primary);font-size:12px;flex:1;">${ioc.ip}</code>
                                <div style="flex:2;">
                                    <div style="height:4px;background:var(--border);border-radius:2px;overflow:hidden;">
                                        <div style="height:100%;width:${pct}%;background:${color};border-radius:2px;transition:width 0.8s ease;"></div>
                                    </div>
                                </div>
                                <span style="font-family:var(--font-mono);font-size:12px;color:${color};font-weight:700;min-width:40px;text-align:right;">${score}</span>
                                <button onclick="blockFromIOC('${ioc.ip}')" style="border:none;background:none;color:var(--text-secondary);cursor:pointer;padding:2px 6px;font-size:11px;" title="Block IP">
                                    <i class="fa-solid fa-ban"></i>
                                </button>
                            </div>
                        </li>
                    `;
                }).join("");

                // Update sidebar IOC count
                const iocCountEl = document.getElementById("map-ioc-count");
                if (iocCountEl) iocCountEl.textContent = iocs.length;

                // Update MITRE
                const mitre = resp.data?.mitre || {};
                renderMITRE(mitre);
            })
            .catch((e) => console.warn("[ThreatIntel] IOC fetch error:", e));
    }

    // =========================================================
    // MITRE ATT&CK Rendering
    // =========================================================
    function renderMITRE(mitre) {
        const el = document.getElementById("mitreList");
        if (!el) return;

        const total = Object.values(mitre).reduce((a, b) => a + b, 0) || 1;
        const sorted = Object.entries(mitre)
            .filter(([, v]) => v > 0)
            .sort((a, b) => b[1] - a[1]);

        if (sorted.length === 0) {
            el.innerHTML = '<div class="text-center py-4" style="color:var(--text-secondary)">No MITRE data available</div>';
            return;
        }

        el.innerHTML = sorted.map(([tactic, count]) => {
            const pct = Math.round((count / total) * 100);
            const info = MITRE_ICONS[tactic] || { icon: "fa-shield", color: "#6b7280" };
            return `
                <div style="display:flex;align-items:center;gap:12px;margin-bottom:14px;">
                    <div style="width:32px;height:32px;border-radius:8px;background:${info.color}22;display:flex;align-items:center;justify-content:center;flex-shrink:0;">
                        <i class="fa-solid ${info.icon}" style="color:${info.color};font-size:13px;"></i>
                    </div>
                    <div style="flex:1;min-width:0;">
                        <div style="display:flex;justify-content:space-between;margin-bottom:4px;">
                            <span style="font-size:12px;font-weight:500;color:var(--text-primary);white-space:nowrap;">${tactic}</span>
                            <span style="font-size:11px;font-family:var(--font-mono);color:${info.color};">${count} events</span>
                        </div>
                        <div style="height:4px;background:var(--border);border-radius:2px;overflow:hidden;">
                            <div style="height:100%;width:${pct}%;background:${info.color};border-radius:2px;transition:width 0.8s ease;"></div>
                        </div>
                    </div>
                </div>
            `;
        }).join("");
    }

    // =========================================================
    // Country Table
    // =========================================================
    function loadCountries() {
        fetch("/api/top-countries")
            .then((r) => r.json())
            .then((resp) => {
                const countries = resp.data || [];
                const tbody = document.getElementById("countryBody");
                if (!tbody) return;

                const total = countries.reduce((s, c) => s + c.count, 0) || 1;

                if (countries.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="4" class="text-center py-4" style="color:var(--text-secondary)">No data</td></tr>';
                    return;
                }

                tbody.innerHTML = countries.map((c, i) => {
                    const pct = Math.round((c.count / total) * 100);
                    return `
                        <tr>
                            <td style="color:var(--text-secondary);font-size:11px;">${i + 1}</td>
                            <td style="font-weight:500;">${c.country}</td>
                            <td><span style="font-family:var(--font-mono);color:var(--accent-cyan);">${c.count}</span></td>
                            <td style="min-width:80px;">
                                <div style="display:flex;align-items:center;gap:6px;">
                                    <div style="height:3px;background:var(--border);border-radius:2px;flex:1;overflow:hidden;">
                                        <div style="height:100%;width:${pct}%;background:var(--accent-orange);border-radius:2px;"></div>
                                    </div>
                                    <span style="font-size:10px;color:var(--text-secondary);min-width:28px;">${pct}%</span>
                                </div>
                            </td>
                        </tr>
                    `;
                }).join("");
            })
            .catch(() => {});
    }

    // =========================================================
    // IOC Management
    // =========================================================
    function loadIOCManagement() {
        fetch("/api/ioc")
            .then((r) => r.json())
            .then((resp) => {
                const { blacklist = [], whitelist = [] } = resp.data || {};
                const el = document.getElementById("iocManagementList");
                if (!el) return;

                if (blacklist.length === 0 && whitelist.length === 0) {
                    el.innerHTML = '<div class="text-center py-3" style="color:var(--text-secondary);font-size:12px;">No IOCs tracked. Add IPs above.</div>';
                    return;
                }

                const renderIP = (ip, type) => `
                    <div style="display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--border);">
                        <i class="fa-solid ${type === 'blacklist' ? 'fa-ban' : 'fa-check-circle'}" 
                           style="color:${type === 'blacklist' ? 'var(--sev-critical)' : 'var(--accent-green)'};font-size:13px;"></i>
                        <code style="flex:1;font-size:12px;">${ip}</code>
                        <span style="font-size:10px;padding:2px 7px;border-radius:4px;background:${type === 'blacklist' ? 'rgba(220,38,38,0.1)' : 'rgba(16,185,129,0.1)'};color:${type === 'blacklist' ? '#f87171' : '#34d399'};">
                            ${type === 'blacklist' ? 'BLOCKED' : 'ALLOWED'}
                        </span>
                        <button onclick="removeIOC('${ip}')" style="border:none;background:none;color:var(--text-dim);cursor:pointer;padding:2px 4px;font-size:11px;">✕</button>
                    </div>
                `;

                el.innerHTML = [
                    ...blacklist.map((ip) => renderIP(ip, "blacklist")),
                    ...whitelist.map((ip) => renderIP(ip, "whitelist")),
                ].join("");
            })
            .catch(() => {});
    }

    // =========================================================
    // Global Actions
    // =========================================================
    window.blacklistIP = function () {
        const ip = document.getElementById("iocIpInput")?.value?.trim();
        if (!ip) return;
        fetch("/api/ioc/blacklist", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ip }),
        }).then(() => {
            showToast("danger", "IP Blocked", `${ip} added to blacklist`);
            document.getElementById("iocIpInput").value = "";
            loadIOCManagement();
        });
    };

    window.whitelistIP = function () {
        const ip = document.getElementById("iocIpInput")?.value?.trim();
        if (!ip) return;
        fetch("/api/ioc/whitelist", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ip }),
        }).then(() => {
            showToast("success", "IP Whitelisted", `${ip} added to allowlist`);
            document.getElementById("iocIpInput").value = "";
            loadIOCManagement();
        });
    };

    window.removeIOC = function (ip) {
        fetch(`/api/ioc/${ip}`, { method: "DELETE" })
            .then(() => { showToast("info", "IOC Removed", ip); loadIOCManagement(); });
    };

    window.blockFromIOC = function (ip) {
        fetch("/api/ioc/blacklist", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ip }),
        }).then(() => {
            showToast("danger", "IP Blocked", `${ip} blocked from threat list`);
            loadIOCManagement();
        });
    };

    // =========================================================
    // Initialize
    // =========================================================
    loadIOCScores();
    loadCountries();
    loadIOCManagement();
    setInterval(loadIOCScores, 15000);
    setInterval(loadCountries, 30000);
    setInterval(loadIOCManagement, 20000);
})();
