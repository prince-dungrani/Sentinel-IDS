/**
 * dashboard/static/js/attack_lab.js
 * ====================================
 * Sentinel-IDS Attack Lab Frontend Controller
 */
(function () {
    "use strict";

    let attackCount = 0;
    let totalPackets = 0;
    let totalAlertsBefore = 0;

    // =========================================================
    // Log Terminal
    // =========================================================
    function logLine(text, color = "var(--text-primary)") {
        const el = document.getElementById("attack-log");
        if (!el) return;
        const line = document.createElement("div");
        line.innerHTML = `<span style="color:var(--text-dim);font-size:10px;">[${new Date().toLocaleTimeString()}]</span> <span style="color:${color};">${text}</span>`;
        el.appendChild(line);
        el.scrollTop = el.scrollHeight;
    }

    window.clearLog = function () {
        const el = document.getElementById("attack-log");
        if (el) el.innerHTML = '<span style="color:var(--accent-green);">sentinel@ids-lab:~$</span> <span style="color:var(--text-secondary);">Log cleared.</span><br>';
    };

    // =========================================================
    // Update mode options based on attack type
    // =========================================================
    window.updateAttackUI = function () {
        const attackType = document.getElementById("attack-type")?.value;
        const modeGroup = document.getElementById("mode-group");
        const modeSelect = document.getElementById("attack-mode");
        if (!modeSelect || !modeGroup) return;

        modeSelect.innerHTML = "";
        if (attackType === "portscan") {
            [["connect", "TCP Connect Scan"], ["syn", "SYN Scan (Stealth)"], ["aggressive", "Aggressive Multi-thread"]].forEach(([v, l]) => {
                modeSelect.innerHTML += `<option value="${v}">${l}</option>`;
            });
            modeGroup.style.display = "block";
        } else if (attackType === "synflood" || attackType === "ddos") {
            [["syn", "SYN Flood (Scapy)"], ["http", "HTTP Flood"]].forEach(([v, l]) => {
                modeSelect.innerHTML += `<option value="${v}">${l}</option>`;
            });
            modeGroup.style.display = "block";
        } else {
            modeGroup.style.display = "none";
        }
    };

    // =========================================================
    // Get current alert count
    // =========================================================
    function getCurrentAlertCount() {
        return fetch("/api/stats")
            .then(r => r.json())
            .then(d => d.data?.total_alerts || 0)
            .catch(() => 0);
    }

    // =========================================================
    // Launch Attack
    // =========================================================
    window.launchAttack = function () {
        const attack    = document.getElementById("attack-type")?.value;
        const mode      = document.getElementById("attack-mode")?.value || "connect";
        const target    = document.getElementById("attack-target")?.value || "127.0.0.1";
        const port      = parseInt(document.getElementById("attack-port")?.value) || 5001;
        const intensity = parseInt(document.getElementById("attack-intensity")?.value) || 200;

        if (!attack) return;

        const btn = document.getElementById("btn-launch");
        const badge = document.getElementById("attack-running-badge");
        const progressDiv = document.getElementById("attack-progress");
        const progressBar = document.getElementById("progress-bar");
        const progressText = document.getElementById("progress-text");

        // Disable button
        if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Launching...'; }
        if (badge) badge.style.display = "inline-flex";
        if (progressDiv) progressDiv.style.display = "block";

        logLine(`🚨 Launching ${attack.toUpperCase()} attack → ${target}:${port} | count=${intensity} | mode=${mode}`, "var(--sev-critical)");

        // Capture baseline alerts
        getCurrentAlertCount().then(baseCount => {
            totalAlertsBefore = baseCount;
        });

        // Animate progress bar
        let prog = 0;
        const progInterval = setInterval(() => {
            prog = Math.min(prog + Math.random() * 8, 95);
            if (progressBar) progressBar.style.width = prog + "%";
            if (progressText) progressText.textContent = `Sending packets... ${Math.round(prog)}%`;
        }, 300);

        // Call backend API
        fetch("/api/attack-lab/launch", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ attack, mode, target, port, count: intensity }),
        })
        .then(r => r.json())
        .then(resp => {
            clearInterval(progInterval);
            if (progressBar) progressBar.style.width = "100%";
            if (progressText) progressText.textContent = "Complete!";

            setTimeout(() => {
                if (progressDiv) progressDiv.style.display = "none";
                if (progressBar) progressBar.style.width = "0%";
            }, 2000);

            if (resp.status === "success") {
                const result = resp.result || {};
                attackCount++;
                const sent = result.sent || result.attempts || result.scanned || intensity;
                totalPackets += sent;

                document.getElementById("attacks-launched").textContent = attackCount;
                document.getElementById("packets-sent").textContent = totalPackets;

                logLine(`✅ Attack complete in ${result.duration_s || "?"}s`, "var(--accent-green)");
                if (result.error) {
                    logLine(`⚠️  Error: ${result.error}`, "var(--accent-yellow)");
                }

                // Check new alerts after 2s
                setTimeout(() => {
                    getCurrentAlertCount().then(newCount => {
                        const newAlerts = newCount - totalAlertsBefore;
                        document.getElementById("alerts-triggered").textContent = newCount;
                        if (newAlerts > 0) {
                            logLine(`🚨 IDS triggered ${newAlerts} new alert(s)!`, "var(--sev-critical)");
                            showToast("danger", `${newAlerts} Alerts Triggered`, `${attack} attack detected by IDS`);
                        } else {
                            logLine("ℹ️  No new IDS alerts (check rules/thresholds)", "var(--text-secondary)");
                        }
                    });
                }, 2500);

                updateMLMonitor();
                updateSessionTable();
                showToast("success", `${attack.toUpperCase()} Complete`, `${sent} packets sent in ${result.duration_s || '?'}s`);
            } else {
                logLine(`❌ Failed: ${resp.message || "Unknown error"}`, "var(--sev-critical)");
                showToast("danger", "Attack Failed", resp.message || "Server error");
            }
        })
        .catch(e => {
            clearInterval(progInterval);
            logLine(`❌ Network error: ${e.message}`, "var(--sev-critical)");
            showToast("danger", "Network Error", "Could not reach backend");
        })
        .finally(() => {
            if (btn) { btn.disabled = false; btn.innerHTML = '<i class="fa-solid fa-play"></i> LAUNCH ATTACK'; }
            if (badge) badge.style.display = "none";
        });
    };

    // =========================================================
    // Start Target App
    // =========================================================
    window.launchTarget = function () {
        fetch("/api/attack-lab/start-target", { method: "POST" })
            .then(r => r.json())
            .then(resp => {
                if (resp.status === "success" || resp.status === "already_running") {
                    logLine("🟢 Vulnerable target started at http://127.0.0.1:5001", "var(--accent-green)");
                    showToast("success", "Target Started", "Vulnerable app running on :5001");
                    document.getElementById("target-status").textContent = "ONLINE";
                } else {
                    logLine(`⚠️  Target: ${resp.message}`, "var(--accent-yellow)");
                }
            })
            .catch(() => logLine("❌ Could not start target", "var(--sev-critical)"));
    };

    // =========================================================
    // ML Monitor
    // =========================================================
    function updateMLMonitor() {
        fetch("/api/alerts?limit=5")
            .then(r => r.json())
            .then(resp => {
                const alerts = (resp.data || []).filter(a => a.engine === "ML Engine");
                const el = document.getElementById("ml-monitor");
                if (!el) return;

                if (alerts.length === 0) {
                    el.innerHTML = '<div style="text-align:center;color:var(--text-dim);font-size:12px;padding:12px;">No ML detections yet. Run an attack with higher intensity.</div>';
                    return;
                }

                el.innerHTML = alerts.map(a => {
                    const conf = ((a.ml_confidence || 0) * 100).toFixed(1);
                    const color = conf >= 90 ? "var(--sev-critical)" : conf >= 75 ? "var(--sev-high)" : "var(--accent-yellow)";
                    return `
                        <div style="padding:10px;border:1px solid var(--border);border-radius:8px;margin-bottom:8px;">
                            <div style="display:flex;justify-content:space-between;margin-bottom:4px;">
                                <strong style="font-size:12px;color:${color};">${a.attack_type || "Unknown"}</strong>
                                <span style="font-size:11px;font-family:var(--font-mono);color:${color};">${conf}%</span>
                            </div>
                            <div style="font-size:10px;color:var(--text-secondary);">Model: ${a.ml_label || "N/A"} | ${a.timestamp}</div>
                            ${a.ml_top_features && a.ml_top_features.length > 0 ?
                              `<div style="font-size:10px;color:var(--text-dim);margin-top:4px;">Top: ${a.ml_top_features.slice(0,2).map(f => f.feature || f).join(", ")}</div>` : ""}
                        </div>`;
                }).join("");
            })
            .catch(() => {});
    }

    // =========================================================
    // Session Table
    // =========================================================
    function updateSessionTable() {
        fetch("/api/attack-lab/sessions")
            .then(r => r.json())
            .then(resp => {
                const sessions = (resp.data || []).reverse().slice(0, 10);
                const tbody = document.getElementById("session-body");
                if (!tbody) return;

                if (sessions.length === 0) return;

                tbody.innerHTML = sessions.map(s => {
                    const time = new Date(s.timestamp).toLocaleTimeString();
                    const status = s.result?.error ? "❌ Error" : "✅ Done";
                    const duration = s.duration + "s";
                    return `
                        <tr>
                            <td class="td-mono" style="font-size:11px;">${time}</td>
                            <td><span class="sev-badge sev-high" style="font-size:9px;">${(s.attack_type || "").toUpperCase()}</span></td>
                            <td style="font-size:11px;">${status}</td>
                            <td class="td-mono" style="font-size:11px;">${duration}</td>
                        </tr>`;
                }).join("");
            })
            .catch(() => {});
    }

    // =========================================================
    // Target Health Check
    // =========================================================
    function checkTargetHealth() {
        const el = document.getElementById("target-status");
        fetch("http://127.0.0.1:5001/health", { signal: AbortSignal.timeout(2000) })
            .then(r => r.json())
            .then(() => { if (el) el.textContent = "ONLINE"; })
            .catch(() => { if (el) el.textContent = "OFFLINE"; });
    }

    // =========================================================
    // Init
    // =========================================================
    updateAttackUI();
    checkTargetHealth();
    setInterval(checkTargetHealth, 10000);
    setInterval(updateMLMonitor, 5000);
    setInterval(updateSessionTable, 10000);
})();
