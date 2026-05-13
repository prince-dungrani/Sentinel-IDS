/**
 * dashboard/static/js/settings.js
 * =================================
 * Sentinel-IDS — ML Settings Page Controller
 */
(function () {
    "use strict";

    // =========================================================
    // Slider syncing
    // =========================================================
    const sliders = [
        { id: "alpha",          valId: "alpha-val",  decimals: 2 },
        { id: "beta",           valId: "beta-val",   decimals: 2 },
        { id: "conf-threshold", valId: "conf-val",   decimals: 2 },
        { id: "anom-threshold", valId: "anom-val",   decimals: 2 },
        { id: "top-features",   valId: "feat-val",   decimals: 0 },
    ];

    sliders.forEach(({ id, valId, decimals }) => {
        const slider = document.getElementById(id);
        const display = document.getElementById(valId);
        if (!slider || !display) return;
        slider.addEventListener("input", () => {
            display.textContent = parseFloat(slider.value).toFixed(decimals);
            updateFusionScore();
        });
    });

    // =========================================================
    // Load Config from Backend
    // =========================================================
    function loadConfig() {
        fetch("/api/ml-config")
            .then((r) => r.json())
            .then((resp) => {
                const cfg = resp.data || {};
                setSlider("alpha", cfg.alpha ?? 0.6, 2, "alpha-val");
                setSlider("beta", cfg.beta ?? 0.4, 2, "beta-val");
                setSlider("conf-threshold", cfg.confidence_threshold ?? 0.65, 2, "conf-val");
                setSlider("anom-threshold", cfg.anomaly_threshold ?? 0.5, 2, "anom-val");
                setSlider("top-features", cfg.top_features_count ?? 5, 0, "feat-val");

                const mlToggle = document.getElementById("ml-enabled");
                if (mlToggle) mlToggle.checked = cfg.ml_enabled !== false;

                const sensSel = document.getElementById("sensitivity");
                if (sensSel && cfg.sensitivity) sensSel.value = cfg.sensitivity;

                updateFusionScore();
            })
            .catch(() => {});
    }

    function setSlider(id, value, decimals, valId) {
        const el = document.getElementById(id);
        const valEl = document.getElementById(valId);
        if (el) el.value = value;
        if (valEl) valEl.textContent = parseFloat(value).toFixed(decimals);
    }

    // =========================================================
    // Save Config
    // =========================================================
    window.saveMLConfig = function () {
        const config = {
            alpha: parseFloat(document.getElementById("alpha").value),
            beta: parseFloat(document.getElementById("beta").value),
            confidence_threshold: parseFloat(document.getElementById("conf-threshold").value),
            anomaly_threshold: parseFloat(document.getElementById("anom-threshold").value),
            top_features_count: parseInt(document.getElementById("top-features").value),
            sensitivity: document.getElementById("sensitivity").value,
            ml_enabled: document.getElementById("ml-enabled").checked,
        };

        fetch("/api/ml-config", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(config),
        }).then((r) => r.json()).then((resp) => {
            if (resp.status === "success") {
                showToast("success", "Config Saved", "ML parameters updated. Hot-reload active.");
                const badge = document.getElementById("save-status");
                if (badge) { badge.style.display = "inline"; setTimeout(() => badge.style.display = "none", 3000); }
            } else {
                showToast("danger", "Save Failed", resp.message || "Unknown error");
            }
        }).catch(() => showToast("danger", "Save Failed", "Network error"));
    };

    window.resetDefaults = function () {
        setSlider("alpha", 0.6, 2, "alpha-val");
        setSlider("beta", 0.4, 2, "beta-val");
        setSlider("conf-threshold", 0.65, 2, "conf-val");
        setSlider("anom-threshold", 0.5, 2, "anom-val");
        setSlider("top-features", 5, 0, "feat-val");
        document.getElementById("sensitivity").value = "medium";
        document.getElementById("ml-enabled").checked = true;
        updateFusionScore();
        showToast("info", "Defaults Restored", "Click Save to apply.");
    };

    // =========================================================
    // Live Fusion Score Display
    // =========================================================
    function updateFusionScore() {
        const alpha = parseFloat(document.getElementById("alpha")?.value || 0.6);
        const beta = parseFloat(document.getElementById("beta")?.value || 0.4);
        const rfExample = 0.75;  // Illustrative RF score
        const isoExample = 0.65; // Illustrative Iso score
        const score = (alpha * rfExample + beta * isoExample).toFixed(3);
        const el = document.getElementById("live-fusion-score");
        if (el) el.textContent = score;
    }

    // =========================================================
    // ML Engine Status
    // =========================================================
    function loadMLStatus() {
        fetch("/api/ml-stats")
            .then((r) => r.json())
            .then((resp) => {
                const d = resp.data || {};
                const el = document.getElementById("ml-status-panel");
                if (!el) return;

                const models = d.models || [];
                if (models.length === 0) {
                    el.innerHTML = '<div style="color:var(--text-secondary);font-size:12px;text-align:center;padding:12px;">ML Engine offline or initializing...</div>';
                    return;
                }

                const envRow = `
                    <div style="display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid var(--border);margin-bottom:12px;">
                        <span style="font-size:12px;font-weight:600;color:var(--text-primary);">Runtime Environment</span>
                        <span style="font-size:12px;font-weight:600;color:${d.env_ok ? 'var(--accent-green)' : 'var(--sev-critical)'};">
                            <i class="fa-solid fa-${d.env_ok ? 'circle-check' : 'circle-xmark'}"></i>
                            ${d.env_ok ? 'COMPATIBLE' : 'INCOMPATIBLE'}
                        </span>
                    </div>`;

                const modelCards = models.map(m => {
                    const color = m.ready ? 'var(--accent-green)' : 'var(--sev-critical)';
                    const icon  = m.ready ? 'circle-check' : 'circle-xmark';
                    return `
                        <div style="background:var(--bg-void);border:1px solid ${m.ready ? 'rgba(16,185,129,0.2)' : 'rgba(239,68,68,0.2)'};border-radius:8px;padding:12px;margin-bottom:10px;">
                            <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px;">
                                <strong style="font-size:12px;color:var(--text-primary);">${m.name}</strong>
                                <span style="font-size:11px;font-weight:700;color:${color};">
                                    <i class="fa-solid fa-${icon}"></i> ${m.status.toUpperCase()}
                                </span>
                            </div>
                            <div style="display:grid;grid-template-columns:1fr 1fr;gap:4px;">
                                <span style="font-size:10px;color:var(--text-dim);">Attack Type</span>
                                <span style="font-size:10px;color:var(--accent-cyan);">${m.attack_type}</span>
                                <span style="font-size:10px;color:var(--text-dim);">Features</span>
                                <span style="font-size:10px;color:var(--text-primary);">${m.feature_count}</span>
                                <span style="font-size:10px;color:var(--text-dim);">sklearn</span>
                                <span style="font-size:10px;color:var(--text-primary);">${m.sklearn_version}</span>
                                <span style="font-size:10px;color:var(--text-dim);">Trained</span>
                                <span style="font-size:10px;color:var(--text-primary);">${m.training_date}</span>
                            </div>
                            ${m.error ? `<div style="font-size:10px;color:var(--sev-critical);margin-top:6px;">⚠️ ${m.error}</div>` : ''}
                        </div>`;
                }).join("");

                el.innerHTML = envRow + modelCards +
                    `<div style="font-size:10px;color:var(--text-dim);text-align:center;padding-top:6px;">
                        ${d.ready_models}/${d.total_models} models ready
                    </div>`;

            }).catch(() => {
                const el = document.getElementById("ml-status-panel");
                if (el) el.innerHTML = '<div style="color:var(--text-secondary);font-size:12px;text-align:center;padding:12px;">ML Engine offline or starting...</div>';
            });
    }

    // =========================================================
    // System Health (psutil)
    // =========================================================
    function loadSystemHealth() {
        fetch("/api/system-stats")
            .then((r) => r.json())
            .then((resp) => {
                const d = resp.data || {};
                const el = document.getElementById("system-health-panel");
                if (!el) return;

                const cpu = d.cpu_percent || 0;
                const ram = d.ram_percent || 0;
                const cpuColor = cpu > 80 ? "var(--sev-critical)" : cpu > 50 ? "var(--accent-yellow)" : "var(--accent-green)";
                const ramColor = ram > 85 ? "var(--sev-critical)" : ram > 65 ? "var(--accent-yellow)" : "var(--accent-green)";

                el.innerHTML = `
                    <div style="display:grid;gap:14px;">
                        <div>
                            <div style="display:flex;justify-content:space-between;margin-bottom:6px;">
                                <span style="font-size:12px;color:var(--text-secondary);">CPU Usage</span>
                                <span style="font-size:12px;font-weight:700;color:${cpuColor};font-family:var(--font-mono);">${cpu}%</span>
                            </div>
                            <div style="height:6px;background:var(--border);border-radius:3px;overflow:hidden;">
                                <div style="height:100%;width:${cpu}%;background:${cpuColor};border-radius:3px;transition:width 0.5s;"></div>
                            </div>
                        </div>
                        <div>
                            <div style="display:flex;justify-content:space-between;margin-bottom:6px;">
                                <span style="font-size:12px;color:var(--text-secondary);">RAM Usage</span>
                                <span style="font-size:12px;font-weight:700;color:${ramColor};font-family:var(--font-mono);">${ram}% (${d.ram_used_gb || '?'} GB / ${d.ram_total_gb || '?'} GB)</span>
                            </div>
                            <div style="height:6px;background:var(--border);border-radius:3px;overflow:hidden;">
                                <div style="height:100%;width:${ram}%;background:${ramColor};border-radius:3px;transition:width 0.5s;"></div>
                            </div>
                        </div>
                        <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;padding-top:4px;">
                            <div style="background:var(--bg-void);border-radius:8px;padding:10px;text-align:center;">
                                <div style="font-size:10px;color:var(--text-dim);text-transform:uppercase;letter-spacing:0.8px;margin-bottom:4px;">Pkts Recv</div>
                                <div style="font-size:14px;font-weight:700;color:var(--accent-cyan);font-family:var(--font-mono);">${(d.net_packets_recv || 0).toLocaleString()}</div>
                            </div>
                            <div style="background:var(--bg-void);border-radius:8px;padding:10px;text-align:center;">
                                <div style="font-size:10px;color:var(--text-dim);text-transform:uppercase;letter-spacing:0.8px;margin-bottom:4px;">Pkts Sent</div>
                                <div style="font-size:14px;font-weight:700;color:var(--accent-blue);font-family:var(--font-mono);">${(d.net_packets_sent || 0).toLocaleString()}</div>
                            </div>
                        </div>
                    </div>
                `;

                const timeEl = document.getElementById("sys-refresh-time");
                if (timeEl) timeEl.textContent = new Date().toLocaleTimeString();
            }).catch(() => {});
    }

    // =========================================================
    // Initialize
    // =========================================================
    loadConfig();
    loadMLStatus();
    loadSystemHealth();
    setInterval(loadSystemHealth, 5000);
    setInterval(loadMLStatus, 10000);
    updateFusionScore();
})();
