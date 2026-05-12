/**
 * dashboard/static/js/attack_map.js
 * ===================================
 * Sentinel-IDS — Professional Live Attack Map
 * 
 * Uses Leaflet.js with OpenStreetMap tiles.
 * Plots live attack dots, animated pulse rings, and
 * rich tooltip popups for every detected threat.
 */

(function () {
    "use strict";

    // =========================================================
    // Map Initialization
    // =========================================================
    const map = L.map("attack-map", {
        center: [20, 0],
        zoom: 2,
        zoomControl: true,
        attributionControl: false,
        minZoom: 1,
        maxZoom: 10,
    });

    // Dark OSM tiles
    L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
        maxZoom: 18,
    }).addTo(map);

    // Attribution
    L.control.attribution({ prefix: false }).addTo(map);

    // =========================================================
    // Severity -> Color mapping
    // =========================================================
    const SEV_COLORS = {
        CRITICAL: "#dc2626",
        HIGH:     "#f97316",
        MEDIUM:   "#f59e0b",
        LOW:      "#3b82f6",
        INFO:     "#6b7280",
    };

    function getSevColor(severity) {
        return SEV_COLORS[(severity || "").toUpperCase()] || SEV_COLORS.LOW;
    }

    // =========================================================
    // Custom Pulse Marker
    // =========================================================
    function createPulseIcon(color, size = 12) {
        return L.divIcon({
            className: "",
            iconSize: [size * 2, size * 2],
            iconAnchor: [size, size],
            html: `
                <div style="position:relative;width:${size * 2}px;height:${size * 2}px;">
                    <div style="
                        position:absolute;top:50%;left:50%;
                        transform:translate(-50%,-50%);
                        width:${size}px;height:${size}px;
                        background:${color};
                        border-radius:50%;
                        box-shadow:0 0 ${size}px ${color};
                        animation:pulseMarker 2s infinite;
                    "></div>
                    <div style="
                        position:absolute;top:50%;left:50%;
                        transform:translate(-50%,-50%);
                        width:${size * 2}px;height:${size * 2}px;
                        border:2px solid ${color};
                        border-radius:50%;
                        opacity:0.4;
                        animation:pulseRing 2s infinite;
                    "></div>
                </div>
            `,
        });
    }

    // Inject pulse animation CSS
    const style = document.createElement("style");
    style.textContent = `
        @keyframes pulseMarker {
            0%,100% { transform:translate(-50%,-50%) scale(1); opacity:1; }
            50%      { transform:translate(-50%,-50%) scale(1.3); opacity:0.85; }
        }
        @keyframes pulseRing {
            0%   { transform:translate(-50%,-50%) scale(0.8); opacity:0.6; }
            100% { transform:translate(-50%,-50%) scale(2.2); opacity:0; }
        }
    `;
    document.head.appendChild(style);

    // =========================================================
    // State
    // =========================================================
    const markersLayer = L.layerGroup().addTo(map);
    let heatmapMode = false;
    let currentData = [];

    // =========================================================
    // Popup HTML Builder
    // =========================================================
    function buildPopup(attack) {
        const color = getSevColor(attack.severity);
        const riskColor = attack.risk_score >= 80 ? "#dc2626"
                        : attack.risk_score >= 60 ? "#f97316"
                        : attack.risk_score >= 40 ? "#f59e0b" : "#3b82f6";

        return `
            <div style="min-width:220px;font-family:'Inter',sans-serif;font-size:12px;background:#151d2e;border-radius:10px;overflow:hidden;">
                <div style="background:${color}22;border-bottom:1px solid ${color}44;padding:10px 14px;display:flex;align-items:center;gap:8px;">
                    <span style="width:8px;height:8px;background:${color};border-radius:50%;box-shadow:0 0 6px ${color};flex-shrink:0;"></span>
                    <strong style="color:${color};font-size:12px;">${attack.attack_type || "Unknown"}</strong>
                    <span style="margin-left:auto;background:${color}22;color:${color};padding:1px 7px;border-radius:10px;font-size:10px;font-weight:700;border:1px solid ${color}44;">${attack.severity || "?"}</span>
                </div>
                <div style="padding:10px 14px;display:grid;row-gap:6px;">
                    <div style="display:flex;justify-content:space-between;">
                        <span style="color:#64748b;">Source IP</span>
                        <code style="color:#f1f5f9;font-size:11px;">${attack.src_ip || "?"}</code>
                    </div>
                    <div style="display:flex;justify-content:space-between;">
                        <span style="color:#64748b;">Location</span>
                        <span style="color:#f1f5f9;">${attack.city || "?"}, ${attack.country || "?"}</span>
                    </div>
                    <div style="display:flex;justify-content:space-between;">
                        <span style="color:#64748b;">Engine</span>
                        <span style="color:#c4b5fd;">${attack.engine || "?"}</span>
                    </div>
                    <div style="display:flex;justify-content:space-between;">
                        <span style="color:#64748b;">Risk Score</span>
                        <span style="color:${riskColor};font-weight:700;">${attack.risk_score || 0}/100</span>
                    </div>
                    <div style="display:flex;justify-content:space-between;">
                        <span style="color:#64748b;">Time</span>
                        <span style="color:#94a3b8;font-size:11px;">${attack.timestamp || "?"}</span>
                    </div>
                    ${attack.rule ? `
                    <div style="display:flex;justify-content:space-between;">
                        <span style="color:#64748b;">Rule</span>
                        <span style="color:#fbbf24;font-size:10px;max-width:130px;text-align:right;">${attack.rule}</span>
                    </div>` : ""}
                </div>
            </div>
        `;
    }

    // =========================================================
    // Render Markers
    // =========================================================
    function renderMarkers(attacks) {
        markersLayer.clearLayers();
        const seen = new Set();

        attacks.forEach((attack) => {
            if (!attack.lat || !attack.lon) return;

            // Slight jitter for overlapping points
            const jitter = () => (Math.random() - 0.5) * 0.4;
            const lat = attack.lat + jitter();
            const lon = attack.lon + jitter();
            const key = `${lat.toFixed(2)},${lon.toFixed(2)}`;

            const sev = (attack.severity || "LOW").toUpperCase();
            const color = getSevColor(sev);
            const size = sev === "CRITICAL" ? 10 : sev === "HIGH" ? 8 : 6;

            const marker = L.marker([lat, lon], {
                icon: createPulseIcon(color, size),
            });

            marker.bindPopup(buildPopup(attack), {
                className: "attack-popup",
                maxWidth: 280,
            });

            markersLayer.addLayer(marker);
        });
    }

    // =========================================================
    // Fetch & Update
    // =========================================================
    function loadMapData() {
        fetch("/api/geoip?limit=150")
            .then((r) => r.json())
            .then((resp) => {
                if (resp.status !== "success") return;
                currentData = resp.data || [];

                renderMarkers(currentData);

                // Update counter stats
                const countEl = document.getElementById("map-total");
                const countriesEl = document.getElementById("map-countries");
                const topAttacker = document.getElementById("map-top-attacker");
                const iocCount = document.getElementById("map-ioc-count");

                if (countEl) countEl.textContent = currentData.length;
                if (countriesEl) {
                    const uniqueCountries = new Set(currentData.map((a) => a.country));
                    countriesEl.textContent = uniqueCountries.size;
                }
                if (topAttacker && currentData.length > 0) {
                    // Count IPs
                    const ipCounts = {};
                    currentData.forEach((a) => { ipCounts[a.src_ip] = (ipCounts[a.src_ip] || 0) + 1; });
                    const top = Object.entries(ipCounts).sort((a, b) => b[1] - a[1])[0];
                    topAttacker.textContent = top ? top[0] : "--";
                    topAttacker.style.fontSize = "14px";
                    topAttacker.style.fontFamily = "var(--font-mono)";
                }
            })
            .catch((e) => console.warn("[AttackMap] Fetch error:", e));
    }

    // =========================================================
    // Control Bindings
    // =========================================================
    document.getElementById("btn-refresh-map")?.addEventListener("click", () => {
        loadMapData();
        if (window.showToast) showToast("info", "Map Refreshed", "Live attack data reloaded.");
    });

    document.getElementById("btn-heatmap")?.addEventListener("click", function () {
        heatmapMode = !heatmapMode;
        this.innerHTML = heatmapMode
            ? '<i class="fa-solid fa-map-marker-alt"></i> Dots'
            : '<i class="fa-solid fa-fire"></i> Heatmap';
        if (heatmapMode) {
            // Simple heatmap: large transparent circles
            markersLayer.clearLayers();
            currentData.forEach((a) => {
                if (!a.lat || !a.lon) return;
                const color = getSevColor(a.severity);
                L.circle([a.lat, a.lon], {
                    radius: 300000,
                    color: "transparent",
                    fillColor: color,
                    fillOpacity: 0.08,
                }).addTo(markersLayer);
            });
        } else {
            renderMarkers(currentData);
        }
    });

    // =========================================================
    // Init & Auto-Refresh (every 10s)
    // =========================================================
    loadMapData();
    setInterval(loadMapData, 10000);

    // Expose for other scripts
    window.attackMap = { reload: loadMapData, map };
})();
