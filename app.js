/**
 * Civil Aviation Cybersecurity Risk Assessment Dashboard - Application Logic
 * Implements Algorithm 1, Formulas 1 & 2, Tables 2, 3, 4, 5 and all interactive modules.
 */

// Global State
const state = {
  activeTab: "live-sim",
  dataSource: "live", // "live" (dynamic Red/Blue telemetry) or "baseline" (static IEEE Access tables)
  domainFilter: "All",
  activeThreats: [],
  selectedThreat: null,
  activeDomainSubtab: "Communication",
  matrixDisplayMode: "r", // 'r' (numeric), 'scale' (1-5), 'count' (threat badges)
  matrixMitigationToggle: false, // show mitigated positions
  charts: {},
  // Evaluator state
  evaluator: {
    asset: "",
    domain: "Communication",
    threatType: "",
    ciaTriad: "Integrity",
    cost: 5,
    accessibility: 5,
    frequency: 5,
    expertise: 5,
    operations: 5,
    finance: 5,
    reputation: 5,
    manualLikelihood: 3.0,
    manualImpact: 3.0,
    useCalculatedL: true,
    useCalculatedI: true,
    description: "",
    mitigations: ""
  },
  // What-if simulator state
  simulatorPillars: {
    capacityBuilding: false,
    proceduresRegulations: false,
    systemsSecurityByDesign: false,
    // Specific toggles
    arincCrypto: false,
    gnssMultiFreq: false,
    ssrDataFusion: false,
    tdoaMlFingerprint: false,
    swimCommonPki: false
  }
};

// Algorithm 1 helper functions
function calcNumericRisk(likelihood, impact) {
  return Number((likelihood * impact).toFixed(2));
}

function calcTolerability(r) {
  if (r >= 15.0) return "intolerable";
  if (r >= 5.0) return "tolerable";
  return "acceptable";
}

function calcFivePointScale(r) {
  if (r >= 20.0) return 5;
  if (r >= 15.0) return 4;
  if (r >= 10.0) return 3;
  if (r >= 5.0) return 2;
  return 1;
}

// Color helpers based on Table 4
function getTolerabilityColor(tolerability) {
  switch (tolerability) {
    case "intolerable":
      return {
        bg: "bg-red-500/20",
        border: "border-red-500",
        text: "text-red-400",
        badge: "bg-red-500 text-white",
        hex: "#ef4444"
      };
    case "tolerable":
      return {
        bg: "bg-amber-500/20",
        border: "border-amber-500",
        text: "text-amber-400",
        badge: "bg-amber-500 text-slate-900 font-semibold",
        hex: "#f59e0b"
      };
    case "acceptable":
      return {
        bg: "bg-emerald-500/20",
        border: "border-emerald-500",
        text: "text-emerald-400",
        badge: "bg-emerald-500 text-slate-900 font-semibold",
        hex: "#10b981"
      };
    default:
      return {
        bg: "bg-slate-700/20",
        border: "border-slate-600",
        text: "text-slate-300",
        badge: "bg-slate-600 text-white",
        hex: "#64748b"
      };
  }
}

// Initialize Application
document.addEventListener("DOMContentLoaded", () => {
  initNavigation();
  initMatrixControls();
  initEvaluator();
  initSimulator();

  // Initialize Live Airspace Radar Simulator
  if (typeof airspaceSim !== "undefined") {
    airspaceSim.init("radar-canvas");

    // Real-time hook: whenever simulator ticks, update dashboard if in live mode
    airspaceSim.onThreatsUpdated = (liveThreats) => {
      if (state.dataSource === "live") {
        state.activeThreats = liveThreats;
        updateExecutiveMetrics();
        renderThreatTable();
        renderMatrixGrid();
        if (state.activeTab === "overview") updateOverviewCharts();
        if (state.activeTab === "domains") renderDomainCharts();
      }
    };

    state.activeThreats = airspaceSim.getLiveDynamicThreats();

    // Direct event listener bindings for guaranteed UI responsiveness
    const zoneSel = document.getElementById("sim-zone-selector");
    if (zoneSel) {
      zoneSel.addEventListener("change", (e) => {
        airspaceSim.setZone(e.target.value);
      });
    }

    const feedLiveBtn = document.getElementById("sim-feed-live-btn");
    if (feedLiveBtn) {
      feedLiveBtn.addEventListener("click", () => {
        airspaceSim.setFeedMode("live_adsb");
      });
    }

    const feedSandBtn = document.getElementById("sim-feed-sandbox-btn");
    if (feedSandBtn) {
      feedSandBtn.addEventListener("click", () => {
        airspaceSim.setFeedMode("sandbox");
      });
    }

    const pollBtn = document.getElementById("sim-poll-btn");
    if (pollBtn) {
      pollBtn.addEventListener("click", () => {
        airspaceSim.fetchLiveSectorFlights(true);
      });
    }
  } else {
    state.activeThreats = JSON.parse(JSON.stringify(INITIAL_THREATS));
  }

  renderAll();
});

// Render everything on load or data update
function renderAll() {
  updateExecutiveMetrics();
  renderThreatTable();
  renderMatrixGrid();
  renderDomainCharts();
  renderProtocolTables();
  renderLiteratureBenchmark();
  updateOverviewCharts();
}

// Toggle between Live Predicted Telemetry and Static Baseline
function setDataSource(mode) {
  state.dataSource = mode;
  const liveBtn = document.getElementById("datasource-live-btn");
  const baseBtn = document.getElementById("datasource-baseline-btn");
  const indicator = document.getElementById("datasource-indicator");

  if (mode === "live") {
    if (liveBtn) {
      liveBtn.className = "px-3 py-1.5 text-xs font-mono font-bold rounded bg-sky-600 text-white shadow-sm border border-sky-400 flex items-center space-x-1.5";
      liveBtn.innerHTML = '<span class="w-2 h-2 rounded-full bg-emerald-300 animate-ping"></span><span>Live Predicted Stream</span>';
    }
    if (baseBtn) {
      baseBtn.className = "px-3 py-1.5 text-xs font-mono font-bold rounded bg-slate-800 text-slate-400 hover:text-white border border-slate-700 flex items-center space-x-1.5";
      baseBtn.innerHTML = '<i data-lucide="database" class="w-3.5 h-3.5"></i><span>Research Baseline</span>';
    }
    if (indicator) {
      indicator.innerHTML = '<span class="w-2 h-2 rounded-full bg-emerald-400 animate-pulse inline-block mr-1.5"></span><span class="text-emerald-400 font-mono font-bold">STREAMING RED/BLUE TELEMETRY</span>';
    }
    if (typeof airspaceSim !== "undefined") {
      state.activeThreats = airspaceSim.getLiveDynamicThreats();
    }
  } else {
    if (baseBtn) {
      baseBtn.className = "px-3 py-1.5 text-xs font-mono font-bold rounded bg-sky-600 text-white shadow-sm border border-sky-400 flex items-center space-x-1.5";
      baseBtn.innerHTML = '<i data-lucide="database" class="w-3.5 h-3.5"></i><span>Research Baseline</span>';
    }
    if (liveBtn) {
      liveBtn.className = "px-3 py-1.5 text-xs font-mono font-bold rounded bg-slate-800 text-slate-400 hover:text-white border border-slate-700 flex items-center space-x-1.5";
      liveBtn.innerHTML = '<span class="w-2 h-2 rounded-full bg-slate-500 inline-block mr-1.5"></span><span>Live Predicted Stream</span>';
    }
    if (indicator) {
      indicator.innerHTML = '<span class="w-2 h-2 rounded-full bg-sky-400 inline-block mr-1.5"></span><span class="text-sky-400 font-mono font-bold">RESEARCH PAPER BASELINE (IEEE ACCESS)</span>';
    }
    state.activeThreats = JSON.parse(JSON.stringify(INITIAL_THREATS));
  }
  if (window.lucide) lucide.createIcons();
  renderAll();
}

// Navigation Tabs
function initNavigation() {
  const navButtons = document.querySelectorAll(".nav-tab-btn");
  navButtons.forEach((btn) => {
    btn.addEventListener("click", () => {
      const tabName = btn.getAttribute("data-tab");
      switchTab(tabName);
    });
  });

  // Domain subtabs
  const domainSubtabs = document.querySelectorAll(".domain-subtab-btn");
  domainSubtabs.forEach((btn) => {
    btn.addEventListener("click", () => {
      const dom = btn.getAttribute("data-domain");
      state.activeDomainSubtab = dom;
      domainSubtabs.forEach((b) => b.classList.remove("active-subtab"));
      btn.classList.add("active-subtab");
      renderDomainCharts();
    });
  });

  // Filter pills on Threat Table
  const filterPills = document.querySelectorAll(".domain-filter-pill");
  filterPills.forEach((pill) => {
    pill.addEventListener("click", () => {
      state.domainFilter = pill.getAttribute("data-domain");
      filterPills.forEach((p) => p.classList.remove("active-pill"));
      pill.classList.add("active-pill");
      renderThreatTable();
      renderMatrixGrid();
    });
  });

  // Search input
  const searchInput = document.getElementById("threat-search-input");
  if (searchInput) {
    searchInput.addEventListener("input", () => {
      renderThreatTable();
    });
  }
}

function switchTab(tabName) {
  state.activeTab = tabName;
  document.querySelectorAll(".nav-tab-btn").forEach((btn) => {
    if (btn.getAttribute("data-tab") === tabName) {
      btn.classList.add("active-nav-tab");
    } else {
      btn.classList.remove("active-nav-tab");
    }
  });

  document.querySelectorAll(".tab-content-panel").forEach((panel) => {
    if (panel.id === `tab-${tabName}`) {
      panel.classList.remove("hidden");
    } else {
      panel.classList.add("hidden");
    }
  });

  // Refresh charts when switching tabs
  if (tabName === "live-sim") {
    setTimeout(() => {
      if (typeof airspaceSim !== "undefined") {
        airspaceSim.init("radar-canvas");
      }
    }, 50);
  } else if (tabName === "overview") {
    setTimeout(updateOverviewCharts, 50);
  } else if (tabName === "domains") {
    setTimeout(renderDomainCharts, 50);
  } else if (tabName === "matrix") {
    renderMatrixGrid();
  }
}

// --- TAB 1: EXECUTIVE OVERVIEW ---
function updateExecutiveMetrics() {
  const threats = state.activeThreats;
  let acceptable = 0,
    tolerable = 0,
    intolerable = 0;
  let sumRisk = 0;
  let maxRiskThreat = threats[0];

  threats.forEach((t) => {
    const r = calcNumericRisk(t.likelihood, t.impact);
    const tol = calcTolerability(r);
    if (tol === "acceptable") acceptable++;
    else if (tol === "tolerable") tolerable++;
    else if (tol === "intolerable") intolerable++;

    sumRisk += r;
    if (r > calcNumericRisk(maxRiskThreat.likelihood, maxRiskThreat.impact)) {
      maxRiskThreat = t;
    }
  });

  const avgRisk = threats.length ? (sumRisk / threats.length).toFixed(1) : "0.0";

  document.getElementById("stat-total-threats").innerText = threats.length;
  document.getElementById("stat-intolerable-count").innerText = intolerable;
  document.getElementById("stat-tolerable-count").innerText = tolerable;
  document.getElementById("stat-acceptable-count").innerText = acceptable;
  document.getElementById("stat-avg-risk").innerText = avgRisk;
  document.getElementById("stat-highest-threat").innerText = `${maxRiskThreat.asset} - ${maxRiskThreat.threatType} (r=${calcNumericRisk(maxRiskThreat.likelihood, maxRiskThreat.impact)})`;
}

function updateOverviewCharts() {
  const threats = state.activeThreats;

  // 1. Tolerability Donut Chart
  let accCount = 0,
    tolCount = 0,
    intolCount = 0;
  threats.forEach((t) => {
    const tol = calcTolerability(calcNumericRisk(t.likelihood, t.impact));
    if (tol === "acceptable") accCount++;
    else if (tol === "tolerable") tolCount++;
    else if (tol === "intolerable") intolCount++;
  });

  const donutCtx = document.getElementById("overview-donut-chart");
  if (donutCtx) {
    if (state.charts.donut) state.charts.donut.destroy();
    state.charts.donut = new Chart(donutCtx, {
      type: "doughnut",
      data: {
        labels: ["Intolerable (r ≥ 15)", "Tolerable (5 ≤ r < 15)", "Acceptable (r < 5)"],
        datasets: [
          {
            data: [intolCount, tolCount, accCount],
            backgroundColor: ["#ef4444", "#f59e0b", "#10b981"],
            borderColor: "#0f172a",
            borderWidth: 2,
            hoverOffset: 6
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: "bottom",
            labels: { color: "#cbd5e1", font: { family: "JetBrains Mono", size: 11 } }
          }
        },
        cutout: "70%"
      }
    });
  }

  // 2. Domain Comparison Bar Chart
  const domains = ["Communication", "Navigation", "Surveillance", "Networking"];
  const domainMaxRisks = [];
  const domainAvgRisks = [];

  domains.forEach((dom) => {
    const domThreats = threats.filter((t) => t.domain === dom);
    if (domThreats.length > 0) {
      const risks = domThreats.map((t) => calcNumericRisk(t.likelihood, t.impact));
      domainMaxRisks.push(Math.max(...risks));
      domainAvgRisks.push(Number((risks.reduce((a, b) => a + b, 0) / risks.length).toFixed(1)));
    } else {
      domainMaxRisks.push(0);
      domainAvgRisks.push(0);
    }
  });

  const barCtx = document.getElementById("overview-domain-chart");
  if (barCtx) {
    if (state.charts.domainBar) state.charts.domainBar.destroy();
    state.charts.domainBar = new Chart(barCtx, {
      type: "bar",
      data: {
        labels: ["Communication", "Navigation", "Surveillance", "Networking (SWIM)"],
        datasets: [
          {
            label: "Max Risk Level (r)",
            data: domainMaxRisks,
            backgroundColor: "#ef4444",
            borderRadius: 4
          },
          {
            label: "Average Risk Level (r)",
            data: domainAvgRisks,
            backgroundColor: "#38bdf8",
            borderRadius: 4
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          y: {
            max: 25,
            grid: { color: "#334155" },
            ticks: { color: "#94a3b8", font: { family: "JetBrains Mono" } }
          },
          x: {
            grid: { display: false },
            ticks: { color: "#94a3b8", font: { family: "JetBrains Mono" } }
          }
        },
        plugins: {
          legend: {
            position: "top",
            labels: { color: "#cbd5e1", font: { family: "JetBrains Mono", size: 11 } }
          }
        }
      }
    });
  }

  // 3. CIA Triad Breakdown Radar Chart
  let cCount = 0,
    iCount = 0,
    aCount = 0;
  let cRisk = 0,
    iRisk = 0,
    aRisk = 0;

  threats.forEach((t) => {
    const r = calcNumericRisk(t.likelihood, t.impact);
    if (t.ciaTriad === "Confidentiality") {
      cCount++;
      cRisk += r;
    } else if (t.ciaTriad === "Integrity") {
      iCount++;
      iRisk += r;
    } else if (t.ciaTriad === "Availability") {
      aCount++;
      aRisk += r;
    }
  });

  const ciaRadarCtx = document.getElementById("overview-radar-chart");
  if (ciaRadarCtx) {
    if (state.charts.ciaRadar) state.charts.ciaRadar.destroy();
    state.charts.ciaRadar = new Chart(ciaRadarCtx, {
      type: "radar",
      data: {
        labels: ["Confidentiality", "Integrity", "Availability"],
        datasets: [
          {
            label: "Average Risk Severity",
            data: [
              cCount ? Number((cRisk / cCount).toFixed(1)) : 0,
              iCount ? Number((iRisk / iCount).toFixed(1)) : 0,
              aCount ? Number((aRisk / aCount).toFixed(1)) : 0
            ],
            backgroundColor: "rgba(56, 189, 248, 0.25)",
            borderColor: "#38bdf8",
            pointBackgroundColor: "#38bdf8"
          },
          {
            label: "Incident Likelihood",
            data: [
              cCount ? Number((threats.filter((t) => t.ciaTriad === "Confidentiality").reduce((s, x) => s + x.likelihood, 0) / cCount).toFixed(1)) : 0,
              iCount ? Number((threats.filter((t) => t.ciaTriad === "Integrity").reduce((s, x) => s + x.likelihood, 0) / iCount).toFixed(1)) : 0,
              aCount ? Number((threats.filter((t) => t.ciaTriad === "Availability").reduce((s, x) => s + x.likelihood, 0) / aCount).toFixed(1)) : 0
            ],
            backgroundColor: "rgba(244, 63, 94, 0.25)",
            borderColor: "#f43f5e",
            pointBackgroundColor: "#f43f5e"
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          r: {
            grid: { color: "#334155" },
            angleLines: { color: "#334155" },
            pointLabels: { color: "#cbd5e1", font: { family: "JetBrains Mono", size: 12 } },
            ticks: { display: false }
          }
        },
        plugins: {
          legend: {
            position: "bottom",
            labels: { color: "#cbd5e1", font: { family: "JetBrains Mono", size: 10 } }
          }
        }
      }
    });
  }
}

// Render Risk Registry Table
function renderThreatTable() {
  const container = document.getElementById("threat-table-body");
  if (!container) return;

  const searchQuery = (document.getElementById("threat-search-input")?.value || "").toLowerCase();
  const filter = state.domainFilter;

  const filtered = state.activeThreats.filter((t) => {
    const matchesDomain = filter === "All" || t.domain === filter;
    const matchesSearch =
      t.asset.toLowerCase().includes(searchQuery) ||
      t.threatType.toLowerCase().includes(searchQuery) ||
      t.domain.toLowerCase().includes(searchQuery) ||
      t.id.toLowerCase().includes(searchQuery);
    return matchesDomain && matchesSearch;
  });

  // Sort descending by risk level
  filtered.sort((a, b) => {
    return calcNumericRisk(b.likelihood, b.impact) - calcNumericRisk(a.likelihood, a.impact);
  });

  container.innerHTML = filtered
    .map((t) => {
      const r = calcNumericRisk(t.likelihood, t.impact);
      const tol = calcTolerability(r);
      const scale5 = calcFivePointScale(r);
      const style = getTolerabilityColor(tol);

      return `
      <tr class="border-b border-slate-800/80 hover:bg-slate-800/50 cursor-pointer transition-colors" onclick="inspectThreat('${t.id}')">
        <td class="py-3 px-4 font-mono text-xs text-sky-400 font-semibold">${t.id}</td>
        <td class="py-3 px-4 text-xs font-medium text-slate-300">
          <span class="px-2 py-0.5 rounded text-[10px] uppercase font-bold bg-slate-800 text-slate-300 border border-slate-700 mr-2">${t.domain}</span>
          ${t.asset}
        </td>
        <td class="py-3 px-4 text-xs text-slate-200 font-medium">
          <div class="flex items-center space-x-1.5">
            <span class="font-bold text-white">${t.threatType}</span>
            ${t.isRealtime ? `<span class="px-1.5 py-0.2 text-[9px] font-mono font-bold rounded bg-emerald-950 text-emerald-400 border border-emerald-700/60">LIVE</span>` : ""}
          </div>
          ${
            t.liveTelemetry
              ? `<div class="text-[11px] text-slate-400 font-mono mt-0.5 truncate max-w-sm" title="${t.liveTelemetry}"><span class="text-sky-400 font-semibold">Sensor:</span> ${t.liveTelemetry}</div>`
              : `<div class="text-[11px] text-slate-500 font-mono">${t.ciaTriad}</div>`
          }
          ${
            t.prediction
              ? `
              <div class="text-[10px] font-mono mt-1 flex items-center space-x-2">
                <span class="px-1.5 py-0.2 rounded font-bold ${
                  t.prediction.probability >= 80
                    ? "bg-red-950 text-red-400 border border-red-700 animate-pulse"
                    : t.prediction.probability >= 50
                    ? "bg-amber-950 text-amber-400 border border-amber-700"
                    : "bg-slate-900 text-slate-400 border border-slate-800"
                }">
                  AI Forecast: ${t.prediction.probability}% Prob
                </span>
                <span class="text-slate-400">Target: ${t.prediction.targetFlight}</span>
                <span class="text-slate-500">· ETA: ${t.prediction.timeToImpact}</span>
              </div>
            `
              : ""
          }
        </td>
        <td class="py-3 px-4 font-mono text-xs text-center text-slate-300">${t.likelihood.toFixed(1)}</td>
        <td class="py-3 px-4 font-mono text-xs text-center text-slate-300">${t.impact.toFixed(1)}</td>
        <td class="py-3 px-4 font-mono text-xs text-center font-bold text-white">
          <span class="px-2 py-0.5 rounded ${style.bg} ${style.text} border ${style.border}">
            ${r.toFixed(1)}
          </span>
        </td>
        <td class="py-3 px-4 text-center">
          <span class="inline-block px-2.5 py-1 text-[11px] rounded-full uppercase tracking-wider font-bold ${style.badge}">
            ${tol}
          </span>
        </td>
        <td class="py-3 px-4 font-mono text-xs text-center font-bold text-slate-400">
          Scale ${scale5}/5
        </td>
        <td class="py-3 px-4 text-right">
          <button class="px-2.5 py-1 bg-sky-950 hover:bg-sky-800 text-sky-300 border border-sky-800 rounded text-xs transition-colors" onclick="event.stopPropagation(); inspectThreat('${t.id}')">
            Details
          </button>
        </td>
      </tr>
    `;
    })
    .join("");

  document.getElementById("filtered-threat-count").innerText = `${filtered.length} of ${state.activeThreats.length} scenarios`;
}

// Inspect Threat Modal / Drawer
function inspectThreat(threatId) {
  const t = state.activeThreats.find((item) => item.id === threatId);
  if (!t) return;

  state.selectedThreat = t;
  const r = calcNumericRisk(t.likelihood, t.impact);
  const tol = calcTolerability(r);
  const scale5 = calcFivePointScale(r);
  const style = getTolerabilityColor(tol);

  const modal = document.getElementById("threat-detail-modal");
  const body = document.getElementById("threat-modal-content");

  const mitigatedR = calcNumericRisk(t.mitigatedLikelihood || t.likelihood, t.mitigatedImpact || t.impact);
  const mitigatedTol = calcTolerability(mitigatedR);
  const mitigatedStyle = getTolerabilityColor(mitigatedTol);

  body.innerHTML = `
    <div class="flex items-start justify-between border-b border-slate-800 pb-4">
      <div>
        <div class="flex items-center space-x-2">
          <span class="px-2.5 py-0.5 rounded text-xs font-mono font-bold bg-sky-950 text-sky-300 border border-sky-800">${t.id}</span>
          <span class="px-2.5 py-0.5 rounded text-xs uppercase font-bold bg-slate-800 text-slate-300">${t.domain}</span>
          <span class="px-2.5 py-0.5 rounded text-xs uppercase font-bold bg-slate-800 text-purple-300">${t.ciaTriad}</span>
        </div>
        <h3 class="text-xl font-bold text-white mt-2">${t.asset}: ${t.threatType}</h3>
        <p class="text-xs text-slate-400 font-mono">Reference: ${t.figure || "Section II-VI"}</p>
      </div>
      <div class="text-right">
        <span class="px-3 py-1.5 text-xs rounded-full uppercase tracking-wider font-bold ${style.badge}">
          ${tol}
        </span>
        <div class="text-xs font-mono text-slate-400 mt-1">Scale: ${scale5}/5</div>
      </div>
    </div>

    ${
      t.isRealtime && t.prediction
        ? `
      <div class="bg-gradient-to-r from-red-950/40 via-purple-950/30 to-slate-900 border border-red-700/60 rounded-lg p-3.5 space-y-2.5 my-3">
        <div class="flex items-center justify-between">
          <div class="flex items-center space-x-2">
            <span class="w-2.5 h-2.5 rounded-full bg-red-500 animate-ping"></span>
            <h4 class="text-xs font-bold uppercase font-mono text-red-400">Blue Team Sensor Feed & AI Attack Forecaster</h4>
          </div>
          <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-red-900/60 text-red-200 border border-red-600">
            ${t.prediction.probability}% Attack Probability
          </span>
        </div>
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono">
          <div class="p-2 bg-slate-950/80 rounded border border-slate-800">
            <span class="text-[10px] text-slate-500 uppercase">Live Sensor Telemetry</span>
            <div class="text-emerald-400 mt-0.5 font-bold truncate">${t.liveTelemetry || "Nominal RF / Avionics Link"}</div>
          </div>
          <div class="p-2 bg-slate-950/80 rounded border border-slate-800">
            <span class="text-[10px] text-slate-500 uppercase">Projected Time to Impact</span>
            <div class="text-amber-400 mt-0.5 font-bold">${t.prediction.timeToImpact || "Immediate"}</div>
          </div>
        </div>
        <div class="text-[11px] font-mono text-slate-300">
          <span class="text-slate-500">Predicted Threat Scenario:</span> <span class="text-white font-bold">${t.prediction.predictedAttack}</span> · <span class="text-slate-500">Target Track:</span> <span class="text-sky-300">${t.prediction.targetFlight}</span>
        </div>
      </div>
      `
        : ""
    }

    <div class="grid grid-cols-1 md:grid-cols-3 gap-4 my-4">
      <div class="bg-slate-900/90 border border-slate-800 rounded p-3 text-center">
        <div class="text-[11px] text-slate-400 uppercase font-mono">Likelihood (L)</div>
        <div class="text-2xl font-bold font-mono text-pink-400 mt-1">${t.likelihood.toFixed(1)} / 5</div>
        <div class="text-[10px] text-slate-500 mt-0.5">${getLikelihoodRatingDesc(t.likelihood)}</div>
      </div>
      <div class="bg-slate-900/90 border border-slate-800 rounded p-3 text-center">
        <div class="text-[11px] text-slate-400 uppercase font-mono">Impact (I)</div>
        <div class="text-2xl font-bold font-mono text-sky-400 mt-1">${t.impact.toFixed(1)} / 5</div>
        <div class="text-[10px] text-slate-500 mt-0.5">${getImpactRatingDesc(t.impact)}</div>
      </div>
      <div class="bg-slate-900/90 border border-slate-800 rounded p-3 text-center">
        <div class="text-[11px] text-slate-400 uppercase font-mono">Risk Level (r = L x I)</div>
        <div class="text-2xl font-bold font-mono ${style.text} mt-1">${r.toFixed(1)} / 25</div>
        <div class="text-[10px] text-slate-500 mt-0.5">${tol.toUpperCase()} RISK</div>
      </div>
    </div>

    <div class="space-y-3 text-sm text-slate-300">
      <div>
        <h4 class="text-xs font-bold uppercase font-mono text-sky-400">Threat Description & Mechanism</h4>
        <p class="text-xs text-slate-300 mt-1 leading-relaxed">${t.description}</p>
      </div>

      <div>
        <h4 class="text-xs font-bold uppercase font-mono text-sky-400">Attack Vector & Technical Scenario</h4>
        <p class="text-xs font-mono bg-slate-900/80 p-2.5 rounded border border-slate-800 text-slate-300 leading-relaxed">${t.attackVector}</p>
      </div>

      <div>
        <h4 class="text-xs font-bold uppercase font-mono text-sky-400">Prescribed Mitigation & Control Measures</h4>
        <ul class="list-disc list-inside text-xs text-slate-300 mt-1 space-y-1">
          ${t.mitigations.map((m) => `<li>${m}</li>`).join("")}
        </ul>
      </div>

      <div class="bg-slate-900/90 border border-slate-800 rounded p-3 mt-4">
        <div class="flex items-center justify-between">
          <span class="text-xs font-bold uppercase font-mono text-emerald-400">Post-Mitigation Residual Risk Forecast</span>
          <span class="px-2 py-0.5 text-[10px] rounded uppercase font-bold ${mitigatedStyle.badge}">${mitigatedTol}</span>
        </div>
        <div class="flex items-center justify-between text-xs font-mono text-slate-300 mt-2">
          <span>Mitigated Likelihood: <strong>${(t.mitigatedLikelihood || t.likelihood).toFixed(1)}</strong></span>
          <span>Mitigated Impact: <strong>${(t.mitigatedImpact || t.impact).toFixed(1)}</strong></span>
          <span>Residual Risk: <strong>${mitigatedR.toFixed(1)}</strong> (Scale ${calcFivePointScale(mitigatedR)}/5)</span>
        </div>
      </div>
    </div>
  `;

  modal.classList.remove("hidden");
}

function closeThreatModal() {
  const modal = document.getElementById("threat-detail-modal");
  if (modal) modal.classList.add("hidden");
}

function getLikelihoodRatingDesc(l) {
  if (l >= 4.5) return "High: Easily accessible tools < $1k, basic knowledge";
  if (l >= 3.5) return "Medium-High: Available tools < $5k, basic info";
  if (l >= 2.5) return "Medium: Tools < $10k, advanced training needed";
  if (l >= 1.5) return "Medium-Low: Tools < $100k, restricted access";
  return "Low: Tools > $100k, highly restricted & complex";
}

function getImpactRatingDesc(i) {
  if (i >= 4.5) return "High: Complete service outage, safety critical";
  if (i >= 3.5) return "Medium-High: Major service loss, board approval";
  if (i >= 2.5) return "Medium: Moderate service disruption, management fix";
  if (i >= 1.5) return "Medium-Low: Minor service degradation";
  return "Low: Insignificant impact, normal operations";
}

// --- TAB 2: INTERACTIVE 5x5 ICAO RISK MATRIX (Table 4) ---
function initMatrixControls() {
  document.querySelectorAll(".matrix-mode-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      state.matrixDisplayMode = btn.getAttribute("data-mode");
      document.querySelectorAll(".matrix-mode-btn").forEach((b) => b.classList.remove("active-mode"));
      btn.classList.add("active-mode");
      renderMatrixGrid();
    });
  });

  const mitToggle = document.getElementById("matrix-mitigation-toggle");
  if (mitToggle) {
    mitToggle.addEventListener("change", (e) => {
      state.matrixMitigationToggle = e.target.checked;
      renderMatrixGrid();
    });
  }
}

function renderMatrixGrid() {
  const container = document.getElementById("risk-matrix-grid");
  if (!container) return;

  const threats = state.activeThreats;
  const useMitigated = state.matrixMitigationToggle;

  // Likelihood rows from 5 down to 1
  // Impact columns from 1 up to 5
  let html = "";

  for (let l = 5; l >= 1; l--) {
    // Likelihood label column
    html += `
      <div class="flex items-center justify-center p-2 font-mono text-xs font-bold text-slate-300 bg-slate-900 border border-slate-800">
        <div class="text-center">
          <div class="text-sm text-pink-400 font-extrabold">${l}</div>
          <div class="text-[10px] text-slate-500 uppercase font-mono">${getLikelihoodShortName(l)}</div>
        </div>
      </div>
    `;

    // 5 impact cells
    for (let i = 1; i <= 5; i++) {
      const cellNumericRisk = l * i;
      const cellTolerability = calcTolerability(cellNumericRisk);
      const cellScale5 = calcFivePointScale(cellNumericRisk);

      // Find threats falling into this cell
      const matchingThreats = threats.filter((t) => {
        const threatL = useMitigated ? t.mitigatedLikelihood || t.likelihood : t.likelihood;
        const threatI = useMitigated ? t.mitigatedImpact || t.impact : t.impact;

        // Round to nearest integer cell (1 to 5)
        const cellL = Math.min(5, Math.max(1, Math.round(threatL)));
        const cellI = Math.min(5, Math.max(1, Math.round(threatI)));
        return cellL === l && cellI === i;
      });

      // Cell color based on Table 4
      let cellBgClass = "";
      let cellBorderClass = "";
      if (cellTolerability === "intolerable") {
        cellBgClass = "bg-red-950/40 hover:bg-red-900/60";
        cellBorderClass = "border-red-600/60";
      } else if (cellTolerability === "tolerable") {
        cellBgClass = "bg-amber-950/40 hover:bg-amber-900/60";
        cellBorderClass = "border-amber-600/60";
      } else {
        cellBgClass = "bg-emerald-950/40 hover:bg-emerald-900/60";
        cellBorderClass = "border-emerald-600/60";
      }

      let displayValue = "";
      if (state.matrixDisplayMode === "r") {
        displayValue = `<span class="text-base font-bold font-mono">${cellNumericRisk}</span>`;
      } else if (state.matrixDisplayMode === "scale") {
        displayValue = `<span class="text-sm font-bold font-mono">Scale ${cellScale5}</span>`;
      } else {
        displayValue = `<span class="text-xs font-mono text-slate-400">${matchingThreats.length} threats</span>`;
      }

      html += `
        <div class="relative min-h-[96px] p-2 rounded border ${cellBorderClass} ${cellBgClass} transition-all flex flex-col justify-between group cursor-pointer" onclick="inspectMatrixCell(${l}, ${i})">
          <div class="flex items-center justify-between">
            <span class="text-[10px] font-mono text-slate-400">${displayValue}</span>
            <span class="text-[9px] uppercase font-bold px-1.5 py-0.2 rounded font-mono ${cellTolerability === "intolerable" ? "text-red-400 bg-red-950" : cellTolerability === "tolerable" ? "text-amber-400 bg-amber-950" : "text-emerald-400 bg-emerald-950"}">
              ${cellTolerability[0].toUpperCase()}
            </span>
          </div>

          <div class="flex flex-wrap gap-1 mt-1 max-h-[64px] overflow-y-auto no-scrollbar">
            ${matchingThreats
              .map(
                (t) => `
              <span class="inline-flex items-center px-1.5 py-0.5 text-[9px] font-mono font-bold rounded bg-slate-900/90 border border-slate-700 text-sky-300 hover:border-sky-400 hover:scale-105 transition-transform" title="${t.asset}: ${t.threatType} (r=${calcNumericRisk(t.likelihood, t.impact)})" onclick="event.stopPropagation(); inspectThreat('${t.id}')">
                ${t.asset} · ${t.threatType.substring(0, 7)}..
              </span>
            `
              )
              .join("")}
          </div>
        </div>
      `;
    }
  }

  container.innerHTML = html;
}

function getLikelihoodShortName(l) {
  if (l === 5) return "High";
  if (l === 4) return "Med-High";
  if (l === 3) return "Medium";
  if (l === 2) return "Med-Low";
  return "Low";
}

function inspectMatrixCell(l, i) {
  const r = l * i;
  const tol = calcTolerability(r);
  const scale5 = calcFivePointScale(r);

  const cellThreats = state.activeThreats.filter((t) => {
    const roundL = Math.min(5, Math.max(1, Math.round(t.likelihood)));
    const roundI = Math.min(5, Math.max(1, Math.round(t.impact)));
    return roundL === l && roundI === i;
  });

  const detailBox = document.getElementById("matrix-cell-inspection");
  if (!detailBox) return;

  const style = getTolerabilityColor(tol);

  detailBox.innerHTML = `
    <div class="p-4 bg-slate-900 border border-slate-800 rounded-lg">
      <div class="flex items-center justify-between border-b border-slate-800 pb-3">
        <div>
          <span class="text-xs font-mono uppercase text-slate-400">Matrix Coordinate [L=${l}, I=${i}]</span>
          <h4 class="text-base font-bold text-white mt-0.5">Cell Risk: r = ${r} (Scale ${scale5}/5)</h4>
        </div>
        <span class="px-3 py-1 rounded text-xs font-bold uppercase font-mono ${style.badge}">${tol}</span>
      </div>

      <div class="mt-3 text-xs text-slate-300">
        <div class="grid grid-cols-2 gap-2 mb-3">
          <div class="p-2 bg-slate-950 rounded border border-slate-800">
            <span class="text-[10px] text-slate-500 uppercase font-mono">Likelihood Definition</span>
            <p class="text-xs text-slate-300 mt-1">${LIKELIHOOD_TABLE.find((x) => x.scale === l)?.frequency || ""}</p>
          </div>
          <div class="p-2 bg-slate-950 rounded border border-slate-800">
            <span class="text-[10px] text-slate-500 uppercase font-mono">Impact Consequence</span>
            <p class="text-xs text-slate-300 mt-1">${IMPACT_TABLE.find((x) => x.scale === i)?.operations || ""}</p>
          </div>
        </div>

        <h5 class="text-xs font-bold uppercase font-mono text-sky-400 mt-2 mb-1.5">Aviation Threats Located in this Cell (${cellThreats.length})</h5>
        ${
          cellThreats.length === 0
            ? '<p class="text-xs text-slate-500 italic">No evaluated threats currently mapped to this exact coordinate.</p>'
            : `<div class="space-y-1.5">
                ${cellThreats
                  .map(
                    (t) => `
                  <div class="p-2 bg-slate-950 rounded border border-slate-800 flex items-center justify-between hover:border-slate-700 cursor-pointer" onclick="inspectThreat('${t.id}')">
                    <div>
                      <span class="font-mono text-xs font-bold text-sky-400 mr-2">${t.asset}</span>
                      <span class="text-xs text-slate-200">${t.threatType}</span>
                    </div>
                    <div class="text-right">
                      <span class="font-mono text-xs font-bold text-slate-300 mr-2">r=${calcNumericRisk(t.likelihood, t.impact)}</span>
                      <button class="text-[11px] text-sky-400 hover:underline">View</button>
                    </div>
                  </div>
                `
                  )
                  .join("")}
              </div>`
        }
      </div>
    </div>
  `;
}

// --- TAB 3: DOMAIN DEEP DIVES (CNS + SWIM) ---
function renderDomainCharts() {
  const dom = state.activeDomainSubtab;
  const threats = state.activeThreats.filter((t) => t.domain === dom);

  const container = document.getElementById("domain-chart-container");
  if (!container) return;

  const chartCanvas = document.getElementById("domain-specific-chart");
  if (!chartCanvas) return;

  const labels = threats.map((t) => `${t.asset}: ${t.threatType}`);
  const likelihoods = threats.map((t) => t.likelihood);
  const impacts = threats.map((t) => t.impact);
  const risks = threats.map((t) => calcFivePointScale(calcNumericRisk(t.likelihood, t.impact)));

  if (state.charts.domainSpecific) state.charts.domainSpecific.destroy();

  // Exactly replicates the visual style of Figures 3, 4, 5, 6, 7, 8, 9, 10, 11, 13
  state.charts.domainSpecific = new Chart(chartCanvas, {
    type: "bar",
    data: {
      labels: labels,
      datasets: [
        {
          label: "Likelihood (1-5)",
          data: likelihoods,
          backgroundColor: "#ec4899", // Magenta/pink as in paper figures
          borderWidth: 1,
          borderColor: "#db2777"
        },
        {
          label: "Impact (1-5)",
          data: impacts,
          backgroundColor: "#2563eb", // Blue as in paper figures
          borderWidth: 1,
          borderColor: "#1d4ed8"
        },
        {
          label: "Risk Level (5-point scale)",
          data: risks,
          backgroundColor: "#dc2626", // Red as in paper figures
          borderWidth: 1,
          borderColor: "#b91c1c"
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        y: {
          min: 0,
          max: 5,
          ticks: { stepSize: 1, color: "#94a3b8", font: { family: "JetBrains Mono" } },
          grid: { color: "#334155" },
          title: {
            display: true,
            text: "Five-Point Scale",
            color: "#94a3b8",
            font: { family: "JetBrains Mono", size: 12 }
          }
        },
        x: {
          grid: { display: false },
          ticks: {
            color: "#cbd5e1",
            font: { family: "JetBrains Mono", size: 10 },
            maxRotation: 30,
            minRotation: 15
          }
        }
      },
      plugins: {
        legend: {
          position: "top",
          labels: { color: "#e2e8f0", font: { family: "JetBrains Mono", size: 11 } }
        },
        tooltip: {
          callbacks: {
            afterBody: (ctx) => {
              const idx = ctx[0].dataIndex;
              const t = threats[idx];
              const r = calcNumericRisk(t.likelihood, t.impact);
              const tol = calcTolerability(r);
              return `Numeric Risk: r = ${r} (Tolerability: ${tol.toUpperCase()})`;
            }
          }
        }
      }
    }
  });

  // Render domain technical narrative & findings
  const narrativeBox = document.getElementById("domain-narrative-box");
  if (narrativeBox) {
    narrativeBox.innerHTML = getDomainNarrative(dom, threats);
  }
}

function getDomainNarrative(domain, threats) {
  if (domain === "Communication") {
    return `
      <div class="p-4 bg-slate-900 border border-slate-800 rounded-lg space-y-3">
        <h4 class="text-sm font-bold uppercase font-mono text-sky-400">Communication Domain Analysis (Section III)</h4>
        <p class="text-xs text-slate-300 leading-relaxed">
          The paper proves that <strong>VHF Voice Communication</strong> possesses the highest risk among all air-ground communication media. Due to its unencrypted analog AM nature and publicly listed AIP airport frequencies, VHF voice is universally eavesdropped and susceptible to intentional jamming. Most critically, <strong>VHF Voice Spoofing</strong> generates an <em>intolerable risk</em> (r=15, 5-point scale = 4), where malicious ground actors transmit unauthorized turn or altitude instructions to pilots.
        </p>
        <p class="text-xs text-slate-300 leading-relaxed">
          Conversely, <strong>CPDLC (Controller-Pilot Data Link Communication)</strong> demonstrates the lowest risk in communication (acceptable to tolerable, r=4.0 to 8.0). Selective addressing, digital VDL2 packet frames, and the barrier of specialized avionics expertise drastically reduce spoofing and eavesdropping feasibility.
        </p>
        <div class="p-2.5 bg-slate-950 rounded border border-slate-800 text-xs font-mono text-amber-300">
          ⚠️ Key Finding: Highest risk = VHF Voice (Intolerable r=15) | Lowest risk = CPDLC (Tolerable r=7.5 / Acceptable r=4.0)
        </div>
      </div>
    `;
  } else if (domain === "Navigation") {
    return `
      <div class="p-4 bg-slate-900 border border-slate-800 rounded-lg space-y-3">
        <h4 class="text-sm font-bold uppercase font-mono text-sky-400">Navigation Domain Analysis (Section IV)</h4>
        <p class="text-xs text-slate-300 leading-relaxed">
          The paper reveals that <strong>GNSS (Satellite-Based Navigation)</strong> presents the highest risk in the navigation aid spectrum (Tolerable r=14.4 for jamming, r=11.0 for spoofing, 5-point scale = 3). Satellite signals reach airborne receivers at extraordinarily low power levels (~ -160 dBW), allowing illicit $50 Personal Privacy Devices (PPDs) to trigger complete GNSS lock loss over wide terminal areas.
        </p>
        <p class="text-xs text-slate-300 leading-relaxed">
          In contrast, terrestrial radio navigation aids such as <strong>ILS (Instrument Landing System)</strong> and <strong>VOR (VHF Omnidirectional Range)</strong> exhibit much lower risk profiles (r=4.5 to 6.0). Although an ILS single-tone or overshadow attack carries severe impact on blind autolandings, the extreme difficulty and precision synchronization required keep their likelihood strictly at scale 1 (Low).
        </p>
        <div class="p-2.5 bg-slate-950 rounded border border-slate-800 text-xs font-mono text-sky-300">
          ⚠️ Key Finding: Highest risk = GNSS (r=14.4) | Lowest risk = ILS / VOR (r=4.5 to 6.0, Scale 1-2)
        </div>
      </div>
    `;
  } else if (domain === "Surveillance") {
    return `
      <div class="p-4 bg-slate-900 border border-slate-800 rounded-lg space-y-3">
        <h4 class="text-sm font-bold uppercase font-mono text-sky-400">Surveillance Domain Analysis (Section V)</h4>
        <p class="text-xs text-slate-300 leading-relaxed">
          <strong>ADS-B (Automatic Dependent Surveillance-Broadcast)</strong> emerges with the highest risk among all aeronautical surveillance technologies (r=14.7 for jamming, r=13.9 for spoofing). ADS-B 1090 MHz Extended Squitter messages are completely unencrypted and lack authentication. An adversary with a basic SDR can inject ghost aircraft, distort true trajectories, or suppress genuine aircraft squitters.
        </p>
        <p class="text-xs text-slate-300 leading-relaxed">
          Conversely, <strong>Secondary Surveillance Radar (SSR)</strong> maintains a substantially lower risk profile (r=4.3 to 7.0). SSR requires directional ground interrogation at 1030 MHz and synchronised 1090 MHz Mode S replies with high pulse power. <strong>Primary Surveillance Radar (PSR)</strong> remains the ultimate non-cooperative, un-spoofable safety fallback.
        </p>
        <div class="p-2.5 bg-slate-950 rounded border border-slate-800 text-xs font-mono text-rose-300">
          ⚠️ Key Finding: Highest risk = ADS-B (r=14.7, Scale 3) | Lowest risk = SSR & MLAT (r=4.3 to 7.0, Scale 1-2)
        </div>
      </div>
    `;
  } else {
    return `
      <div class="p-4 bg-slate-900 border border-slate-800 rounded-lg space-y-3">
        <h4 class="text-sm font-bold uppercase font-mono text-sky-400">Networking / SWIM Domain Analysis (Section VI)</h4>
        <p class="text-xs text-slate-300 leading-relaxed">
          <strong>SWIM (System-Wide Information Management)</strong> shifts global ATM from point-to-point teletypes to a net-centric, service-oriented architecture (SOA) over IP. While delivering tremendous operational efficiency across airlines, airports, ANSPs, and military units, it inherits classical IP-network attack vectors: Distributed Denial of Service (DDoS), Man-in-the-Middle (MITM), and unauthorized access.
        </p>
        <p class="text-xs text-slate-300 leading-relaxed">
          The paper evaluates SWIM cybersecurity risk at a <strong>Medium / Tolerable level (r=10.5, 5-point scale = 3)</strong>. Because SWIM operates on dedicated private IP backbones with backup manual procedures, attacks cause operational delays rather than immediate catastrophic flight loss.
        </p>
        <div class="p-2.5 bg-slate-950 rounded border border-slate-800 text-xs font-mono text-purple-300">
          ⚠️ Key Finding: Overall SWIM Cyber-Attack Risk = Medium (Tolerable r=10.5, Scale 3)
        </div>
      </div>
    `;
  }
}

// Render Protocol Technical Tables (Tables 6, 8, 10)
function renderProtocolTables() {
  const comContainer = document.getElementById("protocol-table-communication");
  if (comContainer) {
    comContainer.innerHTML = PROTOCOL_SPECIFICATIONS.communication
      .map(
        (p) => `
      <tr class="border-b border-slate-800 text-xs">
        <td class="py-2.5 px-3 font-mono font-bold text-sky-400">${p.protocol}</td>
        <td class="py-2.5 px-3 text-slate-300">${p.usage}</td>
        <td class="py-2.5 px-3 font-mono text-slate-400">${p.signal} / ${p.type}</td>
        <td class="py-2.5 px-3 font-mono text-slate-300">${p.frequencyBand}</td>
        <td class="py-2.5 px-3 font-mono text-slate-400">${p.linkLayer}</td>
        <td class="py-2.5 px-3 font-mono text-[11px] text-slate-500">${p.standards}</td>
      </tr>
    `
      )
      .join("");
  }

  const navContainer = document.getElementById("protocol-table-navigation");
  if (navContainer) {
    navContainer.innerHTML = PROTOCOL_SPECIFICATIONS.navigation
      .map(
        (p) => `
      <tr class="border-b border-slate-800 text-xs">
        <td class="py-2.5 px-3 font-mono font-bold text-sky-400">${p.system}</td>
        <td class="py-2.5 px-3 text-slate-300">${p.usage}</td>
        <td class="py-2.5 px-3 font-mono text-slate-400">${p.type}</td>
        <td class="py-2.5 px-3 font-mono text-slate-300">${p.frequencyBand}</td>
        <td class="py-2.5 px-3 text-slate-400 text-[11px]">${p.coverage}</td>
        <td class="py-2.5 px-3 font-mono text-[11px] text-rose-300/80">${p.vulnerability}</td>
      </tr>
    `
      )
      .join("");
  }

  const surContainer = document.getElementById("protocol-table-surveillance");
  if (surContainer) {
    surContainer.innerHTML = PROTOCOL_SPECIFICATIONS.surveillance
      .map(
        (p) => `
      <tr class="border-b border-slate-800 text-xs">
        <td class="py-2.5 px-3 font-mono font-bold text-sky-400">${p.technique}</td>
        <td class="py-2.5 px-3 text-slate-300">${p.concept}</td>
        <td class="py-2.5 px-3 text-slate-300">${p.info}</td>
        <td class="py-2.5 px-3 font-mono text-slate-300">${p.freqBand}</td>
        <td class="py-2.5 px-3 font-mono text-slate-400">${p.updateRate}</td>
        <td class="py-2.5 px-3 font-mono text-[11px] text-slate-500">${p.standards}</td>
      </tr>
    `
      )
      .join("");
  }
}

// --- TAB 4: ALGORITHM 1 INTERACTIVE EVALUATOR ---
function initEvaluator() {
  // Bind step-by-step inputs
  const lFactors = ["eval-cost", "eval-accessibility", "eval-frequency", "eval-expertise"];
  lFactors.forEach((id) => {
    const el = document.getElementById(id);
    if (el) {
      el.addEventListener("change", updateEvaluatorCalculations);
    }
  });

  const iFactors = ["eval-operations", "eval-finance", "eval-reputation"];
  iFactors.forEach((id) => {
    const el = document.getElementById(id);
    if (el) {
      el.addEventListener("change", updateEvaluatorCalculations);
    }
  });

  const manualL = document.getElementById("eval-manual-l");
  const manualI = document.getElementById("eval-manual-i");
  if (manualL) manualL.addEventListener("input", updateEvaluatorCalculations);
  if (manualI) manualI.addEventListener("input", updateEvaluatorCalculations);

  const saveBtn = document.getElementById("eval-save-btn");
  if (saveBtn) {
    saveBtn.addEventListener("click", saveCustomEvaluatedThreat);
  }

  updateEvaluatorCalculations();
}

function updateEvaluatorCalculations() {
  // Calculate recommended Likelihood L from 4 Table 2 dimensions
  const cost = Number(document.getElementById("eval-cost")?.value || 5);
  const acc = Number(document.getElementById("eval-accessibility")?.value || 5);
  const freq = Number(document.getElementById("eval-frequency")?.value || 5);
  const exp = Number(document.getElementById("eval-expertise")?.value || 5);

  const avgL = Number(((cost + acc + freq + exp) / 4).toFixed(1));

  // Calculate recommended Impact I from 3 Table 3 dimensions
  const ops = Number(document.getElementById("eval-operations")?.value || 5);
  const fin = Number(document.getElementById("eval-finance")?.value || 5);
  const rep = Number(document.getElementById("eval-reputation")?.value || 5);

  const avgI = Number(((ops + fin + rep) / 3).toFixed(1));

  // Determine actual L & I (allow override if manual checkbox enabled)
  const useManual = document.getElementById("eval-override-toggle")?.checked || false;
  let finalL = avgL;
  let finalI = avgI;

  if (useManual) {
    finalL = Number(document.getElementById("eval-manual-l")?.value || avgL);
    finalI = Number(document.getElementById("eval-manual-i")?.value || avgI);
  } else {
    const ml = document.getElementById("eval-manual-l");
    const mi = document.getElementById("eval-manual-i");
    if (ml) ml.value = avgL;
    if (mi) mi.value = avgI;
  }

  // Algorithm 1 Step 7: r = L x I (Eq. 1)
  const r = calcNumericRisk(finalL, finalI);

  // Algorithm 1 Step 8: Categorize r into R (Eq. 2)
  const tol = calcTolerability(r);

  // Algorithm 1 Step 9: Convert r to 5-point scale (Table 5)
  const scale5 = calcFivePointScale(r);

  // Update UI output cards
  const lOut = document.getElementById("eval-result-l");
  const iOut = document.getElementById("eval-result-i");
  const rOut = document.getElementById("eval-result-r");
  const tolBadge = document.getElementById("eval-result-tolerability");
  const scaleOut = document.getElementById("eval-result-scale");

  const style = getTolerabilityColor(tol);

  if (lOut) lOut.innerText = finalL.toFixed(1);
  if (iOut) iOut.innerText = finalI.toFixed(1);
  if (rOut) {
    rOut.innerText = r.toFixed(1);
    rOut.className = `text-4xl font-extrabold font-mono ${style.text}`;
  }
  if (tolBadge) {
    tolBadge.innerText = tol.toUpperCase();
    tolBadge.className = `px-3 py-1 rounded text-xs font-bold uppercase tracking-wider font-mono ${style.badge}`;
  }
  if (scaleOut) {
    scaleOut.innerText = `Scale ${scale5} of 5`;
  }

  // Update Action Recommendation Banner
  const actionBanner = document.getElementById("eval-action-recommendation");
  if (actionBanner) {
    if (tol === "intolerable") {
      actionBanner.innerHTML = `
        <div class="p-3 bg-red-950/60 border border-red-500 rounded text-xs text-red-200 flex items-start space-x-2">
          <span class="text-base">🚨</span>
          <div>
            <strong>UNACCEPTABLE RISK LEVEL (r ≥ 15):</strong> Immediate risk mitigation and operational control measures are mandatory before flight operations can proceed safely.
          </div>
        </div>
      `;
    } else if (tol === "tolerable") {
      actionBanner.innerHTML = `
        <div class="p-3 bg-amber-950/60 border border-amber-500 rounded text-xs text-amber-200 flex items-start space-x-2">
          <span class="text-base">⚠️</span>
          <div>
            <strong>TOLERABLE RISK LEVEL (5 ≤ r < 15):</strong> Risk can be tolerated based on active mitigations and continuous monitoring. Review contingency procedures.
          </div>
        </div>
      `;
    } else {
      actionBanner.innerHTML = `
        <div class="p-3 bg-emerald-950/60 border border-emerald-500 rounded text-xs text-emerald-200 flex items-start space-x-2">
          <span class="text-base">✅</span>
          <div>
            <strong>ACCEPTABLE RISK LEVEL (r < 5):</strong> Risk index is within tolerable safety boundaries. No further risk mitigation measures strictly required.
          </div>
        </div>
      `;
    }
  }
}

function saveCustomEvaluatedThreat() {
  const asset = document.getElementById("eval-asset-name")?.value.trim();
  const domain = document.getElementById("eval-domain")?.value || "Communication";
  const threatType = document.getElementById("eval-threat-name")?.value.trim();
  const ciaTriad = document.getElementById("eval-cia")?.value || "Integrity";
  const description = document.getElementById("eval-desc")?.value.trim() || "Custom evaluated threat scenario.";
  const mitigationsText = document.getElementById("eval-mitigations")?.value.trim() || "Standard aviation safety protocols.";

  if (!asset || !threatType) {
    alert("Please enter both an Asset Name and a Cyber-Attack Threat Scenario.");
    return;
  }

  const finalL = Number(document.getElementById("eval-manual-l")?.value || 3.0);
  const finalI = Number(document.getElementById("eval-manual-i")?.value || 3.0);

  const customId = `CUST-${domain.substring(0, 3).toUpperCase()}-${String(state.activeThreats.length + 1).padStart(2, "0")}`;

  const newThreat = {
    id: customId,
    domain: domain,
    asset: asset,
    threatType: threatType,
    category: "Custom Evaluation",
    ciaTriad: ciaTriad,
    likelihood: finalL,
    impact: finalI,
    figure: "Custom Evaluator",
    attackVector: description,
    description: description,
    mitigations: mitigationsText.split("\n").filter((x) => x.trim().length > 0),
    mitigatedLikelihood: Math.max(1.0, finalL - 1.5),
    mitigatedImpact: Math.max(1.0, finalI - 1.0)
  };

  state.activeThreats.push(newThreat);
  renderAll();
  alert(`Threat "${asset}: ${threatType}" successfully calculated (r=${calcNumericRisk(finalL, finalI)}) and added to the Risk Registry and Matrix!`);
  switchTab("matrix");
}

// --- TAB 5: WHAT-IF MITIGATION SIMULATOR ---
function initSimulator() {
  const toggles = document.querySelectorAll(".sim-toggle");
  toggles.forEach((t) => {
    t.addEventListener("change", updateSimulatorResults);
  });
  updateSimulatorResults();
}

function updateSimulatorResults() {
  const arinc = document.getElementById("sim-arinc-crypto")?.checked || false;
  const multiGnss = document.getElementById("sim-multi-gnss")?.checked || false;
  const ssrFusion = document.getElementById("sim-ssr-fusion")?.checked || false;
  const tdoaMl = document.getElementById("sim-tdoa-ml")?.checked || false;
  const swimPki = document.getElementById("sim-swim-pki")?.checked || false;
  const strictHearback = document.getElementById("sim-strict-hearback")?.checked || false;

  let totalOriginalRisk = 0;
  let totalSimulatedRisk = 0;
  let originalIntolerable = 0;
  let simulatedIntolerable = 0;

  const simThreats = state.activeThreats.map((t) => {
    const origR = calcNumericRisk(t.likelihood, t.impact);
    totalOriginalRisk += origR;
    if (calcTolerability(origR) === "intolerable") originalIntolerable++;

    let simL = t.likelihood;
    let simI = t.impact;

    // Apply specific mitigations based on asset & threat type
    if (t.asset === "VHF Voice" && t.threatType === "Spoofing" && strictHearback) {
      simL = Math.max(1.0, simL - 1.5);
      simI = Math.max(1.0, simI - 2.0);
    }
    if ((t.asset === "CPDLC" || t.asset === "ACARS") && arinc) {
      simL = Math.max(1.0, simL - 1.0);
      simI = Math.max(1.0, simI - 2.0);
    }
    if (t.asset === "GNSS" && multiGnss) {
      if (t.threatType === "Jamming") simL = Math.max(1.0, simL - 2.5);
      if (t.threatType === "Spoofing") simL = Math.max(1.0, simL - 1.2);
      simI = Math.max(1.0, simI - 1.0);
    }
    if (t.asset === "SSR" && ssrFusion) {
      if (t.threatType.includes("Spoofing")) simL = Math.max(1.0, simL - 0.5);
      simI = Math.max(1.0, simI - 2.5);
    }
    if (t.asset === "ADS-B" && tdoaMl) {
      if (t.threatType.includes("Spoofing")) {
        simL = Math.max(1.0, simL - 1.5);
        simI = Math.max(1.0, simI - 2.0);
      }
      if (t.threatType === "Jamming") {
        simI = Math.max(1.0, simI - 1.5);
      }
    }
    if (t.asset === "SWIM" && swimPki) {
      simL = Math.max(1.0, simL - 1.8);
      simI = Math.max(1.0, simI - 1.0);
    }

    const newR = calcNumericRisk(simL, simI);
    totalSimulatedRisk += newR;
    if (calcTolerability(newR) === "intolerable") simulatedIntolerable++;

    return {
      ...t,
      simL,
      simI,
      origR,
      newR,
      diff: Number((origR - newR).toFixed(1))
    };
  });

  const riskReductionPct = totalOriginalRisk ? Math.round(((totalOriginalRisk - totalSimulatedRisk) / totalOriginalRisk) * 100) : 0;

  document.getElementById("sim-reduction-pct").innerText = `${riskReductionPct}%`;
  document.getElementById("sim-intolerable-before").innerText = originalIntolerable;
  document.getElementById("sim-intolerable-after").innerText = simulatedIntolerable;
  document.getElementById("sim-total-risk-before").innerText = totalOriginalRisk.toFixed(1);
  document.getElementById("sim-total-risk-after").innerText = totalSimulatedRisk.toFixed(1);

  // Render top mitigated threats
  const tableBody = document.getElementById("sim-results-table-body");
  if (tableBody) {
    const sorted = [...simThreats].sort((a, b) => b.diff - a.diff).slice(0, 7);
    tableBody.innerHTML = sorted
      .map((item) => {
        const origTol = calcTolerability(item.origR);
        const newTol = calcTolerability(item.newR);
        const origStyle = getTolerabilityColor(origTol);
        const newStyle = getTolerabilityColor(newTol);

        return `
        <tr class="border-b border-slate-800 text-xs">
          <td class="py-2.5 px-3 font-mono text-sky-400 font-bold">${item.asset}</td>
          <td class="py-2.5 px-3 text-slate-300">${item.threatType}</td>
          <td class="py-2.5 px-3 font-mono text-center">
            <span class="px-2 py-0.5 rounded text-[11px] ${origStyle.bg} ${origStyle.text} border ${origStyle.border}">
              ${item.origR.toFixed(1)} (${origTol.toUpperCase()})
            </span>
          </td>
          <td class="py-2.5 px-3 font-mono text-center font-bold">
            <span class="px-2 py-0.5 rounded text-[11px] ${newStyle.bg} ${newStyle.text} border ${newStyle.border}">
              ${item.newR.toFixed(1)} (${newTol.toUpperCase()})
            </span>
          </td>
          <td class="py-2.5 px-3 font-mono text-center font-bold text-emerald-400">
            -${item.diff} pts
          </td>
        </tr>
      `;
      })
      .join("");
  }
}

// --- TAB 7: LITERATURE SURVEY BENCHMARK (Table 1) ---
function renderLiteratureBenchmark() {
  const container = document.getElementById("literature-table-body");
  if (!container) return;

  container.innerHTML = LITERATURE_SURVEY_TABLE.map((row) => {
    const isProposed = row.paper.includes("Proposed Study");
    return `
      <tr class="border-b border-slate-800 text-xs ${isProposed ? "bg-sky-950/40 font-semibold" : "hover:bg-slate-800/30"}">
        <td class="py-3 px-4 ${isProposed ? "text-sky-300 font-bold" : "text-slate-300"}">${row.paper}</td>
        <td class="py-3 px-4 font-mono text-center ${row.communication === "No" ? "text-slate-500" : isProposed ? "text-emerald-400 font-bold" : "text-slate-300"}">${row.communication}</td>
        <td class="py-3 px-4 font-mono text-center ${row.navigation === "No" ? "text-slate-500" : isProposed ? "text-emerald-400 font-bold" : "text-slate-300"}">${row.navigation}</td>
        <td class="py-3 px-4 font-mono text-center ${row.surveillance === "No" ? "text-slate-500" : isProposed ? "text-emerald-400 font-bold" : "text-slate-300"}">${row.surveillance}</td>
        <td class="py-3 px-4 font-mono text-center ${row.swim === "No" ? "text-slate-500" : isProposed ? "text-emerald-400 font-bold" : "text-slate-300"}">${row.swim}</td>
        <td class="py-3 px-4 font-mono text-center ${row.riskMethodology === "No" ? "text-red-400" : "text-emerald-400 font-bold"}">${row.riskMethodology}</td>
        <td class="py-3 px-4 text-slate-400 text-[11px]">${row.notes}</td>
      </tr>
    `;
  }).join("");
}

// --- TAB 8: AUDIT & EXPORT ---
function exportThreatsJSON() {
  const threats = state.activeThreats.map((t) => {
    const r = calcNumericRisk(t.likelihood, t.impact);
    return {
      id: t.id,
      domain: t.domain,
      asset: t.asset,
      threatType: t.threatType,
      ciaTriad: t.ciaTriad,
      likelihood: t.likelihood,
      impact: t.impact,
      numericRisk: r,
      tolerability: calcTolerability(r),
      fivePointScale: calcFivePointScale(r),
      attackVector: t.attackVector,
      mitigations: t.mitigations
    };
  });

  const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(threats, null, 2));
  const dlAnchorElem = document.createElement("a");
  dlAnchorElem.setAttribute("href", dataStr);
  dlAnchorElem.setAttribute("download", `aviation_cybersecurity_assessment_${new Date().toISOString().slice(0, 10)}.json`);
  dlAnchorElem.click();
}

function exportThreatsCSV() {
  const headers = ["ID", "Domain", "Asset", "Threat Scenario", "CIA Triad", "Likelihood (L)", "Impact (I)", "Risk (r=LxI)", "Tolerability (R)", "5-Point Scale", "Attack Vector"];
  const rows = state.activeThreats.map((t) => {
    const r = calcNumericRisk(t.likelihood, t.impact);
    return [
      t.id,
      t.domain,
      `"${t.asset}"`,
      `"${t.threatType}"`,
      t.ciaTriad,
      t.likelihood,
      t.impact,
      r,
      calcTolerability(r),
      calcFivePointScale(r),
      `"${(t.attackVector || "").replace(/"/g, '""')}"`
    ];
  });

  const csvContent = "data:text/csv;charset=utf-8," + [headers.join(","), ...rows.map((e) => e.join(","))].join("\n");
  const encodedUri = encodeURI(csvContent);
  const link = document.createElement("a");
  link.setAttribute("href", encodedUri);
  link.setAttribute("download", `aviation_cybersecurity_assessment_${new Date().toISOString().slice(0, 10)}.csv`);
  link.click();
}

function printAuditReport() {
  window.print();
}

// --- CUSTOM TELEMETRY MODAL & STREAM INGESTION ---
function openCustomTelemetryModal() {
  const modal = document.getElementById("telemetry-ingest-modal");
  if (modal) {
    modal.classList.remove("hidden");
    const payloadEl = document.getElementById("telemetry-json-payload");
    if (payloadEl && !payloadEl.value.trim()) {
      loadPresetTelemetry("gps_jam");
    }
  }
}

function closeCustomTelemetryModal() {
  const modal = document.getElementById("telemetry-ingest-modal");
  if (modal) modal.classList.add("hidden");
}

function loadPresetTelemetry(type) {
  const payloadEl = document.getElementById("telemetry-json-payload");
  if (!payloadEl) return;

  let sample = {};
  switch (type) {
    case "gps_jam":
      sample = {
        callsign: "UAL421",
        gnssSnr: 16.4,
        gnssJammed: true,
        rfNoiseFloorDbm: -72.0,
        satellitesLocked: 2,
        notes: "Intentional high-power L1 jamming detected on approach"
      };
      break;
    case "adsb_ghost":
      sample = {
        callsign: "AAL104",
        claimedX: 12.8,
        claimedY: -6.4,
        trueX: 4.2,
        trueY: -2.1,
        adsbSpoofed: true,
        primaryRadarEchoDbsm: 0.0,
        notes: "Ghost Mode S transponder track without physical PSR return"
      };
      break;
    case "vhf_spoof":
      sample = {
        callsign: "DAL883",
        vhfAnomaly: true,
        assignedFrequency: "124.500 MHz",
        clearance: "Rogue ground station transmitting descent instruction to FL040",
        notes: "Unauthorized AM voice transmission detected on sector frequency"
      };
      break;
    case "nominal":
      sample = {
        callsign: "UAL421",
        gnssSnr: 47.1,
        gnssJammed: false,
        claimedX: 0.0,
        trueX: 0.0,
        transponderRate: 360,
        vhfAnomaly: false,
        notes: "Nominal operational state. All sensors within standard ICAO thresholds."
      };
      break;
  }

  payloadEl.value = JSON.stringify(sample, null, 2);
}

function submitCustomTelemetryPacket() {
  const payloadEl = document.getElementById("telemetry-json-payload");
  if (!payloadEl) return;

  try {
    const packet = JSON.parse(payloadEl.value);
    if (typeof airspaceSim !== "undefined") {
      const res = airspaceSim.processCustomTelemetryPacket(packet);
      if (res && res.success) {
        setDataSource("live");
        closeCustomTelemetryModal();
        switchTab("live-sim");
        alert(`Telemetry Ingested for Flight ${res.flight}!\nAlgorithm 1 Risk Re-evaluated: r = ${res.risk.r} (${res.risk.tol.toUpperCase()}).\nLive prediction engine updated!`);
      } else {
        alert("Failed to process packet: " + (res?.error || "Unknown error"));
      }
    }
  } catch (err) {
    alert("Invalid JSON format in telemetry payload:\n" + err.message);
  }
}
