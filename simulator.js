/**
 * Civil Aviation Cybersecurity Live Airspace Simulator & Attack Prediction Engine
 * Implements:
 * - Real-time Airspace Kinematics (ADS-B, VHF, GNSS, SSR, CPDLC, SWIM)
 * - Dynamic Cyber-Attack Injection Deck (Red Team)
 * - Predictive AI Anomaly Detection & Threat Forecasting Engine (Blue Team)
 * - Dynamic Real-Time Algorithm 1 Risk Re-Assessment (r = L x I, Tolerability R)
 * - Multi-Layer Active Countermeasure Defense Response
 * - Custom Telemetry & Red/Blue Feed Ingestion
 */

class AirspaceSimulator {
  constructor() {
    this.canvas = null;
    this.ctx = null;
    this.isRunning = true;
    this.simSpeed = 1; // 1x, 2x, 5x
    this.simTime = 0; // seconds
    this.radarAngle = 0; // sweep angle in radians
    this.selectedFlightId = "UAL421";
    this.onThreatsUpdated = null;
    this.lastThreatUpdateTime = 0;

    // Sector dimensions (nautical miles, centered at 0,0 - Terminal Radar Approach Control TRACON)
    this.sectorRadius = 35; // NM

    // 4 Ground MLAT / TDoA Sensor Stations (positions in NM from airport center)
    this.mlatStations = [
      { id: "MLAT-N", name: "North Station", x: 0, y: 22 },
      { id: "MLAT-E", name: "East Station", x: 22, y: 0 },
      { id: "MLAT-S", name: "South Station", x: 0, y: -22 },
      { id: "MLAT-W", name: "West Station", x: -22, y: 0 }
    ];

    // Airport & Runways (Center: 0, 0)
    this.runways = [
      { name: "09L/27R", length: 4.0, heading: 90, x: -1, y: 0.5 },
      { name: "09R/27L", length: 3.5, heading: 90, x: -1, y: -0.5 }
    ];

    // Navigation Waypoints (in NM)
    this.waypoints = [
      { name: "NOXUS", x: -25, y: 18 },
      { name: "MIDZY", x: 24, y: 20 },
      { name: "KAPPO", x: 26, y: -18 },
      { name: "DANDY", x: -24, y: -20 },
      { name: "ILS27", x: 14, y: 0.5 },
      { name: "ILS09", x: -14, y: -0.5 }
    ];

    // Active Fleet of Commercial Flights
    this.flights = [
      {
        id: "UAL421",
        callsign: "UAL421",
        aircraftType: "A320",
        trueX: -26,
        trueY: 15,
        claimedX: -26,
        claimedY: 15,
        altitude: 12000,
        targetAltitude: 4000,
        speed: 260,
        heading: 125,
        flightPhase: "Approach",
        destination: "RWY 27R",
        assignedFrequency: "124.500 MHz",
        gnssSnr: 45, // dB-Hz (nominal 40-50)
        gnssSpoofed: false,
        gnssJammed: false,
        adsbSpoofed: false,
        adsbDropped: false,
        vhfSpoofed: false,
        transponderRate: 350, // interrogations/sec
        transponderSuppressed: false,
        cpdlcTampered: false,
        activeThreat: null,
        risk: { L: 2.0, I: 3.0, r: 6.0, tol: "tolerable", scale: 2 }
      },
      {
        id: "DLH338",
        callsign: "DLH338",
        aircraftType: "B738",
        trueX: 18,
        trueY: 2,
        claimedX: 18,
        claimedY: 2,
        altitude: 4000,
        targetAltitude: 2000,
        speed: 180,
        heading: 270,
        flightPhase: "Final Approach",
        destination: "RWY 27R",
        assignedFrequency: "118.700 MHz",
        gnssSnr: 46,
        gnssSpoofed: false,
        gnssJammed: false,
        adsbSpoofed: false,
        adsbDropped: false,
        vhfSpoofed: false,
        transponderRate: 420,
        transponderSuppressed: false,
        cpdlcTampered: false,
        activeThreat: null,
        risk: { L: 2.0, I: 4.0, r: 8.0, tol: "tolerable", scale: 2 }
      },
      {
        id: "EGY701",
        callsign: "EGY701",
        aircraftType: "B789",
        trueX: -28,
        trueY: -16,
        claimedX: -28,
        claimedY: -16,
        altitude: 28000,
        targetAltitude: 24000,
        speed: 420,
        heading: 55,
        flightPhase: "En-Route Descent",
        destination: "METRO INTL",
        assignedFrequency: "132.850 MHz",
        gnssSnr: 47,
        gnssSpoofed: false,
        gnssJammed: false,
        adsbSpoofed: false,
        adsbDropped: false,
        vhfSpoofed: false,
        transponderRate: 280,
        transponderSuppressed: false,
        cpdlcTampered: false,
        activeThreat: null,
        risk: { L: 1.5, I: 3.0, r: 4.5, tol: "acceptable", scale: 1 }
      },
      {
        id: "BAW117",
        callsign: "BAW117",
        aircraftType: "A359",
        trueX: 25,
        trueY: -20,
        claimedX: 25,
        claimedY: -20,
        altitude: 34000,
        targetAltitude: 34000,
        speed: 470,
        heading: 310,
        flightPhase: "En-Route",
        destination: "EGLL OVERFLIGHT",
        assignedFrequency: "132.850 MHz",
        gnssSnr: 48,
        gnssSpoofed: false,
        gnssJammed: false,
        adsbSpoofed: false,
        adsbDropped: false,
        vhfSpoofed: false,
        transponderRate: 260,
        transponderSuppressed: false,
        cpdlcTampered: false,
        activeThreat: null,
        risk: { L: 1.5, I: 2.0, r: 3.0, tol: "acceptable", scale: 1 }
      },
      {
        id: "AFR502",
        callsign: "AFR502",
        aircraftType: "B77W",
        trueX: 2,
        trueY: 26,
        claimedX: 2,
        claimedY: 26,
        altitude: 16000,
        targetAltitude: 10000,
        speed: 280,
        heading: 195,
        flightPhase: "Approach",
        destination: "RWY 27L",
        assignedFrequency: "124.500 MHz",
        gnssSnr: 44,
        gnssSpoofed: false,
        gnssJammed: false,
        adsbSpoofed: false,
        adsbDropped: false,
        vhfSpoofed: false,
        transponderRate: 390,
        transponderSuppressed: false,
        cpdlcTampered: false,
        activeThreat: null,
        risk: { L: 2.0, I: 3.0, r: 6.0, tol: "tolerable", scale: 2 }
      },
      {
        id: "SVA204",
        callsign: "SVA204",
        aircraftType: "A321",
        trueX: 2,
        trueY: -2,
        claimedX: 2,
        claimedY: -2,
        altitude: 3200,
        targetAltitude: 18000,
        speed: 220,
        heading: 85,
        flightPhase: "Climb / Departure",
        destination: "OEJN",
        assignedFrequency: "118.700 MHz",
        gnssSnr: 45,
        gnssSpoofed: false,
        gnssJammed: false,
        adsbSpoofed: false,
        adsbDropped: false,
        vhfSpoofed: false,
        transponderRate: 460,
        transponderSuppressed: false,
        cpdlcTampered: false,
        activeThreat: null,
        risk: { L: 2.0, I: 3.5, r: 7.0, tol: "tolerable", scale: 2 }
      }
    ];

    // Ghost aircraft injected dynamically by attacks
    this.ghostAircraft = [];

    // RF Jamming Zones (centers in NM, radius in NM, intensity)
    this.jammingZones = [];

    // Active Attack Scenarios
    this.activeAttacks = [];

    // Attack Prediction & Forensics Event Stream
    this.predictedThreats = [];
    this.eventLog = [];

    // Countermeasures State (Toggled by user or automated defense)
    this.defense = {
      psrSsrFusion: false, // eliminates ghost targets from primary radar checks
      multiFreqGnss: false, // resists single-frequency GPS jamming
      autoFreqHop: false, // automatic VHF backup frequency switch
      tdoaMlVerification: false // restores true ADS-B coordinates using ML TDoA
    };

    // Statistical Counters
    this.stats = {
      predictionsGenerated: 0,
      attacksDetected: 0,
      attacksNeutralized: 0,
      intolerableEvents: 0
    };
  }

  init(canvasId) {
    this.canvas = document.getElementById(canvasId);
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext("2d");

    // Add canvas click interaction to select flights
    this.canvas.addEventListener("click", (e) => {
      this.handleCanvasClick(e);
    });

    if (!this.loopStarted) {
      this.loopStarted = true;
      this.lastTimestamp = performance.now();
      requestAnimationFrame(this.loop.bind(this));
    }

    this.renderActiveAttacksUI();
    this.renderPredictionCards();
    this.refreshTelemetryUI();
    this.renderFlightPills();
    this.logEvent("SYSTEM_INIT", "Civil Aviation Real-Time Cybersecurity Radar & Simulation Online", "INFO");
  }

  handleCanvasClick(e) {
    const rect = this.canvas.getBoundingClientRect();
    const clickX = e.clientX - rect.left;
    const clickY = e.clientY - rect.top;

    const width = this.canvas.width;
    const height = this.canvas.height;
    const centerX = width / 2;
    const centerY = height / 2;
    const scale = (Math.min(width, height) * 0.42) / this.sectorRadius;

    // Convert click to NM coordinates
    const nmX = (clickX - centerX) / scale;
    const nmY = (centerY - clickY) / scale;

    for (const f of this.flights) {
      const dist = Math.hypot(f.claimedX - nmX, f.claimedY - nmY);
      if (dist < 4.0) {
        this.selectFlight(f.id);
        return;
      }
    }
  }

  selectFlight(flightId) {
    this.selectedFlightId = flightId;
    const f = this.flights.find((x) => x.id === flightId);
    if (f) {
      this.updateTelemetryCard(f);
    }
    this.renderFlightPills();
  }

  renderFlightPills() {
    const container = document.getElementById("sim-flight-selector-pills");
    if (!container) return;

    container.innerHTML = this.flights
      .map((f) => {
        const isSelected = f.id === this.selectedFlightId;
        let badgeColor = "border-emerald-500/50 text-emerald-400 bg-slate-950";
        if (f.risk.tol === "intolerable") badgeColor = "border-red-500 text-red-400 bg-red-950/40 animate-pulse";
        else if (f.risk.tol === "tolerable") badgeColor = "border-amber-500/50 text-amber-400 bg-amber-950/20";

        const selectedStyle = isSelected ? "ring-2 ring-sky-400 font-bold" : "opacity-80 hover:opacity-100";

        return `
        <button class="px-2.5 py-1 text-xs font-mono rounded border ${badgeColor} ${selectedStyle} transition-all flex items-center space-x-1.5" onclick="airspaceSim.selectFlight('${f.id}')">
          <span>${f.callsign}</span>
          <span class="text-[10px] text-slate-400">r=${f.risk.r}</span>
        </button>
      `;
      })
      .join("");
  }

  setSpeed(speed) {
    this.simSpeed = speed;
    document.querySelectorAll(".sim-speed-btn").forEach((btn) => {
      if (btn.getAttribute("data-speed") === String(speed)) {
        btn.classList.add("bg-sky-600", "text-white");
        btn.classList.remove("bg-slate-900", "text-slate-400");
      } else {
        btn.classList.remove("bg-sky-600", "text-white");
        btn.classList.add("bg-slate-900", "text-slate-400");
      }
    });
    this.logEvent("CONFIG", `Simulation speed set to ${speed}x`, "INFO");
  }

  toggleRunning() {
    this.isRunning = !this.isRunning;
    const btn = document.getElementById("sim-play-pause-btn");
    if (btn) {
      if (this.isRunning) {
        btn.innerHTML = `<i data-lucide="pause" class="w-4 h-4 mr-1 text-amber-400"></i> Pause`;
      } else {
        btn.innerHTML = `<i data-lucide="play" class="w-4 h-4 mr-1 text-emerald-400"></i> Resume`;
      }
      if (window.lucide) lucide.createIcons();
    }
    this.logEvent("CONFIG", `Simulation ${this.isRunning ? "Resumed" : "Paused"}`, "INFO");
  }

  // Main tick loop
  loop(timestamp) {
    const deltaMs = timestamp - this.lastTimestamp;
    this.lastTimestamp = timestamp;

    if (this.isRunning) {
      const dt = (deltaMs / 1000) * this.simSpeed;
      this.tick(dt);
    }

    this.render();
    requestAnimationFrame(this.loop.bind(this));
  }

  tick(dt) {
    this.simTime += dt;
    this.radarAngle = (this.radarAngle + 1.256 * dt) % (Math.PI * 2);

    // 1. Update Flight Kinematics
    this.updateFlightKinematics(dt);

    // 2. Update Active Attacks Effects
    this.updateAttackMechanics(dt);

    // 3. Run Predictive AI Anomaly Detection Engine
    this.runAttackPredictionEngine();

    // 4. Run Real-Time Algorithm 1 Risk Re-Assessment
    this.recalculateLiveRisk();

    // 5. Update Telemetry Panels
    this.refreshTelemetryUI();

    // 6. Notify subscribers of live threats (throttled every 500ms)
    if (this.onThreatsUpdated && this.simTime - this.lastThreatUpdateTime > 0.5) {
      this.lastThreatUpdateTime = this.simTime;
      this.onThreatsUpdated(this.getLiveDynamicThreats());
    }
  }

  updateFlightKinematics(dt) {
    this.flights.forEach((f) => {
      const speedNMpS = f.speed / 3600;
      const radHeading = ((90 - f.heading) * Math.PI) / 180;

      f.trueX += Math.cos(radHeading) * speedNMpS * dt;
      f.trueY += Math.sin(radHeading) * speedNMpS * dt;

      if (Math.abs(f.altitude - f.targetAltitude) > 10) {
        const altRate = f.altitude > f.targetAltitude ? -1500 : 1500;
        f.altitude += (altRate / 60) * dt;
      }

      if (!f.adsbSpoofed) {
        f.claimedX = f.trueX;
        f.claimedY = f.trueY;
      } else {
        f.claimedX += Math.cos(radHeading + 0.35) * speedNMpS * 1.2 * dt;
        f.claimedY += Math.sin(radHeading + 0.35) * speedNMpS * 1.2 * dt;
      }

      if (Math.hypot(f.trueX, f.trueY) > this.sectorRadius + 5) {
        f.trueX = -f.trueX * 0.95;
        f.trueY = -f.trueY * 0.95;
        f.claimedX = f.trueX;
        f.claimedY = f.trueY;
      }
    });

    this.ghostAircraft.forEach((g) => {
      const speedNMpS = g.speed / 3600;
      const rad = ((90 - g.heading) * Math.PI) / 180;
      g.x += Math.cos(rad) * speedNMpS * dt;
      g.y += Math.sin(rad) * speedNMpS * dt;
    });
  }

  // =========================================================================
  // DYNAMIC THREAT GENERATOR FOR REAL-TIME ASSESSMENT & PREDICTION
  // =========================================================================
  getLiveDynamicThreats() {
    const list = [];

    // Helper: Algorithm 1 classification
    const classify = (l, i) => {
      const r = Number((l * i).toFixed(2));
      let tol = "acceptable";
      if (r >= 15.0) tol = "intolerable";
      else if (r >= 5.0) tol = "tolerable";

      let scale = 1;
      if (r >= 20.0) scale = 5;
      else if (r >= 15.0) scale = 4;
      else if (r >= 10.0) scale = 3;
      else if (r >= 5.0) scale = 2;

      return { r, tol, scale };
    };

    // 1. VHF Voice Spoofing
    const vhfTarget = this.flights.find((f) => f.vhfSpoofed);
    const vhfL = vhfTarget ? 4.5 : 2.0;
    const vhfI = vhfTarget ? 5.0 : 4.0;
    const vhfRisk = classify(vhfL, vhfI);
    list.push({
      id: "RT-COM-VHF-01",
      domain: "Communication",
      asset: "VHF Voice",
      threatType: "Rogue ATC Voice Clearance Spoofing",
      category: "RF Voice Broadcast",
      ciaTriad: "Integrity",
      likelihood: vhfL,
      impact: vhfI,
      numericRisk: vhfRisk.r,
      tolerability: vhfRisk.tol,
      fivePointScale: vhfRisk.scale,
      isRealtime: true,
      liveTelemetry: vhfTarget ? `Rogue Transmission on ${vhfTarget.assignedFrequency} · Abrupt descent to FL040` : "124.500 MHz nominal · Carrier SNR 36 dB",
      prediction: {
        predictedAttack: "Unauthorized Ground Clearance Spoofing",
        probability: vhfTarget ? 98 : 4,
        timeToImpact: vhfTarget ? "Immediate (Collision / CFIT)" : "N/A (Nominal)",
        confidence: 96,
        targetFlight: vhfTarget ? vhfTarget.callsign : "Sector-Wide"
      },
      mitigations: ["Pilot read-back/hear-back protocol", "Emergency frequency hopping to 121.900 MHz", "Secondary radar altitude verification"]
    });

    // 2. VHF Channel Jamming
    const vhfJam = this.jammingZones.length > 0;
    const vhfJamL = vhfJam ? 4.0 : 1.8;
    const vhfJamI = vhfJam ? 3.5 : 2.5;
    const vhfJamRisk = classify(vhfJamL, vhfJamI);
    list.push({
      id: "RT-COM-VHF-02",
      domain: "Communication",
      asset: "VHF Voice",
      threatType: "VHF Channel Noise Jamming",
      category: "RF Voice Broadcast",
      ciaTriad: "Availability",
      likelihood: vhfJamL,
      impact: vhfJamI,
      numericRisk: vhfJamRisk.r,
      tolerability: vhfJamRisk.tol,
      fivePointScale: vhfJamRisk.scale,
      isRealtime: true,
      liveTelemetry: vhfJam ? "Elevated RF noise floor in 118-137 MHz band (+18 dB)" : "RF Noise Floor -112 dBm (Clean)",
      prediction: {
        predictedAttack: "Wideband VHF RF Interference",
        probability: vhfJam ? 89 : 8,
        timeToImpact: vhfJam ? "Channel Congestion in 20s" : "Nominal",
        confidence: 92,
        targetFlight: "Approach Sector"
      },
      mitigations: ["Pre-designated backup frequencies", "Directional ground antennas"]
    });

    // 3. CPDLC / ACARS Data Link Tampering
    const cpdlcTarget = this.flights.find((f) => f.cpdlcTampered);
    const cpdlcL = cpdlcTarget ? 4.0 : 1.5;
    const cpdlcI = cpdlcTarget ? 4.5 : 3.0;
    const cpdlcRisk = classify(cpdlcL, cpdlcI);
    list.push({
      id: "RT-COM-CPDLC-01",
      domain: "Communication",
      asset: "CPDLC / ACARS",
      threatType: "Data Link Route Injection & Tampering",
      category: "Digital Avionics Data Link",
      ciaTriad: "Integrity",
      likelihood: cpdlcL,
      impact: cpdlcI,
      numericRisk: cpdlcRisk.r,
      tolerability: cpdlcRisk.tol,
      fivePointScale: cpdlcRisk.scale,
      isRealtime: true,
      liveTelemetry: cpdlcTarget ? `Bogus Route Amendment injected to ${cpdlcTarget.callsign} · Missing X.509 PKI Signature` : "ARINC 618 Stream Valid · PKI Validated",
      prediction: {
        predictedAttack: "Unauthenticated Waypoint Modification",
        probability: cpdlcTarget ? 93 : 5,
        timeToImpact: cpdlcTarget ? "At Next Waypoint Entry" : "Nominal",
        confidence: 91,
        targetFlight: cpdlcTarget ? cpdlcTarget.callsign : "En-Route Sector"
      },
      mitigations: ["ARINC 823 / AMS message encryption", "ECC digital signatures", "Crew waypoint verbal confirmation"]
    });

    // 4. GNSS RF Jamming
    const gnssJamFlight = this.flights.find((f) => f.gnssJammed || f.gnssSnr < 32);
    let gnssL = gnssJamFlight ? 5.0 : 2.2;
    let gnssI = gnssJamFlight ? 4.0 : 3.0;
    if (this.defense.multiFreqGnss && gnssJamFlight) {
      gnssL = 2.0;
      gnssI = 2.0;
    }
    const gnssJamRisk = classify(gnssL, gnssI);
    list.push({
      id: "RT-NAV-GNSS-01",
      domain: "Navigation",
      asset: "GNSS",
      threatType: "GPS L1 (1575.42 MHz) RF Jamming",
      category: "Satellite Navigation",
      ciaTriad: "Availability",
      likelihood: gnssL,
      impact: gnssI,
      numericRisk: gnssJamRisk.r,
      tolerability: gnssJamRisk.tol,
      fivePointScale: gnssJamRisk.scale,
      isRealtime: true,
      liveTelemetry: gnssJamFlight ? (this.defense.multiFreqGnss ? "L1 Jammed · Resilient L5 Link Active (C/N0: 39 dB-Hz)" : `C/N0: ${gnssJamFlight.gnssSnr.toFixed(1)} dB-Hz (Depleted) · Satellites: 2`) : "C/N0: 46.2 dB-Hz (Nominal) · Satellites: 9",
      prediction: {
        predictedAttack: "Targeted Radio Frequency Interference (GPS PPD)",
        probability: gnssJamFlight ? 96 : 9,
        timeToImpact: gnssJamFlight ? (this.defense.multiFreqGnss ? "Neutralized by L5" : "FMS GPS Lock Loss in 8s") : "Nominal",
        confidence: 95,
        targetFlight: gnssJamFlight ? gnssJamFlight.callsign : "Sector-Wide"
      },
      mitigations: ["Multi-Frequency L5 GNSS + Galileo", "Inertial Reference System (IRS) dead reckoning", "Terrestrial VOR/DME backup"]
    });

    // 5. GNSS Ephemeris Spoofing
    const gnssSpoofFlight = this.flights.find((f) => f.gnssSpoofed);
    const gnssSpoofL = gnssSpoofFlight ? 4.2 : 1.4;
    const gnssSpoofI = gnssSpoofFlight ? 5.0 : 4.0;
    const gnssSpoofRisk = classify(gnssSpoofL, gnssSpoofI);
    list.push({
      id: "RT-NAV-GNSS-02",
      domain: "Navigation",
      asset: "GNSS",
      threatType: "Synthetic GNSS Ephemeris Spoofing",
      category: "Satellite Navigation",
      ciaTriad: "Integrity",
      likelihood: gnssSpoofL,
      impact: gnssSpoofI,
      numericRisk: gnssSpoofRisk.r,
      tolerability: gnssSpoofRisk.tol,
      fivePointScale: gnssSpoofRisk.scale,
      isRealtime: true,
      liveTelemetry: gnssSpoofFlight ? "Cross-Track Position Drift > 0.65 NM · Pseudorange Step > 140m" : "GPS vs IRS Cross-Fix Drift < 0.05 NM (Nominal)",
      prediction: {
        predictedAttack: "Coordinated Multi-Satellite Fake Signal Injection",
        probability: gnssSpoofFlight ? 94 : 3,
        timeToImpact: gnssSpoofFlight ? "Approach Centerline Deviation in 25s" : "Nominal",
        confidence: 93,
        targetFlight: gnssSpoofFlight ? gnssSpoofFlight.callsign : "Terminal Approach"
      },
      mitigations: ["RAIM / AAIM autonomous integrity monitoring", "DME-DME fix cross-check", "Galileo OS-NMA authenticated navigation"]
    });

    // 6. ILS Precision Approach Interference
    const finalApproachFlight = this.flights.find((f) => f.flightPhase === "Final Approach");
    const ilsL = 1.3;
    const ilsI = 4.8;
    const ilsRisk = classify(ilsL, ilsI);
    list.push({
      id: "RT-NAV-ILS-01",
      domain: "Navigation",
      asset: "ILS",
      threatType: "ILS Localizer / Glide Slope Single-Tone Attack",
      category: "Precision Landing Aid",
      ciaTriad: "Integrity",
      likelihood: ilsL,
      impact: ilsI,
      numericRisk: ilsRisk.r,
      tolerability: ilsRisk.tol,
      fivePointScale: ilsRisk.scale,
      isRealtime: true,
      liveTelemetry: finalApproachFlight ? `Tracking ${finalApproachFlight.callsign} on RWY 27R · Localizer DDM: 0.002 (Nominal)` : "Runway 27R/09L Near-Field Monitor Active",
      prediction: {
        predictedAttack: "Carrier Phase / Tone Displacement Attack",
        probability: 6,
        timeToImpact: "Nominal Landing Corridor",
        confidence: 90,
        targetFlight: finalApproachFlight ? finalApproachFlight.callsign : "Runway Threshold"
      },
      mitigations: ["Far-field runway threshold monitor", "Radar altimeter cross-check", "GBAS differential GPS backup"]
    });

    // 7. ADS-B Ghost Aircraft Injection
    const hasGhost = this.ghostAircraft.length > 0;
    let ghostL = hasGhost ? 4.8 : 2.0;
    let ghostI = hasGhost ? 4.8 : 3.0;
    if (this.defense.psrSsrFusion && hasGhost) {
      ghostL = 1.5;
      ghostI = 2.0;
    }
    const ghostRisk = classify(ghostL, ghostI);
    list.push({
      id: "RT-SUR-ADSB-01",
      domain: "Surveillance",
      asset: "ADS-B",
      threatType: "ADS-B Ghost Aircraft Injection (1090ES)",
      category: "Broadcast Surveillance",
      ciaTriad: "Integrity",
      likelihood: ghostL,
      impact: ghostI,
      numericRisk: ghostRisk.r,
      tolerability: ghostRisk.tol,
      fivePointScale: ghostRisk.scale,
      isRealtime: true,
      liveTelemetry: hasGhost ? (this.defense.psrSsrFusion ? "Ghost Squitter Detected & Filtered via Primary Radar Echo" : `Synthetic Mode S Squitter: ${this.ghostAircraft[0].callsign} · Primary Radar Echo: 0 dBsm (Non-Physical)`) : "All 1090 MHz squitters correlated with Primary Radar returns",
      prediction: {
        predictedAttack: "Unauthenticated 1090ES Message Injection",
        probability: hasGhost ? 97 : 7,
        timeToImpact: hasGhost ? (this.defense.psrSsrFusion ? "Neutralized by PSR" : "False TCAS Resolution Advisory in 10s") : "Nominal",
        confidence: 97,
        targetFlight: hasGhost ? this.ghostAircraft[0].targetFlight : "Airspace Grid"
      },
      mitigations: ["Primary Surveillance Radar (PSR) skin-paint data fusion", "TDoA multilateration verification", "ADS-B cryptographic broadcast authentication"]
    });

    // 8. ADS-B Trajectory Spoofing
    const adsbSpoofTarget = this.flights.find((f) => f.adsbSpoofed);
    let trajL = adsbSpoofTarget ? 4.5 : 2.0;
    let trajI = adsbSpoofTarget ? 4.2 : 3.0;
    if (this.defense.tdoaMlVerification && adsbSpoofTarget) {
      trajL = 1.8;
      trajI = 2.0;
    }
    const trajRisk = classify(trajL, trajI);
    list.push({
      id: "RT-SUR-ADSB-02",
      domain: "Surveillance",
      asset: "ADS-B",
      threatType: "ADS-B Trajectory Spoofing / Position Alteration",
      category: "Broadcast Surveillance",
      ciaTriad: "Integrity",
      likelihood: trajL,
      impact: trajI,
      numericRisk: trajRisk.r,
      tolerability: trajRisk.tol,
      fivePointScale: trajRisk.scale,
      isRealtime: true,
      liveTelemetry: adsbSpoofTarget ? (this.defense.tdoaMlVerification ? "TDoA ML Position Overriding Spoofed Coordinates" : `Claimed Pos diverged by ${Math.hypot(adsbSpoofTarget.claimedX - adsbSpoofTarget.trueX, adsbSpoofTarget.claimedY - adsbSpoofTarget.trueY).toFixed(1)} NM · TDoA Error: ${this.computeTdoaResidual(adsbSpoofTarget.claimedX, adsbSpoofTarget.claimedY, adsbSpoofTarget.trueX, adsbSpoofTarget.trueY)} μs`) : "TDoA Residual: 0.12 μs (Nominal)",
      prediction: {
        predictedAttack: "Airspace Trajectory Manipulation",
        probability: adsbSpoofTarget ? 95 : 6,
        timeToImpact: adsbSpoofTarget ? (this.defense.tdoaMlVerification ? "Corrected by ML TDoA" : "Loss of Radar Separation in 18s") : "Nominal",
        confidence: 94,
        targetFlight: adsbSpoofTarget ? adsbSpoofTarget.callsign : "En-Route / Approach"
      },
      mitigations: ["TDoA ML localization (OpenSky Network)", "Monopulse Angle-of-Arrival (AoA) antennas", "Doppler shift verification"]
    });

    // 9. SSR Transponder Over-Interrogation
    const ssrTarget = this.flights.find((f) => f.transponderRate > 1200);
    const ssrL = ssrTarget ? 4.2 : 1.2;
    const ssrI = ssrTarget ? 4.5 : 3.5;
    const ssrRisk = classify(ssrL, ssrI);
    list.push({
      id: "RT-SUR-SSR-01",
      domain: "Surveillance",
      asset: "SSR",
      threatType: "SSR Transponder Pulse Saturation / Lockout",
      category: "Cooperative Radar",
      ciaTriad: "Availability",
      likelihood: ssrL,
      impact: ssrI,
      numericRisk: ssrRisk.r,
      tolerability: ssrRisk.tol,
      fivePointScale: ssrRisk.scale,
      isRealtime: true,
      liveTelemetry: ssrTarget ? `Interrogation PRF: ${ssrTarget.transponderRate} Hz (>1200 Hz threshold) · Transponder duty cycle tripped!` : "Interrogation PRF: 390 Hz · Duty Cycle: 24% (Nominal)",
      prediction: {
        predictedAttack: "Ground Interrogator Flood / Duty-Cycle Exhaustion",
        probability: ssrTarget ? 98 : 4,
        timeToImpact: ssrTarget ? "Radar Track Dropout in 4s" : "Nominal",
        confidence: 98,
        targetFlight: ssrTarget ? ssrTarget.callsign : "Terminal Interrogation Area"
      },
      mitigations: ["Ground sensor PRF coordination", "Interrogator power budget scheduling", "PSR skin-paint fallback"]
    });

    // 10. SWIM Net-Centric MITM & DoS
    const hasSwimAttack = this.activeAttacks.some((a) => a.type === "SWIM_MITM");
    const swimL = hasSwimAttack ? 4.2 : 2.0;
    const swimI = hasSwimAttack ? 4.0 : 3.0;
    const swimRisk = classify(swimL, swimI);
    list.push({
      id: "RT-NET-SWIM-01",
      domain: "Networking",
      asset: "SWIM",
      threatType: "SWIM Enterprise Service Bus MITM / DoS Attack",
      category: "Net-Centric IP Infrastructure",
      ciaTriad: "Integrity",
      likelihood: swimL,
      impact: swimI,
      numericRisk: swimRisk.r,
      tolerability: swimRisk.tol,
      fivePointScale: swimRisk.scale,
      isRealtime: true,
      liveTelemetry: hasSwimAttack ? "SWIM Bus Latency: 520ms · Unsigned AIXM/FIXM updates detected" : "SWIM Enterprise Bus: Mutual TLS OK · Latency: 14ms",
      prediction: {
        predictedAttack: "Unauthorized Net-Centric Data Alteration",
        probability: hasSwimAttack ? 93 : 8,
        timeToImpact: hasSwimAttack ? "Corrupted Weather / Flight Plan Propagation" : "Nominal",
        confidence: 92,
        targetFlight: "Airspace Stakeholders (ANSP/Airlines/AOCC)"
      },
      mitigations: ["SWIM Common PKI mutual certificates", "ICAO INNOVA/ACORNS private network", "Zero Trust Network Architecture (ZTNA)"]
    });

    return list;
  }

  // =========================================================================
  // AUTOMATED ADVERSARIAL CAMPAIGN LAUNCHER (RED TEAM)
  // =========================================================================
  triggerMultiStageCampaign() {
    this.clearAllAttacks();
    const flight = this.flights.find((f) => f.id === "UAL421") || this.flights[0];
    this.selectedFlightId = flight.id;

    // Stage 1: Inject GPS Jamming
    this.injectAttack("GNSS_JAMMING");

    // Stage 2: Infiltrate ADS-B with Ghost Decoy
    setTimeout(() => {
      this.injectAttack("ADSB_GHOST");
    }, 400);

    // Stage 3: Broadcast Rogue Voice Clearance
    setTimeout(() => {
      this.injectAttack("VHF_VOICE_SPOOF");
      this.logEvent("RED_TEAM_CAMPAIGN", "Coordinated Adversarial Campaign Active: GPS Jamming + ADS-B Ghost Decoy + Rogue VHF Voice Clearances!", "CRITICAL");
    }, 800);
  }

  // =========================================================================
  // AUTOMATED CYBER-RESILIENCE RESPONSE (BLUE TEAM)
  // =========================================================================
  triggerFullAutonomousDefense() {
    this.defense.psrSsrFusion = true;
    this.defense.multiFreqGnss = true;
    this.defense.tdoaMlVerification = true;
    this.defense.autoFreqHop = true;

    // Sync UI checkboxes
    const c1 = document.getElementById("defense-psr-fusion");
    const c2 = document.getElementById("defense-multi-gnss");
    const c3 = document.getElementById("defense-tdoa-ml");
    const c4 = document.getElementById("defense-auto-freq");
    if (c1) c1.checked = true;
    if (c2) c2.checked = true;
    if (c3) c3.checked = true;
    if (c4) c4.checked = true;

    this.logEvent("BLUE_TEAM_DEFENSE", "Full Multi-Layer Cyber-Resilience Deployed: PSR-SSR Fusion + Multi-Freq GNSS + TDoA ML + Auto VHF Hopping Active!", "SUCCESS");
  }

  // =========================================================================
  // CUSTOM TELEMETRY PACKET INGESTION & REAL-TIME PREDICTION
  // =========================================================================
  processCustomTelemetryPacket(packet) {
    try {
      const flight = this.flights.find((f) => f.id === packet.flightId || f.callsign === packet.callsign) || this.flights[0];
      
      if (typeof packet.gnssSnr === "number") {
        flight.gnssSnr = packet.gnssSnr;
        if (packet.gnssSnr < 30) flight.gnssJammed = true;
      }

      if (typeof packet.claimedX === "number" && typeof packet.trueX === "number") {
        flight.claimedX = packet.claimedX;
        flight.trueX = packet.trueX;
        if (Math.hypot(packet.claimedX - packet.trueX, packet.claimedY - packet.trueY) > 1.0) {
          flight.adsbSpoofed = true;
        }
      }

      if (typeof packet.transponderRate === "number") {
        flight.transponderRate = packet.transponderRate;
        if (packet.transponderRate > 1200) flight.transponderSuppressed = true;
      }

      if (packet.vhfAnomaly) {
        flight.vhfSpoofed = true;
      }

      if (packet.cpdlcTampered) {
        flight.cpdlcTampered = true;
      }

      this.selectedFlightId = flight.id;
      this.recalculateLiveRisk();
      this.runAttackPredictionEngine();
      this.refreshTelemetryUI();

      this.logEvent("DATA_INGEST", `Processed custom live telemetry packet for ${flight.callsign}. Updated real-time predictive risk profile.`, "SUCCESS");
      return { success: true, flight: flight.callsign, risk: flight.risk };
    } catch (err) {
      this.logEvent("DATA_ERROR", `Failed to parse telemetry packet: ${err.message}`, "CRITICAL");
      return { success: false, error: err.message };
    }
  }

  // =========================================================================
  // ATTACK INJECTION DECK (RED TEAM ENGINE)
  // =========================================================================
  injectAttack(type) {
    const flight = this.flights.find((f) => f.id === this.selectedFlightId) || this.flights[0];
    const attackId = `ATK-${Date.now().toString().slice(-4)}`;

    switch (type) {
      case "ADSB_GHOST": {
        const ghost1 = {
          id: `GHOST-A`,
          callsign: `N${Math.floor(1000 + Math.random() * 9000)}`,
          x: flight.trueX + 3.2,
          y: flight.trueY + 1.5,
          altitude: flight.altitude + 300,
          speed: flight.speed + 15,
          heading: (flight.heading + 180) % 360,
          targetFlight: flight.callsign
        };
        this.ghostAircraft.push(ghost1);
        flight.activeThreat = "ADS-B Ghost Aircraft Injection (1090ES)";
        this.activeAttacks.push({ id: attackId, type: "ADSB_GHOST", target: flight.id, label: "ADS-B Ghost Aircraft" });
        this.logEvent("ATTACK_INJECT", `Red Team: Injected Rogue ADS-B Ghost Aircraft [${ghost1.callsign}] on collision track with ${flight.callsign}`, "CRITICAL");
        break;
      }

      case "ADSB_TRAJECTORY_SPOOF": {
        flight.adsbSpoofed = true;
        flight.activeThreat = "ADS-B Trajectory Spoofing / Modification";
        this.activeAttacks.push({ id: attackId, type: "ADSB_TRAJECTORY_SPOOF", target: flight.id, label: "ADS-B Trajectory Spoofing" });
        this.logEvent("ATTACK_INJECT", `Red Team: Modifying ADS-B position coordinates for ${flight.callsign}. Diverging claimed vs physical location.`, "WARNING");
        break;
      }

      case "GNSS_JAMMING": {
        this.jammingZones.push({
          id: attackId,
          x: flight.trueX,
          y: flight.trueY,
          radius: 12.0,
          intensity: 0.95
        });
        flight.gnssJammed = true;
        flight.activeThreat = "GNSS RF Jamming (L1 1575.42 MHz)";
        this.activeAttacks.push({ id: attackId, type: "GNSS_JAMMING", target: flight.id, label: "GNSS Jamming Zone" });
        this.logEvent("ATTACK_INJECT", `Red Team: Activated 50W GPS Jammer near ${flight.callsign}. Satellite SNR plunging to noise floor.`, "CRITICAL");
        break;
      }

      case "GNSS_SPOOFING": {
        flight.gnssSpoofed = true;
        flight.gnssSnr = 38;
        flight.activeThreat = "GNSS Ephemeris / False Position Spoofing";
        this.activeAttacks.push({ id: attackId, type: "GNSS_SPOOFING", target: flight.id, label: "GNSS Ephemeris Spoofing" });
        this.logEvent("ATTACK_INJECT", `Red Team: Transmitting synthetic GPS ephemeris. Drifting flight ${flight.callsign} off runway approach centerline.`, "CRITICAL");
        break;
      }

      case "VHF_VOICE_SPOOF": {
        flight.vhfSpoofed = true;
        flight.activeThreat = "VHF Voice Clearance Spoofing (Rogue ATC)";
        this.activeAttacks.push({ id: attackId, type: "VHF_VOICE_SPOOF", target: flight.id, label: "VHF Voice Rogue ATC" });
        this.logEvent("ATTACK_INJECT", `Red Team: Unauthorized ground transmission on ${flight.assignedFrequency}: "Rogue ATC issuing IMMEDIATE DESCENT TO FL040" to ${flight.callsign}`, "CRITICAL");
        break;
      }

      case "SSR_OVER_INTERROGATION": {
        flight.transponderRate = 1650;
        flight.activeThreat = "SSR Transponder Over-Interrogation";
        this.activeAttacks.push({ id: attackId, type: "SSR_OVER_INTERROGATION", target: flight.id, label: "SSR Transponder Saturation" });
        this.logEvent("ATTACK_INJECT", `Red Team: Transmitting 1650 interrogations/sec at 1030 MHz. Transponder duty-cycle saturation threshold exceeded!`, "WARNING");
        break;
      }

      case "SWIM_MITM": {
        flight.cpdlcTampered = true;
        flight.activeThreat = "SWIM Net-Centric MITM / Message Injection";
        this.activeAttacks.push({ id: attackId, type: "SWIM_MITM", target: flight.id, label: "SWIM Enterprise MITM" });
        this.logEvent("ATTACK_INJECT", `Red Team: Man-in-the-Middle on SWIM Enterprise Bus. Injecting unauthorized route amendment to ${flight.callsign}.`, "WARNING");
        break;
      }
    }

    this.renderActiveAttacksUI();
    this.renderFlightPills();
  }

  clearAllAttacks() {
    this.activeAttacks = [];
    this.ghostAircraft = [];
    this.jammingZones = [];
    this.flights.forEach((f) => {
      f.gnssJammed = false;
      f.gnssSpoofed = false;
      f.adsbSpoofed = false;
      f.adsbDropped = false;
      f.vhfSpoofed = false;
      f.transponderRate = 350;
      f.transponderSuppressed = false;
      f.cpdlcTampered = false;
      f.activeThreat = null;
      f.claimedX = f.trueX;
      f.claimedY = f.trueY;
      f.gnssSnr = 46;
    });
    this.predictedThreats = [];
    this.renderActiveAttacksUI();
    this.renderPredictionCards();
    this.renderFlightPills();
    this.logEvent("DEFENSE", "All simulated cyber-attacks cleared. Baseline operational security restored.", "SUCCESS");
  }

  updateAttackMechanics(dt) {
    this.flights.forEach((f) => {
      let jammed = false;
      for (const zone of this.jammingZones) {
        const d = Math.hypot(f.trueX - zone.x, f.trueY - zone.y);
        if (d < zone.radius) {
          jammed = true;
          if (this.defense.multiFreqGnss) {
            f.gnssSnr = 39;
          } else {
            f.gnssSnr = Math.max(12, f.gnssSnr - 18 * dt);
          }
          break;
        }
      }
      if (!jammed && !f.gnssSpoofed) {
        f.gnssSnr = Math.min(48, f.gnssSnr + 5 * dt);
      }

      if (f.transponderRate > 1200) {
        f.transponderSuppressed = true;
      } else {
        f.transponderSuppressed = false;
      }
    });

    if (this.defense.psrSsrFusion && this.ghostAircraft.length > 0) {
      this.logEvent("DEFENSE_AUTO", "Primary Radar (PSR) skin-paint check failed for ghost ADS-B squitter. Eliminating virtual ghost target.", "SUCCESS");
      this.ghostAircraft = [];
      this.stats.attacksNeutralized++;
    }

    if (this.defense.tdoaMlVerification) {
      this.flights.forEach((f) => {
        if (f.adsbSpoofed) {
          f.claimedX = f.trueX;
          f.claimedY = f.trueY;
        }
      });
    }

    if (this.defense.autoFreqHop) {
      this.flights.forEach((f) => {
        if (f.vhfSpoofed) {
          f.assignedFrequency = "121.900 MHz (Backup Channel)";
          f.vhfSpoofed = false;
          f.activeThreat = null;
          this.logEvent("DEFENSE_AUTO", `${f.callsign} hopped to secure backup frequency 121.900 MHz. Rogue transmission isolated.`, "SUCCESS");
        }
      });
    }
  }

  // =========================================================================
  // PREDICTIVE AI ANOMALY DETECTION ENGINE (BLUE TEAM FORECASTER)
  // =========================================================================
  runAttackPredictionEngine() {
    const newPredictions = [];

    this.flights.forEach((f) => {
      // 1. TDoA Multi-Lateration Consistency Predictor
      const tdoaResidual = this.computeTdoaResidual(f.claimedX, f.claimedY, f.trueX, f.trueY);
      if (tdoaResidual > 1.2) {
        newPredictions.push({
          flightId: f.id,
          callsign: f.callsign,
          anomalyType: "TDoA Time-Difference of Arrival Discrepancy",
          metricValue: `${tdoaResidual.toFixed(2)} μs error (Threshold: 0.8 μs)`,
          predictedAttack: "ADS-B Trajectory Spoofing / Message Tampering",
          confidence: Math.min(99, Math.round(75 + tdoaResidual * 10)),
          timeToImpact: "15 seconds",
          severity: "HIGH",
          recommendedMitigation: "Activate TDoA ML Localization & Reject 1090ES Position Vector"
        });
        this.stats.predictionsGenerated++;
      }

      this.ghostAircraft.forEach((g) => {
        newPredictions.push({
          flightId: g.id,
          callsign: g.callsign,
          anomalyType: "Cooperative ADS-B Track Without Primary Radar (PSR) Skin Return",
          metricValue: "PSR Echo = 0 dBsm (Non-Physical Target)",
          predictedAttack: "ADS-B Ghost Aircraft Injection Attack",
          confidence: 97,
          timeToImpact: "10 seconds to False TCAS Collision Alert",
          severity: "CRITICAL",
          recommendedMitigation: "Deploy SSR-PSR Sensor Data Fusion & Suppress Track"
        });
      });

      // 2. GNSS Carrier-to-Noise Degradation Predictor
      if (f.gnssSnr < 32) {
        newPredictions.push({
          flightId: f.id,
          callsign: f.callsign,
          anomalyType: "RF Signal-to-Noise Depletion in GPS L1 Band",
          metricValue: `C/N0 = ${f.gnssSnr.toFixed(1)} dB-Hz (Nominal: 45 dB-Hz)`,
          predictedAttack: "Active Radio Frequency Interference / GPS Jamming",
          confidence: 95,
          timeToImpact: "8 seconds before complete FMS GPS Lock Loss",
          severity: "HIGH",
          recommendedMitigation: "Switch to Multi-Frequency L5 GNSS and engage Inertial Reference System (IRS)"
        });
        this.stats.predictionsGenerated++;
      }

      // 3. GNSS Ephemeris & Position Drift Predictor
      if (f.gnssSpoofed) {
        newPredictions.push({
          flightId: f.id,
          callsign: f.callsign,
          anomalyType: "GNSS vs Dead-Reckoning IRS Coordinate Divergence",
          metricValue: `Position Cross-Track Drift > 0.45 NM`,
          predictedAttack: "GNSS Ephemeris Spoofing / Approach Bending",
          confidence: 91,
          timeToImpact: "25 seconds before localizer capture deviation",
          severity: "CRITICAL",
          recommendedMitigation: "Enforce DME-DME Radio Fix & AAIM Integrity Check"
        });
        this.stats.predictionsGenerated++;
      }

      // 4. VHF Phraseology & Flight Plan Divergence Predictor
      if (f.vhfSpoofed) {
        newPredictions.push({
          flightId: f.id,
          callsign: f.callsign,
          anomalyType: "Unauthenticated Voice Clearance Diverging from Filed Flight Plan",
          metricValue: "Clearance Rate = Abrupt Descent -8,000 ft without ATC Handover",
          predictedAttack: "VHF Voice Spoofing / Rogue ATC Transmission",
          confidence: 94,
          timeToImpact: "Immediate (Collision / CFIT Risk)",
          severity: "INTOLERABLE",
          recommendedMitigation: "Immediate Hear-Back Protocol Verification & Hop to Backup Channel"
        });
        this.stats.predictionsGenerated++;
      }

      // 5. Transponder Pulse Saturation Rate Predictor
      if (f.transponderRate > 1200) {
        newPredictions.push({
          flightId: f.id,
          callsign: f.callsign,
          anomalyType: "1030 MHz Interrogation Pulse Frequency Surge",
          metricValue: `${f.transponderRate} pulses/sec (Operational Max: 1200/s)`,
          predictedAttack: "SSR Transponder Duty-Cycle Over-Interrogation",
          confidence: 98,
          timeToImpact: "5 seconds to Transponder Thermal Lockdown",
          severity: "HIGH",
          recommendedMitigation: "Coordinate Ground Interrogator Scheduling & Cap Interrogation Power"
        });
        this.stats.predictionsGenerated++;
      }

      // 6. CPDLC / ACARS Data Link Integrity Predictor
      if (f.cpdlcTampered) {
        newPredictions.push({
          flightId: f.id,
          callsign: f.callsign,
          anomalyType: "SWIM Net-Centric Hash Mismatch on Route Amendment",
          metricValue: "Missing Valid X.509 PKI Signature",
          predictedAttack: "SWIM Enterprise MITM / ACARS Route Injection",
          confidence: 92,
          timeToImpact: "FMS Route Activation Phase",
          severity: "MEDIUM",
          recommendedMitigation: "Enforce ARINC 823 PKI Validation and Reject Unsigned Amendment"
        });
        this.stats.predictionsGenerated++;
      }
    });

    this.predictedThreats = newPredictions;
    this.renderPredictionCards();
  }

  computeTdoaResidual(claimedX, claimedY, trueX, trueY) {
    const deltaDist = Math.hypot(claimedX - trueX, claimedY - trueY);
    return Number((deltaDist * 6.18 + (Math.random() * 0.1 - 0.05)).toFixed(2));
  }

  // =========================================================================
  // DYNAMIC ALGORITHM 1 RISK RE-ASSESSMENT
  // =========================================================================
  recalculateLiveRisk() {
    let intolerableCount = 0;

    this.flights.forEach((f) => {
      let L = 2.0;
      let I = 2.5;

      if (f.vhfSpoofed) {
        L = 4.0;
        I = 5.0;
      } else if (f.adsbSpoofed || this.ghostAircraft.some((g) => g.targetFlight === f.callsign)) {
        L = 4.2;
        I = 4.5;
      } else if (f.gnssSpoofed) {
        L = 3.5;
        I = 4.8;
      } else if (f.gnssJammed) {
        L = 4.8;
        I = 3.0;
      } else if (f.transponderSuppressed) {
        L = 3.0;
        I = 4.0;
      } else if (f.cpdlcTampered) {
        L = 2.5;
        I = 4.0;
      }

      const r = Number((L * I).toFixed(1));

      let tol = "acceptable";
      if (r >= 15.0) {
        tol = "intolerable";
        intolerableCount++;
      } else if (r >= 5.0) {
        tol = "tolerable";
      }

      let scale = 1;
      if (r >= 20.0) scale = 5;
      else if (r >= 15.0) scale = 4;
      else if (r >= 10.0) scale = 3;
      else if (r >= 5.0) scale = 2;

      f.risk = { L, I, r, tol, scale };
    });

    this.stats.intolerableEvents = intolerableCount;
  }

  // =========================================================================
  // RENDERING & VISUAL RADAR DISPLAY
  // =========================================================================
  render() {
    if (!this.ctx || !this.canvas) return;
    const ctx = this.ctx;
    const width = this.canvas.width;
    const height = this.canvas.height;
    const centerX = width / 2;
    const centerY = height / 2;
    const scale = (Math.min(width, height) * 0.42) / this.sectorRadius;

    ctx.fillStyle = "#04080e";
    ctx.fillRect(0, 0, width, height);

    ctx.lineWidth = 1;
    [5, 10, 20, 30].forEach((ringNM) => {
      ctx.strokeStyle = ringNM === 30 ? "#1e3a5f" : "#0f2338";
      ctx.beginPath();
      ctx.arc(centerX, centerY, ringNM * scale, 0, Math.PI * 2);
      ctx.stroke();

      ctx.fillStyle = "#336699";
      ctx.font = "10px JetBrains Mono";
      ctx.fillText(`${ringNM} NM`, centerX + 4, centerY - ringNM * scale + 12);
    });

    ctx.strokeStyle = "#0c1f33";
    ctx.beginPath();
    ctx.moveTo(centerX, 0);
    ctx.lineTo(centerX, height);
    ctx.moveTo(0, centerY);
    ctx.lineTo(width, centerY);
    ctx.stroke();

    this.mlatStations.forEach((s) => {
      const sx = centerX + s.x * scale;
      const sy = centerY - s.y * scale;
      ctx.fillStyle = "#0284c7";
      ctx.strokeStyle = "#38bdf8";
      ctx.lineWidth = 1.5;
      ctx.beginPath();
      ctx.arc(sx, sy, 4, 0, Math.PI * 2);
      ctx.fill();
      ctx.stroke();

      ctx.fillStyle = "#7dd3fc";
      ctx.font = "9px JetBrains Mono";
      ctx.fillText(s.id, sx + 6, sy + 3);
    });

    this.waypoints.forEach((w) => {
      const wx = centerX + w.x * scale;
      const wy = centerY - w.y * scale;
      ctx.strokeStyle = "#1e40af";
      ctx.beginPath();
      ctx.moveTo(wx, wy - 4);
      ctx.lineTo(wx + 4, wy + 4);
      ctx.lineTo(wx - 4, wy + 4);
      ctx.closePath();
      ctx.stroke();

      ctx.fillStyle = "#60a5fa";
      ctx.font = "9px JetBrains Mono";
      ctx.fillText(w.name, wx + 6, wy + 3);
    });

    ctx.strokeStyle = "#10b981";
    ctx.lineWidth = 2.5;
    this.runways.forEach((rw) => {
      const rx1 = centerX + (rw.x - rw.length / 2) * scale;
      const rx2 = centerX + (rw.x + rw.length / 2) * scale;
      const ry = centerY - rw.y * scale;
      ctx.beginPath();
      ctx.moveTo(rx1, ry);
      ctx.lineTo(rx2, ry);
      ctx.stroke();
    });

    this.jammingZones.forEach((z) => {
      const zx = centerX + z.x * scale;
      const zy = centerY - z.y * scale;
      const radPx = z.radius * scale;

      const grad = ctx.createRadialGradient(zx, zy, 2, zx, zy, radPx);
      grad.addColorStop(0, "rgba(239, 68, 68, 0.45)");
      grad.addColorStop(0.7, "rgba(245, 158, 11, 0.2)");
      grad.addColorStop(1, "rgba(239, 68, 68, 0.0)");

      ctx.fillStyle = grad;
      ctx.beginPath();
      ctx.arc(zx, zy, radPx, 0, Math.PI * 2);
      ctx.fill();

      ctx.strokeStyle = "#ef4444";
      ctx.setLineDash([4, 4]);
      ctx.stroke();
      ctx.setLineDash([]);

      ctx.fillStyle = "#fca5a5";
      ctx.font = "10px JetBrains Mono";
      ctx.fillText("⚠️ GPS JAMMING RF INTERFERENCE CONTOUR", zx - 110, zy - radPx - 6);
    });

    const sweepRadius = Math.max(width, height) * 0.7;
    const sweepX = centerX + Math.cos(this.radarAngle) * sweepRadius;
    const sweepY = centerY + Math.sin(this.radarAngle) * sweepRadius;

    ctx.strokeStyle = "rgba(56, 189, 248, 0.35)";
    ctx.lineWidth = 1.5;
    ctx.beginPath();
    ctx.moveTo(centerX, centerY);
    ctx.lineTo(sweepX, sweepY);
    ctx.stroke();

    this.flights.forEach((f) => {
      const isSelected = f.id === this.selectedFlightId;
      const fx = centerX + f.claimedX * scale;
      const fy = centerY - f.claimedY * scale;

      if (f.adsbSpoofed) {
        const tx = centerX + f.trueX * scale;
        const ty = centerY - f.trueY * scale;

        ctx.fillStyle = "#38bdf8";
        ctx.beginPath();
        ctx.arc(tx, ty, 3.5, 0, Math.PI * 2);
        ctx.fill();

        ctx.strokeStyle = "#f59e0b";
        ctx.setLineDash([3, 3]);
        ctx.beginPath();
        ctx.moveTo(tx, ty);
        ctx.lineTo(fx, fy);
        ctx.stroke();
        ctx.setLineDash([]);

        ctx.fillStyle = "#f59e0b";
        ctx.font = "9px JetBrains Mono";
        ctx.fillText("True Skin Echo (PSR)", tx + 6, ty + 12);
      }

      let blipColor = "#10b981";
      if (f.risk.tol === "intolerable") blipColor = "#ef4444";
      else if (f.risk.tol === "tolerable") blipColor = "#f59e0b";

      ctx.save();
      ctx.translate(fx, fy);
      ctx.rotate((f.heading * Math.PI) / 180);

      ctx.fillStyle = blipColor;
      ctx.beginPath();
      ctx.moveTo(0, -7);
      ctx.lineTo(5, 6);
      ctx.lineTo(0, 4);
      ctx.lineTo(-5, 6);
      ctx.closePath();
      ctx.fill();

      if (isSelected) {
        ctx.strokeStyle = "#38bdf8";
        ctx.lineWidth = 1.5;
        ctx.beginPath();
        ctx.arc(0, 0, 12, 0, Math.PI * 2);
        ctx.stroke();
      }
      ctx.restore();

      const leadNM = (f.speed / 3600) * 60;
      const radLead = ((90 - f.heading) * Math.PI) / 180;
      ctx.strokeStyle = blipColor;
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(fx, fy);
      ctx.lineTo(fx + Math.cos(radLead) * leadNM * scale, fy - Math.sin(radLead) * leadNM * scale);
      ctx.stroke();

      ctx.fillStyle = isSelected ? "#ffffff" : "#cbd5e1";
      ctx.font = "bold 11px JetBrains Mono";
      ctx.fillText(f.callsign, fx + 10, fy - 6);

      ctx.font = "10px JetBrains Mono";
      ctx.fillStyle = blipColor;
      const fl = Math.round(f.altitude / 100);
      ctx.fillText(`FL${fl} ${f.speed}kt`, fx + 10, fy + 7);

      ctx.fillStyle = f.risk.tol === "intolerable" ? "#ef4444" : f.risk.tol === "tolerable" ? "#f59e0b" : "#10b981";
      ctx.fillText(`Risk r=${f.risk.r} [${f.risk.tol.toUpperCase()}]`, fx + 10, fy + 19);

      if (f.activeThreat) {
        ctx.fillStyle = "#f87171";
        ctx.font = "bold 9px JetBrains Mono";
        ctx.fillText(`⚠️ ${f.activeThreat.substring(0, 24)}..`, fx + 10, fy + 30);
      }
    });

    this.ghostAircraft.forEach((g) => {
      const gx = centerX + g.x * scale;
      const gy = centerY - g.y * scale;

      ctx.save();
      ctx.translate(gx, gy);
      ctx.rotate((g.heading * Math.PI) / 180);

      ctx.strokeStyle = "#ef4444";
      ctx.lineWidth = 1.5;
      ctx.setLineDash([3, 2]);
      ctx.strokeRect(-6, -6, 12, 12);
      ctx.setLineDash([]);
      ctx.restore();

      ctx.fillStyle = "#ef4444";
      ctx.font = "bold 10px JetBrains Mono";
      ctx.fillText(`${g.callsign} [GHOST]`, gx + 10, gy - 4);
      ctx.font = "9px JetBrains Mono";
      ctx.fillText(`FL${Math.round(g.altitude / 100)} NO PRIMARY ECHO`, gx + 10, gy + 8);
    });
  }

  // =========================================================================
  // UI SYNC & TELEMETRY CONTROLS
  // =========================================================================
  refreshTelemetryUI() {
    const flight = this.flights.find((f) => f.id === this.selectedFlightId);
    if (flight) {
      this.updateTelemetryCard(flight);
    }

    const simTimeEl = document.getElementById("sim-clock-time");
    if (simTimeEl) {
      const mins = Math.floor(this.simTime / 60);
      const secs = Math.floor(this.simTime % 60);
      simTimeEl.innerText = `${String(mins).padStart(2, "0")}:${String(secs).padStart(2, "0")} UTC`;
    }

    const simActiveAttacksEl = document.getElementById("sim-active-attacks-count");
    if (simActiveAttacksEl) {
      simActiveAttacksEl.innerText = this.activeAttacks.length;
    }

    const simPredictionsEl = document.getElementById("sim-predictions-count");
    if (simPredictionsEl) {
      simPredictionsEl.innerText = this.predictedThreats.length;
    }

    const simIntolerableEl = document.getElementById("sim-live-intolerable-count");
    if (simIntolerableEl) {
      simIntolerableEl.innerText = this.stats.intolerableEvents;
    }
  }

  updateTelemetryCard(f) {
    const card = document.getElementById("selected-flight-telemetry");
    if (!card) return;

    const rStyle = f.risk.tol === "intolerable" ? "text-red-400 border-red-500 bg-red-950/40" : f.risk.tol === "tolerable" ? "text-amber-400 border-amber-500 bg-amber-950/40" : "text-emerald-400 border-emerald-500 bg-emerald-950/40";

    card.innerHTML = `
      <div class="flex items-center justify-between border-b border-slate-800 pb-3">
        <div>
          <div class="flex items-center space-x-2">
            <span class="text-base font-bold font-mono text-white">${f.callsign}</span>
            <span class="px-2 py-0.5 rounded text-[10px] uppercase font-bold bg-slate-800 text-sky-400 border border-slate-700">${f.aircraftType}</span>
            <span class="px-2 py-0.5 rounded text-[10px] uppercase font-bold bg-slate-800 text-slate-300">${f.flightPhase}</span>
          </div>
          <div class="text-xs text-slate-400 font-mono mt-0.5">Route Dest: ${f.destination} · VHF: ${f.assignedFrequency}</div>
        </div>
        <div class="text-right">
          <span class="px-2.5 py-1 rounded text-xs uppercase font-bold font-mono border ${rStyle}">
            ${f.risk.tol}
          </span>
          <div class="text-xs font-mono text-slate-400 mt-1">Algorithm 1: r = ${f.risk.r}</div>
        </div>
      </div>

      <div class="grid grid-cols-2 sm:grid-cols-4 gap-2 my-3 text-xs font-mono">
        <div class="p-2 bg-slate-950 rounded border border-slate-800">
          <div class="text-[10px] text-slate-500 uppercase">Altitude / Speed</div>
          <div class="text-sm font-bold text-white mt-0.5">${Math.round(f.altitude)} ft · ${Math.round(f.speed)} kts</div>
        </div>
        <div class="p-2 bg-slate-950 rounded border border-slate-800">
          <div class="text-[10px] text-slate-500 uppercase">GNSS C/N0 SNR</div>
          <div class="text-sm font-bold ${f.gnssSnr < 32 ? "text-red-400" : "text-emerald-400"} mt-0.5">${f.gnssSnr.toFixed(1)} dB-Hz</div>
        </div>
        <div class="p-2 bg-slate-950 rounded border border-slate-800">
          <div class="text-[10px] text-slate-500 uppercase">SSR Reply Rate</div>
          <div class="text-sm font-bold ${f.transponderRate > 1200 ? "text-red-400" : "text-sky-400"} mt-0.5">${f.transponderRate} Hz</div>
        </div>
        <div class="p-2 bg-slate-950 rounded border border-slate-800">
          <div class="text-[10px] text-slate-500 uppercase">TDoA Residual</div>
          <div class="text-sm font-bold ${f.adsbSpoofed ? "text-red-400" : "text-emerald-400"} mt-0.5">
            ${this.computeTdoaResidual(f.claimedX, f.claimedY, f.trueX, f.trueY)} μs
          </div>
        </div>
      </div>

      ${
        f.activeThreat
          ? `<div class="p-2.5 bg-red-950/60 border border-red-500/80 rounded text-xs text-red-200 flex items-center justify-between">
              <div>
                <strong>ACTIVE ATTACK:</strong> ${f.activeThreat}
              </div>
              <span class="px-2 py-0.5 rounded text-[10px] uppercase font-bold bg-red-500 text-white animate-pulse">Escalating</span>
            </div>`
          : `<div class="p-2 bg-slate-950 border border-slate-800 rounded text-xs text-slate-400">
              No anomalies detected on this flight strip. Surveillance and navigation integrity nominal.
            </div>`
      }
    `;
  }

  renderPredictionCards() {
    const container = document.getElementById("prediction-cards-container");
    if (!container) return;

    if (this.predictedThreats.length === 0) {
      container.innerHTML = `
        <div class="p-5 bg-slate-950 border border-slate-800 rounded-lg text-center text-slate-500 text-xs">
          <i data-lucide="shield-check" class="w-7 h-7 mx-auto mb-1.5 text-emerald-400"></i>
          <p class="font-bold text-slate-300">Predictive Anomaly Forecaster: Clean Sector</p>
          <p class="text-[11px] text-slate-500 mt-1">Multi-sensor kinematic, TDoA, and RF spectral models report zero impending cyber-attacks.</p>
        </div>
      `;
      if (window.lucide) lucide.createIcons();
      return;
    }

    container.innerHTML = this.predictedThreats
      .map((p) => {
        const isCritical = p.severity === "CRITICAL" || p.severity === "INTOLERABLE";
        const badgeClass = isCritical ? "bg-red-500 text-white" : "bg-amber-500 text-slate-900";

        return `
        <div class="p-3 bg-slate-950 border ${isCritical ? "border-red-500/80" : "border-amber-500/80"} rounded-lg space-y-1.5">
          <div class="flex items-center justify-between">
            <div class="flex items-center space-x-2">
              <span class="px-2 py-0.5 rounded text-[10px] uppercase font-bold font-mono ${badgeClass}">${p.severity}</span>
              <span class="text-xs font-bold font-mono text-white">${p.callsign}</span>
            </div>
            <span class="text-xs font-mono font-bold text-pink-400">${p.confidence}% Confidence</span>
          </div>

          <div class="text-xs text-slate-300">
            <div class="font-bold text-sky-400">${p.predictedAttack}</div>
            <div class="text-[11px] text-slate-400 font-mono mt-0.5">Symptom: ${p.anomalyType} (${p.metricValue})</div>
          </div>

          <div class="flex items-center justify-between pt-1 border-t border-slate-800/80 text-[11px] font-mono">
            <span class="text-slate-400">Est. Impact: <strong class="text-amber-300">${p.timeToImpact}</strong></span>
            <button class="text-sky-400 hover:underline font-bold" onclick="airspaceSim.applyPrescribedMitigation('${p.predictedAttack}')">
              Deploy Fix →
            </button>
          </div>
        </div>
      `;
      })
      .join("");

    if (window.lucide) lucide.createIcons();
  }

  applyPrescribedMitigation(attackType) {
    if (attackType.includes("ADS-B Ghost")) {
      this.defense.psrSsrFusion = true;
      const toggle = document.getElementById("defense-psr-fusion");
      if (toggle) toggle.checked = true;
      this.logEvent("DEFENSE_USER", "Engaged Primary Radar (PSR) skin-paint data fusion to filter ghost aircraft.", "SUCCESS");
    } else if (attackType.includes("GPS Jamming")) {
      this.defense.multiFreqGnss = true;
      const toggle = document.getElementById("defense-multi-gnss");
      if (toggle) toggle.checked = true;
      this.logEvent("DEFENSE_USER", "Switched avionics to Multi-Frequency L5 GNSS and on-board IRS cross-check.", "SUCCESS");
    } else if (attackType.includes("ADS-B Trajectory")) {
      this.defense.tdoaMlVerification = true;
      const toggle = document.getElementById("defense-tdoa-ml");
      if (toggle) toggle.checked = true;
      this.logEvent("DEFENSE_USER", "Activated TDoA Machine Learning Fingerprinting to correct spoofed positions.", "SUCCESS");
    } else if (attackType.includes("VHF Voice")) {
      this.defense.autoFreqHop = true;
      const toggle = document.getElementById("defense-auto-freq");
      if (toggle) toggle.checked = true;
      this.logEvent("DEFENSE_USER", "Ordered emergency frequency change to secondary assigned channel 121.900 MHz.", "SUCCESS");
    }
  }

  renderActiveAttacksUI() {
    const list = document.getElementById("active-attacks-list");
    if (!list) return;

    if (this.activeAttacks.length === 0) {
      list.innerHTML = `<p class="text-xs text-slate-500 italic">No cyber-attacks currently injected. Sector operating in nominal security posture.</p>`;
      return;
    }

    list.innerHTML = this.activeAttacks
      .map(
        (a) => `
      <div class="flex items-center justify-between p-2 bg-red-950/40 border border-red-900/60 rounded text-xs font-mono">
        <div class="flex items-center space-x-2">
          <span class="w-2 h-2 rounded-full bg-red-500 animate-ping"></span>
          <span class="text-red-300 font-bold">${a.label}</span>
          <span class="text-slate-500">→ [Target: ${a.target}]</span>
        </div>
        <button class="px-2 py-0.5 bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-white rounded text-[10px]" onclick="airspaceSim.cancelAttack('${a.id}')">
          Neutralize
        </button>
      </div>
    `
      )
      .join("");
  }

  cancelAttack(attackId) {
    const atk = this.activeAttacks.find((a) => a.id === attackId);
    if (!atk) return;

    this.activeAttacks = this.activeAttacks.filter((a) => a.id !== attackId);
    this.jammingZones = this.jammingZones.filter((z) => z.id !== attackId);

    const flight = this.flights.find((f) => f.id === atk.target);
    if (flight) {
      flight.gnssJammed = false;
      flight.gnssSpoofed = false;
      flight.adsbSpoofed = false;
      flight.vhfSpoofed = false;
      flight.transponderRate = 350;
      flight.cpdlcTampered = false;
      flight.activeThreat = null;
      flight.claimedX = flight.trueX;
      flight.claimedY = flight.trueY;
    }

    if (atk.type === "ADSB_GHOST") {
      this.ghostAircraft = [];
    }

    this.renderActiveAttacksUI();
    this.renderFlightPills();
    this.logEvent("DEFENSE", `Attack neutralized: ${atk.label} terminated on ${atk.target}.`, "SUCCESS");
  }

  logEvent(type, message, level = "INFO") {
    const timestamp = new Date().toLocaleTimeString();
    this.eventLog.unshift({ timestamp, type, message, level });
    if (this.eventLog.length > 50) this.eventLog.pop();

    const logBox = document.getElementById("simulator-event-log");
    if (!logBox) return;

    logBox.innerHTML = this.eventLog
      .map((e) => {
        let badgeColor = "text-sky-400";
        if (e.level === "CRITICAL") badgeColor = "text-red-400 font-bold";
        else if (e.level === "WARNING") badgeColor = "text-amber-400";
        else if (e.level === "SUCCESS") badgeColor = "text-emerald-400";

        return `
        <div class="py-1 border-b border-slate-900 text-[11px] font-mono leading-tight">
          <span class="text-slate-500">${e.timestamp}</span>
          <span class="${badgeColor} ml-1">[${e.type}]</span>
          <span class="text-slate-300 ml-1">${e.message}</span>
        </div>
      `;
      })
      .join("");
  }
}

// Global instance
const airspaceSim = new AirspaceSimulator();
