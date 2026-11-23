# Civil Aviation Cybersecurity Live Risk Simulator & Attack Prediction Engine

An interactive, aerospace-grade cybersecurity risk assessment dashboard, live airspace simulator, and predictive AI anomaly forecasting engine implementing the methodology published in:

> **"Studying Cybersecurity in Civil Aviation, Including Developing and Applying Aviation Cybersecurity Risk Assessment"**  
> *Ahmed Abdelwahab Elmarady and Kamel Rahouma*  
> **IEEE Access**, Vol. 9, 2021. DOI: [10.1109/ACCESS.2021.3121230](https://doi.org/10.1109/ACCESS.2021.3121230)

---

## ✈️ Live Airspace Simulator & Attack Prediction Engine (`simulator.js`)

Unlike static risk matrices, this platform features a **real-time kinematic tactical airspace simulator** (TRACON 35 NM sector) that simulates live aircraft avionics, injects live cyber attacks, predicts threats before impact, and re-assesses risk in real time using the paper's **Algorithm 1**:

### 1. Real-Time Airspace & Avionics Kinematics
- **6 Active Commercial Flights** (`UAL421`, `DLH338`, `EGY701`, `BAW117`, `AFR502`, `SVA204`) with realistic flight phases (En-Route, Approach, Final Approach, Departure), speed, heading, and altitude profiles.
- **12 RPM Rotating Primary/Secondary Radar Sweep** with range rings (5, 10, 20, 30 NM), approach cones, runway centerlines (09L/27R, 09R/27L), waypoints, and 4 Ground Multilateration (MLAT) sensor stations.
- **Live Avionics Telemetry**: GNSS Carrier-to-Noise Ratio ($C/N_0$), SSR transponder reply rate (Hz), Time Difference of Arrival (TDoA) residuals ($\mu\text{s}$), VHF channel SNR, and CPDLC link states.

### 2. Red Team Cyber-Attack Injection Deck
Users can inject the 7 core cyber-attack vectors identified in the research paper onto any active flight:
1. **🚨 ADS-B Ghost Target Injection**: Injects synthetic 1090 MHz Mode S squitters creating phantom aircraft on collision courses without Primary Radar (PSR) skin-paint returns.
2. **🛰️ ADS-B Trajectory Spoofing**: Gradually offsets claimed coordinates from the true physical flight path.
3. **📡 GNSS RF Jamming (L1 1575.42 MHz)**: Deploys expanding RF interference contours that plunge satellite $C/N_0$ below lock threshold ($32\text{ dB-Hz}$).
4. **🗺️ GNSS Ephemeris Spoofing**: Injects synthetic satellite ephemeris, causing cross-track drift relative to on-board Inertial Reference Systems (IRS).
5. **🎙️ Rogue VHF Voice ATC Clearance**: Injects unauthorized altitude or heading clearances (Intolerable Risk, $r = 15.0$).
6. **📻 SSR Over-Interrogation**: Surges interrogation pulse rates to $1,650\text{ Hz}$ ($>1,200\text{ Hz}$ limit), triggering transponder thermal duty-cycle suppression.
7. **🌐 SWIM Enterprise Bus MITM**: Injects unsigned route amendments over the net-centric IP bus.

### 3. Blue Team Predictive AI Anomaly Forecaster
The predictive engine runs 6 multi-sensor anomaly detection algorithms to forecast attacks and impact:
- **TDoA Hyperbolic Residue Predictor**: Compares claimed ADS-B positions against theoretical arrival times at MLAT ground stations. Flags ghost targets ($P > 97\%$).
- **Kinematic Plausibility Forecaster**: Evaluates acceleration steps, unphysical turn rates, and velocity discontinuities.
- **Pre-Jamming $C/N_0$ Depletion Forecaster**: Detects GPS RF degradation 8–10 seconds before complete FMS satellite lock loss.
- **GNSS-IRS Cross-Track Drift Detector**: Flags ephemeris spoofing when dead-reckoning IRS diverges by $>0.45\text{ NM}$.
- **SSR Pulse Slope Forecaster**: Predicts transponder thermal shutdown 5 seconds before response cutoff.
- **VHF Flight Intent Parser**: Flags clearances contradicting filed flight plans and minimum safe altitudes.

### 4. Dynamic Real-Time Algorithm 1 Risk Re-Assessment
As attacks develop, the engine dynamically recalculates:
- $L_{\text{live}}$: Elevates based on observed attack signals.
- $I_{\text{live}}$: Escalates based on flight phase and traffic density.
- $r_{\text{live}} = L_{\text{live}} \times I_{\text{live}}$ with instant transition into **Intolerable ($r \ge 15$)**, **Tolerable ($5 \le r < 15$)**, or **Acceptable ($r < 5$)** on flight data blocks.

### 5. Multi-Layer Cyber Resilience Countermeasures
- **PSR-SSR Sensor Fusion**: Filters ghost ADS-B targets using primary radar skin echoes.
- **Multi-Frequency L5 GNSS + AAIM**: Automatically rejects jammed L1 signals and engages inertial navigation.
- **TDoA ML Localization**: Restores true aircraft coordinates using RF fingerprinting from OpenSky data.
- **Automated VHF Frequency Hopping**: Transmits emergency switch orders to pre-allocated backup channels.

### 6. Streaming Red/Blue Telemetry & Custom Ingestion Pipeline
- **Reactive Global Pipeline**: Dynamically synchronizes executive metrics, the 5×5 ICAO Risk Matrix, the Risk Registry, and CNS deep-dive charts with live streaming Red/Blue events.
- **Dual Data Source Switcher**: Seamlessly toggle between `[🟢 Live Predicted Stream]` and `[🔵 Research Baseline]`.
- **Adversarial Campaign Deck**: One-click launch of multi-stage coordinated campaigns (`GNSS Jamming` + `ADS-B Ghost Decoy` + `Rogue VHF Voice Clearance`).
- **Custom Telemetry Ingest Modal**: Ingest synthetic JSON packets (e.g., $C/N_0$ SNR drop, unphysical claimed vs. true coordinate divergence, interrogation PRF surge) with instant AI risk re-evaluation and attack forecasting.

---

## 🎯 Executive Summary of Research Findings (IEEE Access 2021)

| Aviation Domain | Highest Risk Asset | Lowest Risk Asset | Primary Vulnerability Drivers |
|:---|:---|:---|:---|
| **Communication** | **VHF Voice** ($r = 15.0$, **Intolerable**) | **CPDLC** ($r = 4.0 - 7.5$, **Acceptable/Tolerable**) | VHF voice is analog AM without encryption; spoofed clearances cause runway collisions or CFIT. CPDLC uses selective digital data links. |
| **Navigation** | **GNSS (GPS)** ($r = 14.4$, **Tolerable**) | **ILS / VOR** ($r = 4.5 - 6.0$, **Acceptable/Tolerable**) | GPS signals are extremely weak ($-160\text{ dBW}$); easily jammed by cheap $\$50$ PPDs. Ground aids require complex synchronized transmitters. |
| **Surveillance** | **ADS-B** ($r = 14.7$, **Tolerable**) | **SSR / PSR** ($r = 4.3 - 7.0$, **Acceptable/Tolerable**) | ADS-B broadcasts open 1090 MHz Mode S squitters without authentication (ghost targets). SSR uses directional interrogation. |
| **Networking** | **SWIM** ($r = 10.5$, **Medium / Tolerable**) | *N/A (Net-Centric)* | Net-centric IP exchanges introduce MITM and DoS threats; mitigated by Common PKI and private trust networks (INNOVA/ACORNS). |

---

## 📐 Mathematical Formulation (Algorithm 1)

1. **Numeric Risk Level ($r$) — Equation (1):**
   $$r = L \times I \quad (1 \le r \le 25)$$

2. **Qualitative Tolerability Index ($R$) — Equation (2):**
   $$R = \begin{cases} 
   \text{intolerable (Red)}, & r \ge 15 \\ 
   \text{tolerable (Orange)}, & 5 \le r < 15 \\ 
   \text{acceptable (Light Green)}, & r < 5 
   \end{cases}$$

3. **Conversion to Five-Point Scale — Table 5:**
   $$\text{Scale}(r) = \begin{cases} 
   5, & r \ge 20 \quad (\text{Intolerable}) \\ 
   4, & 15 \le r < 20 \quad (\text{Intolerable}) \\ 
   3, & 10 \le r < 15 \quad (\text{Tolerable}) \\ 
   2, & 5 \le r < 10 \quad (\text{Tolerable}) \\ 
   1, & r < 5 \quad (\text{Acceptable}) 
   \end{cases}$$

---

## 🚀 How to Run the Live Simulator & Dashboard

### Option A: Direct Browser Launch (Zero Dependencies)
Simply open `index.html` in any modern web browser:
```bash
# On Windows PowerShell:
Start-Process "index.html"
```

### Option B: Local Python HTTP Server with REST API
```bash
python server.py
# Server opens at http://localhost:8088
```

---

## 🧪 Automated Unit Verification
Run the complete test suite verifying all equations, tables, and domain rankings:
```bash
python test_engine.py
# Ran 7 tests in 0.001s - OK
```

---

## 📁 Repository Structure

- `index.html`: Aerospace glass-cockpit dashboard with Live Tactical Radar Scope, Attack Deck, and 8 analytical workspaces.
- `simulator.js`: Real-time kinematic flight engine, Red Team attack injector, and Blue Team predictive AI forecaster.
- `app.js`: Reactive controller managing Chart.js visualizations, ICAO 5×5 matrix, Algorithm 1 evaluator, and export modules.
- `data.js`: Extracted dataset of 23 threat scenarios, protocol specifications (Tables 6, 8, 10), and literature survey (Table 1).
- `style.css`: Cockpit dark-mode styling, telemetry borders, radar sweep animations, and print stylesheets.
- `risk_engine.py`: Standalone Python 3 engine executing Algorithm 1, dataclasses, and statistical summaries.
- `test_engine.py`: Automated unit test suite verifying 100% adherence to paper formulas and results.
- `server.py`: Lightweight Python server offering `/api/threats` and `/api/evaluate` REST endpoints.
