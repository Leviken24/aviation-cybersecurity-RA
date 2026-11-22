# Civil Aviation Cybersecurity Risk Assessment & Decision Support Dashboard

An interactive, aerospace-grade cybersecurity risk assessment dashboard and analytical engine implementing the methodology published in:

> **"Studying Cybersecurity in Civil Aviation, Including Developing and Applying Aviation Cybersecurity Risk Assessment"**  
> *Ahmed Abdelwahab Elmarady and Kamel Rahouma*  
> **IEEE Access**, Vol. 9, 2021. DOI: [10.1109/ACCESS.2021.3121230](https://doi.org/10.1109/ACCESS.2021.3121230)

---

## 🎯 Executive Summary of Research Findings

The paper develops a continuous qualitative and quantitative methodology (compliant with ICAO Documents 8973, 9895, 9985, and 10084) to evaluate cyber-attack threats across legacy and next-generation Civil Aviation Critical Infrastructure:

| Aviation Domain | Highest Risk Asset | Lowest Risk Asset | Primary Vulnerability Drivers |
|:---|:---|:---|:---|
| **Communication** | **VHF Voice** ($r = 15.0$, **Intolerable**) | **CPDLC** ($r = 4.0 - 7.5$, **Acceptable/Tolerable**) | VHF voice is analog AM without encryption; spoofed clearances cause runway collisions or CFIT. CPDLC uses selective digital data links. |
| **Navigation** | **GNSS (GPS)** ($r = 14.4$, **Tolerable**) | **ILS / VOR** ($r = 4.5 - 6.0$, **Acceptable/Tolerable**) | GPS signals are extremely weak ($-160\text{ dBW}$); easily jammed by cheap $\$50$ PPDs. Ground aids require complex synchronized transmitters. |
| **Surveillance** | **ADS-B** ($r = 14.7$, **Tolerable**) | **SSR / PSR** ($r = 4.3 - 7.0$, **Acceptable/Tolerable**) | ADS-B broadcasts open 1090 MHz Mode S squitters without authentication (ghost targets). SSR uses directional interrogation. |
| **Networking** | **SWIM** ($r = 10.5$, **Medium / Tolerable**) | *N/A (Net-Centric)* | Net-centric IP exchanges introduce MITM and DoS threats; mitigated by Common PKI and private trust networks (INNOVA/ACORNS). |

---

## 📐 Algorithmic Formulation (Algorithm 1)

### 1. Likelihood Determination ($L \in [1, 5]$) — Table 2
Likelihood is determined across 4 dimensions:
1. **Tool Cost**: $<\$1\text{k}$ (5), $<\$5\text{k}$ (4), $<\$10\text{k}$ (3), $<\$100\text{k}$ (2), $>\$100\text{k}$ (1)
2. **Tool Accessibility**: Easily accessible (5) $\to$ Highly restricted (1)
3. **Historical Frequency**: Once every 2 weeks (5) $\to$ Once every $3+$ years (1)
4. **Attacker Expertise**: Basic knowledge (5) $\to$ Complex specialized expertise (1)

### 2. Impact Determination ($I \in [1, 5]$) — Table 3
Worst-case scenario impact assessed across:
- **Operational Flight Impact**: Insignificant (1) $\to$ Serious total service outage (5)
- **Financial Recovery**: Business unit budget (1) $\to$ Governmental support required (5)
- **Reputational Confidence**: Isolated complaints (1) $\to$ Organization cannot continue (5)

### 3. Numeric Risk Level ($r$) — Equation (1)
$$r = L \times I \quad (1 \le r \le 25)$$

### 4. Qualitative Tolerability Index ($R$) — Equation (2)
$$R = \begin{cases} 
\text{intolerable (Red)}, & r \ge 15 \\ 
\text{tolerable (Orange)}, & 5 \le r < 15 \\ 
\text{acceptable (Light Green)}, & r < 5 
\end{cases}$$

- **Acceptable ($r < 5$)**: No further risk mitigation measures strictly required.
- **Tolerable ($5 \le r < 15$)**: Risk can be tolerated based on approved operational mitigations and active monitoring.
- **Intolerable ($r \ge 15$)**: Consequences are unacceptable; immediate mitigation is mandatory.

### 5. Conversion to Five-Point Scale — Table 5
$$\text{Scale}(r) = \begin{cases} 
5, & r \ge 20 \quad (\text{Intolerable}) \\ 
4, & 15 \le r < 20 \quad (\text{Intolerable}) \\ 
3, & 10 \le r < 15 \quad (\text{Tolerable}) \\ 
2, & 5 \le r < 10 \quad (\text{Tolerable}) \\ 
1, & r < 5 \quad (\text{Acceptable}) 
\end{cases}$$

---

## 🛡️ The Three Pillars of Aviation Cyber Resilience

As established in Section II of the paper, mitigation rests on:
1. **Capacity Building & Training**: Tabletop exercises, cyber flight simulations, pilot/controller awareness.
2. **Procedures & Regulations**: ICAO/EASA regulations, strict pilot read-back/hear-back, frequency spectrum policing.
3. **Systems & Security by Design**:
   - Cryptographic standards: ARINC 823 / ACARS Message Security (AMS) with Elliptic Curve Cryptography (ECC).
   - Sensor Data Fusion: Cross-checking cooperative SSR/ADS-B with non-cooperative Primary Radar (PSR) to eliminate ghost targets.
   - Machine Learning TDoA Fingerprinting: Verifying ADS-B position claims using OpenSky Network historical data.
   - Multi-Frequency GNSS (L1 + L5) with AAIM / RAIM multi-sensor integrity cross-checks.
   - SWIM Common Public Key Infrastructure (PKI) and ICAO INNOVA/ACORNS private secure trust framework.

---

## 🚀 How to Run the Dashboard

### Option A: Direct Browser Launch (Zero Dependencies)
Simply open `index.html` in any modern web browser (Google Chrome, Edge, Firefox, Safari):
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

- `index.html`: Aerospace cockpit glass-themed single-page application.
- `style.css`: Custom animations, color palettes, telemetry cards, and print styles.
- `data.js`: Extracted dataset of 23 threat scenarios, protocol specifications (Tables 6, 8, 10), and literature comparison (Table 1).
- `app.js`: Reactive controller managing charts, 5×5 matrix interactions, Algorithm 1 calculator, what-if simulator, and exports.
- `risk_engine.py`: Standalone Python module executing Algorithm 1, dataclasses, and statistical summaries.
- `test_engine.py`: Automated unit tests verifying 100% adherence to paper formulas and results.
- `server.py`: Lightweight Python server offering `/api/threats` and `/api/evaluate` REST endpoints.
