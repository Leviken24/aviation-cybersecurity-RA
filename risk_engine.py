"""
Aviation Cybersecurity Risk Assessment Engine
Implements Algorithm 1, Formula 1, Formula 2, and Tables 2-5 from:
"Studying Cybersecurity in Civil Aviation, Including Developing and Applying
Aviation Cybersecurity Risk Assessment" - Ahmed Abdelwahab Elmarady & Kamel Rahouma (IEEE Access 2021)
"""

from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple
import json

# Table 2: Description of categories of likelihood
LIKELIHOOD_CRITERIA = {
    5: {
        "rating": "High",
        "tool_cost": "Less than $1000",
        "tool_accessibility": "Easily accessible",
        "frequency": "At least once every two weeks",
        "expertise": "Basic knowledge"
    },
    4: {
        "rating": "Medium-High",
        "tool_cost": "Less than $5000",
        "tool_accessibility": "Available but not so easy",
        "frequency": "At least once every three months",
        "expertise": "Substantial basic information is required"
    },
    3: {
        "rating": "Medium",
        "tool_cost": "Less than $10000",
        "tool_accessibility": "Available with some conditions",
        "frequency": "Once every three months to a year",
        "expertise": "Advanced training and knowledge are required"
    },
    2: {
        "rating": "Medium-low",
        "tool_cost": "Less than $100000",
        "tool_accessibility": "Restricted access",
        "frequency": "Once every one to three years",
        "expertise": "Advanced knowledge and experience are required"
    },
    1: {
        "rating": "Low",
        "tool_cost": "More than $100000",
        "tool_accessibility": "Highly restricted access",
        "frequency": "Once every three years or more",
        "expertise": "Advanced and complex knowledge and experience are required"
    }
}

# Table 3: Description of various categories of impact
IMPACT_CRITERIA = {
    5: {
        "rating": "High",
        "operations": "Serious impact where no operational services can be provided for an extended time period",
        "finance": "Serious impact where recovery of such impact requires major support, e.g., governmental support",
        "reputation": "The reputation cannot be recovered with stakeholders and the organization/company may not continue in its current form"
    },
    4: {
        "rating": "Medium-High",
        "operations": "Major impact where a majority of operational services cannot be provided for some time",
        "finance": "Major impact where recovery of such impact requires approval from the board level",
        "reputation": "The reputation can be affected on capability to provide function services by the majority of the stakeholders"
    },
    3: {
        "rating": "Medium",
        "operations": "Moderate impact where some operational services cannot be provided",
        "finance": "Moderate impact where recovery of such impact requires upper management approval for response",
        "reputation": "The reputation can be affected on organization/company services and activities by a key stakeholder"
    },
    2: {
        "rating": "Medium-low",
        "operations": "Minor impact where some operational services are degraded",
        "finance": "Moderate impact where recovery of such impact requires delegated approval for response",
        "reputation": "The reputation can be affected by the complaints of a key stakeholder on organization/company service and activities"
    },
    1: {
        "rating": "Low",
        "operations": "Insignificant impact where operational services can be provided as usual",
        "finance": "Insignificant impact where recovery of such impact can be managed within business unit /section budget",
        "reputation": "The reputation can be affected by the isolated complaints of individual stakeholder"
    }
}


def calculate_numeric_risk(likelihood: float, impact: float) -> float:
    """
    Equation (1): r = L x I
    Where r is numeric risk level (1 to 25)
    """
    return round(likelihood * impact, 2)


def categorize_tolerability(r: float) -> str:
    """
    Equation (2):
    R =
      intolerable, r >= 15
      tolerable,   15 > r >= 5
      acceptable,  r < 5
    """
    if r >= 15.0:
        return "intolerable"
    elif r >= 5.0:
        return "tolerable"
    else:
        return "acceptable"


def convert_to_five_point_scale(r: float) -> int:
    """
    Table 5: Conversion of risk level into a five-point scale
    r >= 20      -> 5 (intolerable)
    20 > r >= 15 -> 4 (intolerable)
    15 > r >= 10 -> 3 (tolerable)
    10 > r >= 5  -> 2 (tolerable)
    r < 5        -> 1 (acceptable)
    """
    if r >= 20.0:
        return 5
    elif r >= 15.0:
        return 4
    elif r >= 10.0:
        return 3
    elif r >= 5.0:
        return 2
    else:
        return 1


@dataclass
class CyberThreat:
    id: str
    domain: str          # Communication, Navigation, Surveillance, Networking
    asset: str           # e.g., VHF Voice, CPDLC, GNSS, ADS-B, SWIM
    threat_type: str     # Eavesdropping, Jamming, Spoofing, etc.
    attack_vector: str
    cia_triad: str       # Confidentiality, Integrity, Availability
    likelihood: float    # 1.0 - 5.0
    impact: float        # 1.0 - 5.0
    description: str
    mitigations: List[str]
    mitigated_likelihood: Optional[float] = None
    mitigated_impact: Optional[float] = None

    @property
    def numeric_risk(self) -> float:
        return calculate_numeric_risk(self.likelihood, self.impact)

    @property
    def tolerability(self) -> str:
        return categorize_tolerability(self.numeric_risk)

    @property
    def five_point_scale(self) -> int:
        return convert_to_five_point_scale(self.numeric_risk)

    @property
    def mitigated_numeric_risk(self) -> float:
        l = self.mitigated_likelihood if self.mitigated_likelihood is not None else self.likelihood
        i = self.mitigated_impact if self.mitigated_impact is not None else self.impact
        return calculate_numeric_risk(l, i)

    @property
    def mitigated_tolerability(self) -> str:
        return categorize_tolerability(self.mitigated_numeric_risk)

    @property
    def mitigated_five_point_scale(self) -> int:
        return convert_to_five_point_scale(self.mitigated_numeric_risk)


# Dataset directly curated from paper text, Tables 6-12 and Figures 3-13
PAPER_THREATS_DATASET: List[CyberThreat] = [
    # --- Communication (Section III) ---
    CyberThreat(
        id="COM-VHF-01",
        domain="Communication",
        asset="VHF Voice",
        threat_type="Eavesdropping",
        attack_vector="Radio frequency interception of unencrypted 117.975-137 MHz AM voice transmissions using cheap RTL-SDR dongle or radio scanner.",
        cia_triad="Confidentiality",
        likelihood=4.8,
        impact=1.0,
        description="Conversations over VHF are unencrypted and public. High likelihood due to accessible SDRs, but minimal immediate impact on flight safety.",
        mitigations=[
            "Administrative frequency regulations and monitoring",
            "Transition to encrypted digital voice/data links (L-DACS, AeroMACS)",
            "Strict pilot/controller radio discipline"
        ],
        mitigated_likelihood=2.0,
        mitigated_impact=1.0
    ),
    CyberThreat(
        id="COM-VHF-02",
        domain="Communication",
        asset="VHF Voice",
        threat_type="Jamming",
        attack_vector="Broadcasting high-power RF noise or unmodulated carrier on assigned airport tower/approach frequencies using portable transmitters.",
        cia_triad="Availability",
        likelihood=4.0,
        impact=3.0,
        description="Likely due to low-cost jamming devices and open frequency lists in AIP. Medium impact as controllers must divert to secondary backup channels.",
        mitigations=[
            "Proper frequency spectrum management and international regulations",
            "Pre-designated backup frequencies on standby",
            "Directional ground receiver antenna arrays with null-steering"
        ],
        mitigated_likelihood=2.0,
        mitigated_impact=2.0
    ),
    CyberThreat(
        id="COM-VHF-03",
        domain="Communication",
        asset="VHF Voice",
        threat_type="Spoofing",
        attack_vector="Unauthorized rogue ground transmitter transmitting fabricated ATC clearances (e.g., false altitude changes or runway turns) to pilots.",
        cia_triad="Integrity",
        likelihood=3.0,
        impact=5.0,
        description="Requires aviation phraseology and transmitter knowledge, but causes intolerable impact on flight safety (risk of controlled flight into terrain or runway collision).",
        mitigations=[
            "Strict read-back / hear-back verification procedures",
            "Dual-frequency confirmation protocols for critical runway clearances",
            "Acoustic / voiceprint biometrics and secondary radar altitude validation"
        ],
        mitigated_likelihood=1.5,
        mitigated_impact=3.0
    ),
    CyberThreat(
        id="COM-CPDLC-01",
        domain="Communication",
        asset="CPDLC",
        threat_type="Eavesdropping",
        attack_vector="Interception of selective VDL2 (136.975 MHz) digital packet traffic between ATC and aircraft.",
        cia_triad="Confidentiality",
        likelihood=2.5,
        impact=1.6,
        description="Digital packets require specialized VDL2 decoders. Low safety impact since data is operational clearances.",
        mitigations=[
            "ARINC 823 cryptographic encapsulation",
            "Session key exchange via Elliptic Curve Cryptography (ECC)"
        ],
        mitigated_likelihood=1.2,
        mitigated_impact=1.0
    ),
    CyberThreat(
        id="COM-CPDLC-02",
        domain="Communication",
        asset="CPDLC",
        threat_type="Jamming / Flooding",
        attack_vector="Transmitting multiple burst packets to saturate VDL2 receiver buffers or blocking 136.975 MHz signaling channel.",
        cia_triad="Availability",
        likelihood=2.0,
        impact=4.0,
        description="Channel blocking forces aircraft to drop digital data link and revert to congested VHF voice channels during en-route flight.",
        mitigations=[
            "Automatic multi-link fallback (switching to SATCOM or HFDL)",
            "Rate-limiting and buffer overflow guards on VDL ground stations"
        ],
        mitigated_likelihood=1.5,
        mitigated_impact=2.0
    ),
    CyberThreat(
        id="COM-CPDLC-03",
        domain="Communication",
        asset="CPDLC",
        threat_type="Spoofing / Injection",
        attack_vector="Masquerading as ATC or aircraft by forging ARINC messages to inject unauthorized routing instructions.",
        cia_triad="Integrity",
        likelihood=1.5,
        impact=5.0,
        description="Complex knowledge of ARINC protocols and session handshake is needed. High potential impact if erroneous route is accepted.",
        mitigations=[
            "Aeronautical Radio Inc. (ARINC) 823 standard implementation",
            "Host Identity Protocol (HIP) and digital certificate authentication"
        ],
        mitigated_likelihood=1.0,
        mitigated_impact=2.5
    ),
    CyberThreat(
        id="COM-ACARS-01",
        domain="Communication",
        asset="ACARS",
        threat_type="Weight & Balance Tampering",
        attack_vector="Ground-based injection of falsified load sheet / cargo distribution data via ARINC 618 character links.",
        cia_triad="Integrity",
        likelihood=1.6,
        impact=5.0,
        description="Incorrect weight & balance data received before takeoff could lead to improper elevator trim, causing loss of pitch control during rotation.",
        mitigations=[
            "Cross-verification with physical ground dispatch manifest",
            "ACARS Message Security (AMS) cryptographic message authentication (ARINC 823-P1)"
        ],
        mitigated_likelihood=1.0,
        mitigated_impact=2.0
    ),
    CyberThreat(
        id="COM-ACARS-02",
        domain="Communication",
        asset="ACARS",
        threat_type="Flight Plan Update Tampering",
        attack_vector="Transmitting bogus route waypoints via ACARS to aircraft flight management system (FMS).",
        cia_triad="Integrity",
        likelihood=1.6,
        impact=5.0,
        description="Pilots accepting modified route deviate laterally from airways, potentially entering conflicting airspace or restricted zones.",
        mitigations=[
            "Mandatory verbal ATC confirmation before activating FMS route updates",
            "Digital signatures on airline operational control (AOC) messages"
        ],
        mitigated_likelihood=1.0,
        mitigated_impact=2.0
    ),

    # --- Navigation (Section IV) ---
    CyberThreat(
        id="NAV-GNSS-01",
        domain="Navigation",
        asset="GNSS",
        threat_type="Jamming",
        attack_vector="Broadcasting interference on GPS L1 (1575.42 MHz) or GLONASS frequencies using illicit Personal Privacy Devices (PPDs) or military-grade jammers.",
        cia_triad="Availability",
        likelihood=4.8,
        impact=3.0,
        description="Extremely high likelihood due to cheap PPDs and fragile -160 dBW received satellite signals. Medium impact because terrestrial aids (VOR/DME/ILS) remain available as backup.",
        mitigations=[
            "Transition to multi-frequency / multi-constellation GNSS (GPS L1/L5 + Galileo + GLONASS)",
            "Enforcement of strict anti-jammer regulations and radio direction-finding patrols",
            "Maintenance of Alternative Positioning, Navigation, and Timing (A-PNT) ground infrastructure"
        ],
        mitigated_likelihood=2.2,
        mitigated_impact=2.0
    ),
    CyberThreat(
        id="NAV-GNSS-02",
        domain="Navigation",
        asset="GNSS",
        threat_type="Spoofing",
        attack_vector="Transmitting synthetic satellite signals with slightly higher power to take over GNSS receiver tracking loops and induce position/time errors.",
        cia_triad="Integrity",
        likelihood=2.2,
        impact=5.0,
        description="Requires specialized multi-channel RF simulator and orbit ephemeris synthesis. High impact if undetected during approach or en-route.",
        mitigations=[
            "Cross-checking GNSS position against on-board Inertial Reference System (IRS) and DME-DME",
            "Receiver Autonomous Integrity Monitoring (RAIM) & Aircraft Autonomous Integrity Monitoring (AAIM)",
            "Galileo Open Service Navigation Message Authentication (OS-NMA)"
        ],
        mitigated_likelihood=1.2,
        mitigated_impact=2.5
    ),
    CyberThreat(
        id="NAV-ILS-01",
        domain="Navigation",
        asset="ILS",
        threat_type="Single-Tone Attack",
        attack_vector="Broadcasting an unmodulated 90 Hz or 150 Hz tone at the localizer (108-111.975 MHz) or glide slope (328.6-335.4 MHz) carrier frequency.",
        cia_triad="Integrity",
        likelihood=1.2,
        impact=5.0,
        description="Biases the course deviation indicator (CDI) needle, pulling aircraft off runway centerline during final blind landing.",
        mitigations=[
            "Perimeter ground RF monitoring sensors along airport approaches",
            "Cross-comparison with radar altimeter, GPS-GBAS, and visual glide slope indicators"
        ],
        mitigated_likelihood=1.0,
        mitigated_impact=2.5
    ),
    CyberThreat(
        id="NAV-ILS-02",
        domain="Navigation",
        asset="ILS",
        threat_type="Overshadow Attack",
        attack_vector="Transmitting a pre-crafted illegitimate ILS signal at higher RF power to overpower the legitimate ground station signal.",
        cia_triad="Integrity",
        likelihood=1.2,
        impact=5.0,
        description="Forces aircraft receiver phase-lock loop to track the hostile signal, misleading pilot or autopilot during autoland.",
        mitigations=[
            "Continuous automated signal integrity verification at runway threshold monitors",
            "GBAS differential correction cross-checks"
        ],
        mitigated_likelihood=1.0,
        mitigated_impact=2.5
    ),
    CyberThreat(
        id="NAV-VOR-01",
        domain="Navigation",
        asset="VOR",
        threat_type="Jamming",
        attack_vector="Interference on 108-117.975 MHz band preventing detection of 30 Hz reference/variable phase signals.",
        cia_triad="Availability",
        likelihood=1.3,
        impact=3.5,
        description="VOR is a legacy non-precision aid. Low likelihood due to specialized aeronautical frequencies; low risk profile.",
        mitigations=[
            "Automatic switching to DME-DME positioning or GPS RNAV",
            "Radio spectrum policing around ground VOR stations"
        ],
        mitigated_likelihood=1.0,
        mitigated_impact=2.0
    ),
    CyberThreat(
        id="NAV-VOR-02",
        domain="Navigation",
        asset="VOR",
        threat_type="Spoofing",
        attack_vector="Synthesizing modulated 30 Hz subcarrier to shift the perceived bearing radial angle from the station.",
        cia_triad="Integrity",
        likelihood=1.0,
        impact=4.5,
        description="Complex dual-frequency modulation required. Minimal occurrence; risk is acceptable.",
        mitigations=[
            "Dual-VOR cross-bearing discrepancy checks",
            "Periodic flight inspection and ground station integrity sensors"
        ],
        mitigated_likelihood=1.0,
        mitigated_impact=2.0
    ),

    # --- Surveillance (Section V) ---
    CyberThreat(
        id="SUR-SSR-01",
        domain="Surveillance",
        asset="SSR",
        threat_type="Jamming",
        attack_vector="High-power directional RF pulse jamming on 1030 MHz (interrogation) or 1090 MHz (reply) frequencies.",
        cia_triad="Availability",
        likelihood=1.6,
        impact=4.3,
        description="Rotating mechanical radar antenna and high power make jamming difficult without military-grade hardware. Causes radar drops on ATC displays.",
        mitigations=[
            "Primary Surveillance Radar (PSR) uncooperative target fallback",
            "Multi-radar coverage overlapping from adjacent sectors"
        ],
        mitigated_likelihood=1.2,
        mitigated_impact=2.0
    ),
    CyberThreat(
        id="SUR-SSR-02",
        domain="Surveillance",
        asset="SSR",
        threat_type="Spoofing / Ghost Targets",
        attack_vector="Transmitting synchronized 1090 MHz Mode A/C/S pulses in response to ground interrogations to inject phantom aircraft.",
        cia_triad="Integrity",
        likelihood=1.4,
        impact=5.0,
        description="Spoofs ATC interrogators into plotting non-existent aircraft tracks, triggering false conflict alerts.",
        mitigations=[
            "Data fusion between SSR and Primary Surveillance Radar (PSR) returns",
            "Interrogation beam timing and directional monopulse verification"
        ],
        mitigated_likelihood=1.0,
        mitigated_impact=2.5
    ),
    CyberThreat(
        id="SUR-SSR-03",
        domain="Surveillance",
        asset="SSR",
        threat_type="Over-Interrogation",
        attack_vector="Flooding transponders with >1200 interrogations/sec on 1030 MHz from multiple unsynchronized ground transmitters.",
        cia_triad="Availability",
        likelihood=1.0,
        impact=4.3,
        description="Forces transponder duty-cycle limiting circuitry to desensitize, causing legitimate radar track loss (documented in 2014 Central Europe incident).",
        mitigations=[
            "EASA/ICAO transponder interrogation rate coordination",
            "Ground station power budget and interrogation scheduling limits"
        ],
        mitigated_likelihood=1.0,
        mitigated_impact=1.5
    ),
    CyberThreat(
        id="SUR-MLAT-01",
        domain="Surveillance",
        asset="MLAT / WAM",
        threat_type="GPS De-synchronization Attack",
        attack_vector="Targeting ground MLAT receiver GPS timing clocks using distributed multi-device GPS spoofing.",
        cia_triad="Integrity",
        likelihood=2.5,
        impact=3.6,
        description="MLAT relies on sub-nanosecond Time Difference of Arrival (TDoA). Distorting clock synchronization shifts computed aircraft positions.",
        mitigations=[
            "Physical-layer verification (Doppler shift, carrier phase analysis)",
            "Equipping ground stations with backup Rubidium / Cesium atomic clocks"
        ],
        mitigated_likelihood=1.5,
        mitigated_impact=2.0
    ),
    CyberThreat(
        id="SUR-ADSB-01",
        domain="Surveillance",
        asset="ADS-B",
        threat_type="Eavesdropping",
        attack_vector="Passive reception of 1090 MHz unencrypted Extended Squitter broadcasts using cheap USB SDR sticks.",
        cia_triad="Confidentiality",
        likelihood=4.8,
        impact=1.0,
        description="Worldwide crowdsourced networks (FlightRadar24, OpenSky) track ADS-B openly. Negligible safety impact.",
        mitigations=[
            "ICAO Privacy ICAO Address (PIA) anonymous identifier rotation for sensitive flights",
            "Acceptance of open broadcast model for civil transparency"
        ],
        mitigated_likelihood=2.5,
        mitigated_impact=1.0
    ),
    CyberThreat(
        id="SUR-ADSB-02",
        domain="Surveillance",
        asset="ADS-B",
        threat_type="Jamming",
        attack_vector="Flooding 1090 MHz channel with RF noise, suppressing reception of low-power airborne transponder squitters.",
        cia_triad="Availability",
        likelihood=4.2,
        impact=3.5,
        description="High likelihood due to low receiving power threshold of ADS-B ground antennas and SDR accessibility. High risk in ADS-B-only airspaces.",
        mitigations=[
            "TDoA multi-station fingerprinting to localize aircraft even during signal degradation",
            "Retaining SSR/MLAT backup networks in high-density terminal sectors"
        ],
        mitigated_likelihood=2.0,
        mitigated_impact=2.0
    ),
    CyberThreat(
        id="SUR-ADSB-03",
        domain="Surveillance",
        asset="ADS-B",
        threat_type="Spoofing / Ghost Targets / Deletion",
        attack_vector="Injecting false 1090ES Mode S frames with bogus ICAO addresses, fake altitudes, or altered positions; modifying trajectory vectors.",
        cia_triad="Integrity",
        likelihood=2.9,
        impact=4.8,
        description="Readily executed with SDR and open-source tools (e.g. GNU Radio). High impact on ATC situational awareness and automatic collision avoidance systems.",
        mitigations=[
            "Location verification using multilateration (MLAT) TDoA cross-checks",
            "Machine-learning TDoA fingerprinting using OpenSky historical data",
            "Angle of Arrival (AoA) sector antennas and monopulse direction-finding",
            "ADS-B cryptographic broadcast authentication (ECC short signatures / X.509)"
        ],
        mitigated_likelihood=1.5,
        mitigated_impact=2.5
    ),

    # --- Networking / SWIM (Section VI) ---
    CyberThreat(
        id="NET-SWIM-01",
        domain="Networking",
        asset="SWIM",
        threat_type="Man-in-the-Middle / Data Tampering",
        attack_vector="Interception and modification of net-centric aeronautical/meteorological messages across IP interfaces without end-to-end acknowledgement.",
        cia_triad="Integrity",
        likelihood=3.5,
        impact=3.0,
        description="SWIM connects ANSPs, airlines, airports, and military via IP networks. Remote or insider access enables message modification.",
        mitigations=[
            "SWIM Common Public Key Infrastructure (Common PKI) with mutual TLS digital certificates",
            "ICAO INNOVA/ACORNS private secure trust framework",
            "Strict end-to-end cryptographic message signing"
        ],
        mitigated_likelihood=1.8,
        mitigated_impact=2.0
    ),
    CyberThreat(
        id="NET-SWIM-02",
        domain="Networking",
        asset="SWIM",
        threat_type="Unauthorized Access & DoS",
        attack_vector="Distributed Denial of Service (DDoS) against SWIM messaging buses (JMS, AMQP) or unauthorized lateral movement within SWIM portals.",
        cia_triad="Availability",
        likelihood=3.5,
        impact=3.0,
        description="Outage forces ATM facilities to fall back to isolated manual coordination channels, causing delays and lost shared situational awareness.",
        mitigations=[
            "Isolated private aviation IP network partitioning (air-gapped from public internet)",
            "High-availability redundant service clusters with DDoS scrubbing",
            "Zero Trust Network Architecture (ZTNA) and role-based access control (RBAC)"
        ],
        mitigated_likelihood=1.5,
        mitigated_impact=2.0
    )
]


def run_algorithm_1(dataset: List[CyberThreat] = PAPER_THREATS_DATASET) -> Dict:
    """
    Executes Algorithm 1 on the complete dataset and compiles statistics.
    """
    results = []
    acceptable_count = 0
    tolerable_count = 0
    intolerable_count = 0

    domain_summary = {}

    for t in dataset:
        # Step 5: Likelihood L (from Table 2)
        L = t.likelihood
        # Step 6: Impact I (from Table 3)
        I = t.impact
        # Step 7: calculate numeric risk r = L * I (Eq. 1)
        r = calculate_numeric_risk(L, I)
        # Step 8: categorize r into R (Eq. 2)
        R = categorize_tolerability(r)
        # Step 9: convert r to five-point scale (Table 5)
        scale_5 = convert_to_five_point_scale(r)

        if R == "acceptable":
            acceptable_count += 1
        elif R == "tolerable":
            tolerable_count += 1
        elif R == "intolerable":
            intolerable_count += 1

        if t.domain not in domain_summary:
            domain_summary[t.domain] = {
                "threats": [],
                "max_risk": 0.0,
                "highest_risk_asset": "",
                "lowest_risk_asset": "",
                "avg_risk": 0.0
            }
        domain_summary[t.domain]["threats"].append((t.asset, t.threat_type, r, R, scale_5))

        results.append({
            "id": t.id,
            "domain": t.domain,
            "asset": t.asset,
            "threat_type": t.threat_type,
            "likelihood": L,
            "impact": I,
            "numeric_risk": r,
            "tolerability": R,
            "five_point_scale": scale_5,
            "mitigated_risk": t.mitigated_numeric_risk,
            "mitigated_tolerability": t.mitigated_tolerability,
            "mitigated_five_point_scale": t.mitigated_five_point_scale
        })

    # Domain-level summary calculations
    for dom, data in domain_summary.items():
        threats = data["threats"]
        risks = [item[2] for item in threats]
        data["max_risk"] = max(risks)
        data["avg_risk"] = round(sum(risks) / len(risks), 2)
        # Sort threats by risk
        sorted_threats = sorted(threats, key=lambda x: x[2], reverse=True)
        data["highest_risk_asset"] = sorted_threats[0][0]
        data["lowest_risk_asset"] = sorted_threats[-1][0]

    return {
        "total_threats": len(results),
        "acceptable_count": acceptable_count,
        "tolerable_count": tolerable_count,
        "intolerable_count": intolerable_count,
        "domain_summary": domain_summary,
        "threats": results
    }


if __name__ == "__main__":
    summary = run_algorithm_1()
    print("=== Algorithm 1 Execution Summary ===")
    print(f"Total Threats Assessed: {summary['total_threats']}")
    print(f"Acceptable Risks: {summary['acceptable_count']}")
    print(f"Tolerable Risks:  {summary['tolerable_count']}")
    print(f"Intolerable Risks: {summary['intolerable_count']}")
    print("\n--- Domain Summary ---")
    for dom, data in summary["domain_summary"].items():
        print(f"Domain: {dom:15} | Max Risk: {data['max_risk']:5.2f} | Avg Risk: {data['avg_risk']:5.2f} | Highest Risk Asset: {data['highest_risk_asset']}")
