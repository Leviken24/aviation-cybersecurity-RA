/**
 * Civil Aviation Cybersecurity Risk Assessment Database
 * Extracted and modeled directly from:
 * "Studying Cybersecurity in Civil Aviation, Including Developing and Applying
 * Aviation Cybersecurity Risk Assessment" - Ahmed Abdelwahab Elmarady & Kamel Rahouma (IEEE Access 2021)
 */

const LIKELIHOOD_TABLE = [
  {
    scale: 5,
    rating: "High",
    toolCost: "Less than $1000",
    accessibility: "Easily accessible",
    frequency: "At least once every two weeks",
    expertise: "Basic knowledge"
  },
  {
    scale: 4,
    rating: "Medium-High",
    toolCost: "Less than $5000",
    accessibility: "Available but not so easy",
    frequency: "At least once every three months",
    expertise: "Substantial basic information is required"
  },
  {
    scale: 3,
    rating: "Medium",
    toolCost: "Less than $10000",
    accessibility: "Available with some conditions",
    frequency: "Once every three months to a year",
    expertise: "Advanced training and knowledge are required"
  },
  {
    scale: 2,
    rating: "Medium-low",
    toolCost: "Less than $100000",
    accessibility: "Restricted access",
    frequency: "Once every one to three years",
    expertise: "Advanced knowledge and experience are required"
  },
  {
    scale: 1,
    rating: "Low",
    toolCost: "More than $100000",
    accessibility: "Highly restricted access",
    frequency: "Once every three years or more",
    expertise: "Advanced and complex knowledge and experience are required"
  }
];

const IMPACT_TABLE = [
  {
    scale: 5,
    rating: "High",
    operations: "Serious impact where no operational services can be provided for an extended time period",
    finance: "Serious impact where recovery of such impact requires major support, e.g., governmental support",
    reputation: "The reputation cannot be recovered with stakeholders and the organization/company may not continue in its current form"
  },
  {
    scale: 4,
    rating: "Medium-High",
    operations: "Major impact where a majority of operational services cannot be provided for some time",
    finance: "Major impact where recovery of such impact requires approval from the board level",
    reputation: "The reputation can be affected on capability to provide function services by majority of the stakeholders"
  },
  {
    scale: 3,
    rating: "Medium",
    operations: "Moderate impact where some operational services cannot be provided",
    finance: "Moderate impact where recovery of such impact requires upper management approval for response",
    reputation: "The reputation can be affected on organization/company services and activities by a key stakeholder"
  },
  {
    scale: 2,
    rating: "Medium-low",
    operations: "Minor impact where some operational services are degraded",
    finance: "Moderate impact where recovery of such impact requires delegated approval for response",
    reputation: "The reputation can be affected by the complaints of a key stakeholder on organization/company service and activities"
  },
  {
    scale: 1,
    rating: "Low",
    operations: "Insignificant impact where operational services can be provided as usual",
    finance: "Insignificant impact where recovery of such impact can be managed within business unit /section budget",
    reputation: "The reputation can be affected by the isolated complaints of individual stakeholder"
  }
];

// Table 4: Cybersecurity Risk Matrix definition
// Formula: r = L x I
// R: intolerable (r >= 15), tolerable (15 > r >= 5), acceptable (r < 5)
// Scale mapping (Table 5):
// r >= 20 -> 5
// 20 > r >= 15 -> 4
// 15 > r >= 10 -> 3
// 10 > r >= 5 -> 2
// r < 5 -> 1

const INITIAL_THREATS = [
  // --- COMMUNICATION ---
  {
    id: "COM-VHF-01",
    domain: "Communication",
    asset: "VHF Voice",
    threatType: "Eavesdropping",
    category: "Radio Frequency",
    ciaTriad: "Confidentiality",
    likelihood: 4.8,
    impact: 1.0,
    figure: "Figure 3",
    attackVector: "Passive radio reception of analog AM voice on 117.975–137 MHz using inexpensive RTL-SDR or scanner.",
    description: "VHF voice is broadcast in the clear without encryption. Extremely high likelihood due to accessible SDRs, but minimal direct safety impact.",
    mitigations: [
      "Administrative spectrum enforcement & monitor stations",
      "Strict radio discipline",
      "Transition toward encrypted digital voice/data links"
    ],
    mitigatedLikelihood: 2.0,
    mitigatedImpact: 1.0,
    appliedMitigations: []
  },
  {
    id: "COM-VHF-02",
    domain: "Communication",
    asset: "VHF Voice",
    threatType: "Jamming",
    category: "Radio Frequency",
    ciaTriad: "Availability",
    likelihood: 4.0,
    impact: 3.0,
    figure: "Figure 3",
    attackVector: "Broadcasting high-power RF carrier or noise on published airport tower/approach frequencies.",
    description: "Easily carried out with cheap commercial jammers. Causes loss of communication channel, spiking controller workload and forcing backup frequency switch.",
    mitigations: [
      "Proper national/international frequency management",
      "Pre-allocated backup channels with quick-switch procedures",
      "Directional antenna arrays & RF interference direction finding"
    ],
    mitigatedLikelihood: 2.0,
    mitigatedImpact: 2.0,
    appliedMitigations: []
  },
  {
    id: "COM-VHF-03",
    domain: "Communication",
    asset: "VHF Voice",
    threatType: "Spoofing",
    category: "Radio Frequency",
    ciaTriad: "Integrity",
    likelihood: 3.0,
    impact: 5.0,
    figure: "Figure 3",
    attackVector: "Transmitting fraudulent ATC voice instructions (false clearances, erroneous heading or altitude) to aircraft.",
    description: "Requires basic aviation phraseology knowledge. Represents an INTOLERABLE risk level because wrong clearances can cause runway collisions or CFIT.",
    mitigations: [
      "Strict pilot-ATC read-back and hear-back procedures",
      "Secondary radar cross-check of aircraft response",
      "Dual-frequency confirmation for critical departure/approach instructions",
      "Voice biometrics / acoustic authentication"
    ],
    mitigatedLikelihood: 1.5,
    mitigatedImpact: 3.0,
    appliedMitigations: []
  },
  {
    id: "COM-CPDLC-01",
    domain: "Communication",
    asset: "CPDLC",
    threatType: "Eavesdropping",
    category: "Data Link",
    ciaTriad: "Confidentiality",
    likelihood: 2.5,
    impact: 1.6,
    figure: "Figure 4",
    attackVector: "Interception of VDL2 (136.975 MHz) digital packet frames.",
    description: "Requires VDL2 protocol decoders. Selective addressing reduces passive interception compared to broadcast VHF voice.",
    mitigations: [
      "ARINC 823 encryption wrapping",
      "Elliptic Curve Cryptography (ECC) session keys"
    ],
    mitigatedLikelihood: 1.2,
    mitigatedImpact: 1.0,
    appliedMitigations: []
  },
  {
    id: "COM-CPDLC-02",
    domain: "Communication",
    asset: "CPDLC",
    threatType: "Jamming / Flooding",
    category: "Data Link",
    ciaTriad: "Availability",
    likelihood: 2.0,
    impact: 4.0,
    figure: "Figure 4",
    attackVector: "Transmitting repeated malformed CPDLC packets to overwhelm VDL ground station buffers or jamming 136.975 MHz.",
    description: "Forces data link teardown, causing ATC and aircraft to revert to congested voice frequencies.",
    mitigations: [
      "Multi-link redundancy (automatic switch to SATCOM or HFDL)",
      "Ground station rate limiting and queue threshold alarms"
    ],
    mitigatedLikelihood: 1.5,
    mitigatedImpact: 2.0,
    appliedMitigations: []
  },
  {
    id: "COM-CPDLC-03",
    domain: "Communication",
    asset: "CPDLC",
    threatType: "Spoofing / Injection",
    category: "Data Link",
    ciaTriad: "Integrity",
    likelihood: 1.5,
    impact: 5.0,
    figure: "Figure 4",
    attackVector: "Masquerading as ATC or aircraft by injecting unauthorized clearance packets.",
    description: "Requires complex understanding of ARINC 622/623 protocol stacks and active session hijacking.",
    mitigations: [
      "Host Identity Protocol (HIP)",
      "ARINC 823 digital signature authentication",
      "Mandatory pilot voice readback on route clearance changes"
    ],
    mitigatedLikelihood: 1.0,
    mitigatedImpact: 2.5,
    appliedMitigations: []
  },
  {
    id: "COM-ACARS-01",
    domain: "Communication",
    asset: "ACARS",
    threatType: "Weight & Balance Update Tampering",
    category: "Avionics Data Link",
    ciaTriad: "Integrity",
    likelihood: 1.6,
    impact: 5.0,
    figure: "Figure 5",
    attackVector: "Ground injection of false aircraft weight and center-of-gravity load sheet data via ARINC 618 character stream.",
    description: "Incorrect stabilizer trim calculation manifests during takeoff rotation, creating uncontrollable pitch-up/pitch-down attitude.",
    mitigations: [
      "ACARS Message Security (AMS) cryptographic message authentication",
      "Cross-verification with physical cargo/fuel dispatch sheet"
    ],
    mitigatedLikelihood: 1.0,
    mitigatedImpact: 2.0,
    appliedMitigations: []
  },
  {
    id: "COM-ACARS-02",
    domain: "Communication",
    asset: "ACARS",
    threatType: "Flight Plan Update Tampering",
    category: "Avionics Data Link",
    ciaTriad: "Integrity",
    likelihood: 1.6,
    impact: 5.0,
    figure: "Figure 5",
    attackVector: "Transmitting bogus route waypoints to aircraft Flight Management System (FMS).",
    description: "Leads to lateral route deviation into prohibited airspace or conflicting air traffic corridors.",
    mitigations: [
      "Cryptographic signing of airline operational control (AOC) messages",
      "Mandatory controller clearance validation before FMS route activation"
    ],
    mitigatedLikelihood: 1.0,
    mitigatedImpact: 2.0,
    appliedMitigations: []
  },

  // --- NAVIGATION ---
  {
    id: "NAV-GNSS-01",
    domain: "Navigation",
    asset: "GNSS",
    threatType: "Jamming",
    category: "Satellite Navigation",
    ciaTriad: "Availability",
    likelihood: 4.8,
    impact: 3.0,
    figure: "Figure 6",
    attackVector: "Transmission of RF interference on GPS L1 (1575.42 MHz) or GLONASS bands using portable personal privacy devices (PPDs) or military jammers.",
    description: "Extremely high likelihood due to widespread PPD availability and very weak incoming satellite signal power (~ -160 dBW). Tolerable impact in regions with legacy ground radio aids.",
    mitigations: [
      "Multi-constellation & multi-frequency GNSS receivers (L1, L2, L5 / Galileo / BeiDou)",
      "Retaining terrestrial Alternative Positioning, Navigation, and Timing (A-PNT) networks",
      "Airport perimeter spectrum monitoring & automated direction finding"
    ],
    mitigatedLikelihood: 2.2,
    mitigatedImpact: 2.0,
    appliedMitigations: []
  },
  {
    id: "NAV-GNSS-02",
    domain: "Navigation",
    asset: "GNSS",
    threatType: "Spoofing",
    category: "Satellite Navigation",
    ciaTriad: "Integrity",
    likelihood: 2.2,
    impact: 5.0,
    figure: "Figure 6",
    attackVector: "Broadcasting counterfeit GPS signals with progressive time/phase offsets to gradually drag receiver positioning off track.",
    description: "Requires specialized multi-channel RF generator. High impact if undetected during precision approach or remote oceanic routing.",
    mitigations: [
      "Receiver Autonomous Integrity Monitoring (RAIM) & Aircraft Autonomous Integrity Monitoring (AAIM)",
      "Cross-check against Inertial Reference System (IRS) and DME-DME fix",
      "Galileo Open Service Navigation Message Authentication (OS-NMA)"
    ],
    mitigatedLikelihood: 1.2,
    mitigatedImpact: 2.5,
    appliedMitigations: []
  },
  {
    id: "NAV-ILS-01",
    domain: "Navigation",
    asset: "ILS",
    threatType: "Single-Tone Attack",
    category: "Terrestrial Precision Landing",
    ciaTriad: "Integrity",
    likelihood: 1.2,
    impact: 5.0,
    figure: "Figure 7",
    attackVector: "Transmitting a standalone 90 Hz or 150 Hz tone at localizer (108-111.975 MHz) or glide slope frequencies.",
    description: "Distorts the course deviation indicator (CDI) needle, nudging approaching aircraft away from runway centerline during instrument landing.",
    mitigations: [
      "Automated field-strength monitoring along runway approach corridors",
      "Cross-check with radar altimeter, runway lights, and GBAS differential signals"
    ],
    mitigatedLikelihood: 1.0,
    mitigatedImpact: 2.5,
    appliedMitigations: []
  },
  {
    id: "NAV-ILS-02",
    domain: "Navigation",
    asset: "ILS",
    threatType: "Overshadow Attack",
    category: "Terrestrial Precision Landing",
    ciaTriad: "Integrity",
    likelihood: 1.2,
    impact: 5.0,
    figure: "Figure 7",
    attackVector: "Overpowering the legitimate localizer/glide slope signal with an aligned, higher-power fake beam.",
    description: "Forces aircraft receiver phase-lock loops to track the attacker's guidance signal.",
    mitigations: [
      "ILS near-field and far-field integrity monitors with automated interlock shutoff",
      "Airport perimeter physical and radio surveillance"
    ],
    mitigatedLikelihood: 1.0,
    mitigatedImpact: 2.5,
    appliedMitigations: []
  },
  {
    id: "NAV-VOR-01",
    domain: "Navigation",
    asset: "VOR",
    threatType: "Jamming",
    category: "Terrestrial En-Route Navigation",
    ciaTriad: "Availability",
    likelihood: 1.3,
    impact: 3.5,
    figure: "Figure 8",
    attackVector: "Broadcasting in-band interference on 108–117.975 MHz to suppress 30 Hz reference/variable phase detection.",
    description: "Low likelihood due to dedicated aeronautical frequency licensing and line-of-sight propagation. Acceptable overall risk.",
    mitigations: [
      "Switching to DME-DME or Area Navigation (RNAV)",
      "Spectrum monitoring by civil aviation authorities"
    ],
    mitigatedLikelihood: 1.0,
    mitigatedImpact: 2.0,
    appliedMitigations: []
  },
  {
    id: "NAV-VOR-02",
    domain: "Navigation",
    asset: "VOR",
    threatType: "Spoofing",
    category: "Terrestrial En-Route Navigation",
    ciaTriad: "Integrity",
    likelihood: 1.0,
    impact: 4.5,
    figure: "Figure 8",
    attackVector: "Synthesizing phase-shifted 30 Hz subcarrier signals to alter perceived radial bearing.",
    description: "Technically complex due to rotating directional radiation simulation. Acceptable risk level.",
    mitigations: [
      "Dual VOR receiver consistency cross-checks",
      "Periodic flight inspection validation"
    ],
    mitigatedLikelihood: 1.0,
    mitigatedImpact: 2.0,
    appliedMitigations: []
  },

  // --- SURVEILLANCE ---
  {
    id: "SUR-SSR-01",
    domain: "Surveillance",
    asset: "SSR",
    threatType: "Jamming",
    category: "Cooperative Radar",
    ciaTriad: "Availability",
    likelihood: 1.6,
    impact: 4.3,
    figure: "Figure 9",
    attackVector: "High-power pulsed RF jamming on 1030 MHz (interrogator) or 1090 MHz (transponder reply).",
    description: "Radar directional antenna rotation and high pulse power make jamming difficult without military hardware. Drops targets from ATC screens.",
    mitigations: [
      "Primary Surveillance Radar (PSR) uncooperative skin-paint fallback",
      "Overlapping coverage from adjacent radar sectors"
    ],
    mitigatedLikelihood: 1.2,
    mitigatedImpact: 2.0,
    appliedMitigations: []
  },
  {
    id: "SUR-SSR-02",
    domain: "Surveillance",
    asset: "SSR",
    threatType: "Spoofing / Ghost Targets",
    category: "Cooperative Radar",
    ciaTriad: "Integrity",
    likelihood: 1.4,
    impact: 5.0,
    figure: "Figure 9",
    attackVector: "Transmitting synchronized 1090 MHz replies to ground 1030 MHz interrogations with crafted Mode A/C/S codes.",
    description: "Creates false aircraft tracks on ATC radar screens, confusing controllers and triggering false conflict alerts.",
    mitigations: [
      "Data fusion between SSR and Primary Surveillance Radar (PSR) measurements",
      "Monopulse antenna angle-of-arrival consistency checking"
    ],
    mitigatedLikelihood: 1.0,
    mitigatedImpact: 2.5,
    appliedMitigations: []
  },
  {
    id: "SUR-SSR-03",
    domain: "Surveillance",
    asset: "SSR",
    threatType: "Over-Interrogation",
    category: "Cooperative Radar",
    ciaTriad: "Availability",
    likelihood: 1.0,
    impact: 4.3,
    figure: "Figure 9",
    attackVector: "Transmitting excessive interrogation pulses (>1200/sec) from multiple ground emitters, triggering transponder rate-limiting desensitization.",
    description: "Known historical incident (Central Europe, June 2014) caused transponder suppression and temporary loss of radar track.",
    mitigations: [
      "EASA/ICAO ground interrogator power and PRF coordination",
      "Automated sensor duty-cycle regulatory monitoring"
    ],
    mitigatedLikelihood: 1.0,
    mitigatedImpact: 1.5,
    appliedMitigations: []
  },
  {
    id: "SUR-MLAT-01",
    domain: "Surveillance",
    asset: "MLAT / WAM",
    threatType: "GPS De-synchronization Attack",
    category: "Independent Cooperative",
    ciaTriad: "Integrity",
    likelihood: 2.5,
    impact: 3.6,
    figure: "Figure 10",
    attackVector: "Targeting ground MLAT receiver GPS timing references using distributed multi-device spoofers.",
    description: "Distorts Time Difference of Arrival (TDoA) hyperbolic localization, degrading computed aircraft coordinate accuracy.",
    mitigations: [
      "Physical-layer verification: Doppler shift, carrier phase, and RF fingerprinting",
      "High-stability Rubidium / Cesium atomic clocks at ground sensor stations"
    ],
    mitigatedLikelihood: 1.5,
    mitigatedImpact: 2.0,
    appliedMitigations: []
  },
  {
    id: "SUR-ADSB-01",
    domain: "Surveillance",
    asset: "ADS-B",
    threatType: "Eavesdropping",
    category: "Broadcast Surveillance",
    ciaTriad: "Confidentiality",
    likelihood: 4.8,
    impact: 1.0,
    figure: "Figure 11",
    attackVector: "Passive demodulation of 1090 MHz Extended Squitter messages using ubiquitous $20 USB SDR dongles.",
    description: "Crowdsourced tracking networks receive open unencrypted squitters globally. Negligible flight safety risk.",
    mitigations: [
      "ICAO Privacy ICAO Address (PIA) rolling identifier scheme",
      "Clear demarcation between public tracking and certified ATM safety networks"
    ],
    mitigatedLikelihood: 2.5,
    mitigatedImpact: 1.0,
    appliedMitigations: []
  },
  {
    id: "SUR-ADSB-02",
    domain: "Surveillance",
    asset: "ADS-B",
    threatType: "Jamming",
    category: "Broadcast Surveillance",
    ciaTriad: "Availability",
    likelihood: 4.2,
    impact: 3.5,
    figure: "Figure 11",
    attackVector: "High-power noise broadcast on 1090 MHz drowning out weak omnidirectional transponder squitters at ground receivers.",
    description: "High likelihood due to SDR accessibility and sensitive ground antenna preamplifiers. High risk in ADS-B exclusive airspaces.",
    mitigations: [
      "TDoA ML fingerprinting to localize aircraft even during message corruption",
      "Maintaining secondary radar (SSR) and MLAT as active backup layers"
    ],
    mitigatedLikelihood: 2.0,
    mitigatedImpact: 2.0,
    appliedMitigations: []
  },
  {
    id: "SUR-ADSB-03",
    domain: "Surveillance",
    asset: "ADS-B",
    threatType: "Spoofing / Ghost Targets / Deletion",
    category: "Broadcast Surveillance",
    ciaTriad: "Integrity",
    likelihood: 2.9,
    impact: 4.8,
    figure: "Figure 11",
    attackVector: "Transmitting crafted Mode S 1090ES squitters with bogus 24-bit ICAO addresses, positions, or velocities; modifying flight paths.",
    description: "Lack of message authentication allows insertion of ghost aircraft or deletion of valid targets, creating severe collision alert hazards.",
    mitigations: [
      "Location verification via Multilateration (MLAT) TDoA cross-checks",
      "Machine learning TDoA fingerprinting using OpenSky network historical data",
      "Angle of Arrival (AoA) monopulse sector antennas",
      "Cryptographic broadcast authentication (ECC short signatures / X.509 certificates)"
    ],
    mitigatedLikelihood: 1.5,
    mitigatedImpact: 2.5,
    appliedMitigations: []
  },

  // --- NETWORKING / SWIM ---
  {
    id: "NET-SWIM-01",
    domain: "Networking",
    asset: "SWIM",
    threatType: "Man-in-the-Middle / Data Tampering",
    category: "Net-Centric IP Infrastructure",
    ciaTriad: "Integrity",
    likelihood: 3.5,
    impact: 3.0,
    figure: "Figure 13",
    attackVector: "Intercepting and altering net-centric aeronautical/weather/flight data exchanged over IP networks lacking end-to-end authentication.",
    description: "SWIM unifies ANSPs, airlines, airports, and military. Compromised IP nodes allow malicious message tampering.",
    mitigations: [
      "SWIM Common Public Key Infrastructure (Common PKI) with mutual TLS",
      "ICAO INNOVA/ACORNS private secure trust framework",
      "End-to-end digital signatures on critical ATM datasets (AIXM, FIXM, IWXXM)"
    ],
    mitigatedLikelihood: 1.8,
    mitigatedImpact: 2.0,
    appliedMitigations: []
  },
  {
    id: "NET-SWIM-02",
    domain: "Networking",
    asset: "SWIM",
    threatType: "Unauthorized Access & DoS",
    category: "Net-Centric IP Infrastructure",
    ciaTriad: "Availability",
    likelihood: 3.5,
    impact: 3.0,
    figure: "Figure 13",
    attackVector: "DDoS attacks on SWIM enterprise service bus or exploiting unpatched software to gain unauthorized administrative access.",
    description: "Service disruption forces ATM stakeholders back into isolated legacy coordination modes, causing widespread flight delays.",
    mitigations: [
      "Dedicated air-gapped private aviation IP network",
      "Zero Trust Network Architecture (ZTNA) with granular role-based access",
      "DDoS mitigation scrubbing centers and resilient multi-region service brokers"
    ],
    mitigatedLikelihood: 1.5,
    mitigatedImpact: 2.0,
    appliedMitigations: []
  }
];

// Literature survey comparison from Table 1
const LITERATURE_SURVEY_TABLE = [
  {
    paper: "Sueki & Kim [16] (2016)",
    communication: "No",
    navigation: "No",
    surveillance: "ADS-B only",
    swim: "Yes",
    riskMethodology: "No",
    notes: "Identified NextGen vulnerabilities in ADS-B and SWIM; lacked quantitative risk assessment."
  },
  {
    paper: "Shaikh et al. [21] (2019)",
    communication: "CPDLC and ACARS only",
    navigation: "GPS navigation only",
    surveillance: "ADS-B only",
    swim: "No",
    riskMethodology: "No",
    notes: "Focused on E-enabled aircraft systems; excluded VHF, GBAS, SBAS, SSR, SWIM."
  },
  {
    paper: "Osechas et al. [10] (2017)",
    communication: "VDL2 only",
    navigation: "GBAS only",
    surveillance: "SSR only",
    swim: "No",
    riskMethodology: "No",
    notes: "Analyzed RF interference (jamming/spoofing) in selected systems; no risk formula."
  },
  {
    paper: "Strohmeier et al. [20] (2020)",
    communication: "VHF, CPDLC, and ACARS",
    navigation: "No",
    surveillance: "SSR, MLAT, ADS-B",
    swim: "No",
    riskMethodology: "No",
    notes: "Detailed air-ground link security, but omitted radio navigation aids and SWIM."
  },
  {
    paper: "Strohmeier et al. [19] (2017)",
    communication: "Yes",
    navigation: "Yes",
    surveillance: "Yes",
    swim: "No",
    riskMethodology: "Partial (Expert Survey)",
    notes: "Surveys aviation experts on perceived trustworthiness, but no continuous analytical algorithm."
  },
  {
    paper: "Elmarady & Rahouma [Proposed Study] (2021)",
    communication: "Yes (VHF, CPDLC, ACARS)",
    navigation: "Yes (GNSS, ILS, VOR, DME)",
    surveillance: "Yes (PSR, SSR, MLAT, ADS-B)",
    swim: "Yes (Net-Centric IP, PKI, INNOVA)",
    riskMethodology: "Yes (Quantitative r = L x I, Qualitative R, Table 5 5-point scale)",
    notes: "Complete CNS/ATM + SWIM coverage with continuous mathematical risk assessment and mitigation framework."
  }
];

// Technical protocol comparison from Tables 6, 8, 10
const PROTOCOL_SPECIFICATIONS = {
  communication: [
    {
      protocol: "VHF Voice",
      usage: "Air-ground voice communication for ATC instructions & flight safety",
      signal: "Analog AM",
      type: "Broadcast",
      frequencyBand: "117.975 - 137.000 MHz",
      channelSpacing: "25 kHz or 8.33 kHz",
      linkLayer: "VHF AM",
      standards: "ICAO Annex 10 vol. 3, Doc 9718"
    },
    {
      protocol: "CPDLC",
      usage: "Air-ground digital data link for ATC clearances & reports",
      signal: "Digital",
      type: "Selective",
      frequencyBand: "VDL2: 136.975 MHz (common signaling channel)",
      channelSpacing: "25 kHz",
      linkLayer: "HFDL, VDL Mode 2, SATCOM",
      standards: "ICAO Annex 10 vol. 3, Doc 10037"
    },
    {
      protocol: "ACARS",
      usage: "AOC data link: weight/balance, flight plans, engine health, weather",
      signal: "Digital (ASCII)",
      type: "Broadcast / Point-to-Point",
      frequencyBand: "131.550 MHz (primary worldwide) / 136.975 MHz",
      channelSpacing: "25 kHz",
      linkLayer: "Plain old VHF, VDL, HFDL, SATCOM",
      standards: "ARINC 618, ARINC 620-8, ARINC 823"
    }
  ],
  navigation: [
    {
      system: "GNSS (GPS / GLONASS / Galileo)",
      usage: "Global 3D positioning and precise UTC time",
      type: "Satellite Constellation",
      frequencyBand: "L1: 1575.42 MHz, L2: 1227.60 MHz, L5: 1176.45 MHz",
      standardReference: "ICAO Annex 10 vol. 1, Doc 9849",
      coverage: "Global seamless",
      vulnerability: "Extremely weak signal (-160 dBW), unencrypted civil code"
    },
    {
      system: "ILS (Instrument Landing System)",
      usage: "Precision horizontal (Localizer) & vertical (Glide Slope) runway guidance",
      type: "Ground-based Terrestrial",
      frequencyBand: "Localizer: 108-111.975 MHz; Glide Slope: 328.6-335.4 MHz",
      standardReference: "ICAO Annex 10 vol. 1, Doc 8071",
      coverage: "Runway approach sector (up to 25 NM)",
      vulnerability: "Single-tone injection, overshadow attack"
    },
    {
      system: "VOR (VHF Omnidirectional Range)",
      usage: "360-degree magnetic bearing radial determination",
      type: "Ground-based Terrestrial",
      frequencyBand: "108.000 - 117.975 MHz",
      standardReference: "ICAO Annex 10 vol. 1, Doc 8071",
      coverage: "Line-of-sight radial (up to 150-200 NM)",
      vulnerability: "Phase spoofing, frequency jamming"
    },
    {
      system: "DME (Distance Measuring Equipment)",
      usage: "Slant range measurement via paired pulse timing delay",
      type: "Ground Transponder",
      frequencyBand: "962 - 1213 MHz (UHF)",
      standardReference: "ICAO Annex 10 vol. 1, Doc 8071",
      coverage: "En-route & terminal navigation",
      vulnerability: "Pulse reply exhaustion, RF jamming"
    }
  ],
  surveillance: [
    {
      technique: "PSR (Primary Surveillance Radar)",
      concept: "Non-cooperative echo reflections from aircraft skin",
      info: "Slant range and azimuth",
      signal: "Analogue pulses",
      freqBand: "1-2 GHz (L-band), 2-4 GHz (S-band)",
      updateRate: "Low (mechanical rotation 4-12 RPM)",
      standards: "ICAO Doc 9924"
    },
    {
      technique: "SSR (Secondary Surveillance Radar)",
      concept: "Cooperative ground interrogator + on-board Mode A/C/S transponder",
      info: "Range, azimuth, Mode A (ID), Mode C (altitude), Mode S (intent)",
      signal: "Digital pulse reply",
      freqBand: "Uplink: 1030 MHz, Downlink: 1090 MHz",
      updateRate: "Low (mechanical rotation)",
      standards: "ICAO Annex 10 vol. 4, Doc 9684"
    },
    {
      technique: "MLAT / WAM (Multilateration)",
      concept: "Independent cooperative TDoA calculation from multiple ground receivers",
      info: "3D position, ID, velocity",
      signal: "Digital transponder reply",
      freqBand: "1030 MHz interrogation / 1090 MHz reply",
      updateRate: "High (stationary sensor grid)",
      standards: "ICAO Annex 10 vol. 4, Doc 9924"
    },
    {
      technique: "ADS-B (1090ES & Space-Based)",
      concept: "Dependent cooperative omnidirectional broadcast from GPS/transponder",
      info: "High-precision GPS position, velocity, callsign, altitude",
      signal: "Digital Extended Squitter",
      freqBand: "1090 MHz (Extended Squitter) / 978 MHz (UAT)",
      updateRate: "High (position twice/sec, ID once/5 sec)",
      standards: "ICAO Annex 10 vol. 4, Doc 9924"
    }
  ]
};
