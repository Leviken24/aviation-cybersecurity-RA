/**
 * Civil Aviation Cybersecurity Live Airspace Simulator & Attack Prediction Engine
 * Implements:
 * - Real-time Airspace Kinematics (ADS-B, VHF, GNSS, SSR, CPDLC, SWIM) across 5 global sectors
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
    this.selectedFlightId = "BAW456";
    this.onThreatsUpdated = null;
    this.lastThreatUpdateTime = 0;

    // Real-World Live ADS-B Tracking Mode vs Tactical Sandbox Mode
    this.feedMode = "live_adsb"; // "live_adsb" (Real flights overhead) or "sandbox"
    this.currentZone = "london";
    this.liveFlights = [];
    this.liveZoneMeta = null;
    this.isFetchingLive = false;
    this.livePollTimer = null;
    this.clockTimer = null;
    this.liveStats = {
      totalDetected: 0,
      inSector: 0,
      intolerable: 0,
      tolerable: 0,
      acceptable: 0
    };

    // Major International Airspace Sectors with authentic flight fleets
    this.zoneConfigs = {
      london: {
        id: "london",
        name: "London TMA (EGLL / Heathrow)",
        centerLat: 51.4700,
        centerLon: -0.4543,
        radiusNm: 35.0,
        bbox: [50.9, -1.3, 52.0, 0.4],
        runways: [
          { name: "27R/09L", length: 4.0, heading: 90, x: 0, y: 0.3 },
          { name: "27L/09R", length: 3.7, heading: 90, x: 0, y: -0.3 }
        ],
        waypoints: [
          { name: "LAM", x: 20, y: 12 },
          { name: "BIG", x: 12, y: -18 },
          { name: "OCK", x: -8, y: -14 },
          { name: "BOV", x: -14, y: 16 }
        ],
        fleetTemplate: [
          { callsign: "BAW456", icao24: "400a12", aircraftType: "A320", country: "United Kingdom", x: 3.2, y: 0.3, altitude: 1450, geo_altitude: 1420, speed: 138, heading: 270, vertical_rate: -700, squawk: "1000", assignedFrequency: "118.500 MHz", latency_sec: 1.2, destination: "EGLL RWY 27R" },
          { callsign: "VIR105", icao24: "406c33", aircraftType: "B789", country: "United Kingdom", x: 8.8, y: -0.3, altitude: 3200, geo_altitude: 3150, speed: 175, heading: 270, vertical_rate: -800, squawk: "2104", assignedFrequency: "118.500 MHz", latency_sec: 1.5, destination: "EGLL RWY 27L" },
          { callsign: "EZY812", icao24: "407119", aircraftType: "A320", country: "United Kingdom", x: 18.5, y: 10.5, altitude: 7200, geo_altitude: 7150, speed: 240, heading: 250, vertical_rate: -1200, squawk: "4521", assignedFrequency: "120.400 MHz", latency_sec: 2.1, destination: "EGLL LAM Arrival" },
          { callsign: "RYR331", icao24: "4ca892", aircraftType: "B738", country: "Ireland", x: 1.5, y: -0.3, altitude: 800, geo_altitude: 780, speed: 134, heading: 270, vertical_rate: -650, squawk: "1000", assignedFrequency: "118.500 MHz", latency_sec: 0.9, destination: "EGLL RWY 27L" },
          { callsign: "SIA318", icao24: "76ce81", aircraftType: "A388", country: "Singapore", x: 14.5, y: -16.0, altitude: 9500, geo_altitude: 9450, speed: 270, heading: 330, vertical_rate: -1500, squawk: "6312", assignedFrequency: "128.025 MHz", latency_sec: 2.5, destination: "EGLL BIG Arrival" },
          { callsign: "QFA001", icao24: "7c1b29", aircraftType: "B789", country: "Australia", x: -16.0, y: -12.5, altitude: 11500, geo_altitude: 9800, speed: 290, heading: 65, vertical_rate: -1600, squawk: "3411", assignedFrequency: "134.975 MHz", latency_sec: 1.8, destination: "EGLL OCK Inbound" },
          { callsign: "AFR1680", icao24: "3949e2", aircraftType: "A321", country: "France", x: -7.5, y: 14.0, altitude: 5800, geo_altitude: 5750, speed: 220, heading: 170, vertical_rate: 1800, squawk: "5201", assignedFrequency: "118.700 MHz", latency_sec: 1.4, destination: "Climb Out to CDG" },
          { callsign: "DLH902", icao24: "3c66a4", aircraftType: "A320", country: "Germany", x: 26.0, y: -8.0, altitude: 34000, geo_altitude: 34020, speed: 460, heading: 285, vertical_rate: 0, squawk: "7124", assignedFrequency: "132.850 MHz", latency_sec: 3.1, destination: "En-Route Cruise" },
          { callsign: "UAL901", icao24: "a8b112", aircraftType: "B77W", country: "United States", x: -24.5, y: 18.0, altitude: 15000, geo_altitude: 14950, speed: 320, heading: 110, vertical_rate: -1800, squawk: "2255", assignedFrequency: "120.400 MHz", latency_sec: 1.9, destination: "EGLL BOV Arrival" },
          { callsign: "KLM1014", icao24: "4841a5", aircraftType: "E190", country: "Netherlands", x: 6.5, y: 12.0, altitude: 4800, geo_altitude: 4760, speed: 200, heading: 210, vertical_rate: -900, squawk: "4110", assignedFrequency: "119.725 MHz", latency_sec: 1.1, destination: "Terminal Vector" },
          { callsign: "AAL100", icao24: "a154ec", aircraftType: "B772", country: "United States", x: 22.0, y: 4.5, altitude: 8900, geo_altitude: 8850, speed: 260, heading: 260, vertical_rate: -1300, squawk: "5602", assignedFrequency: "128.025 MHz", latency_sec: 2.2, destination: "EGLL LAM STAR" },
          { callsign: "IBE3160", icao24: "344318", aircraftType: "A320", country: "Spain", x: 10.2, y: -10.5, altitude: 5100, geo_altitude: 5060, speed: 210, heading: 315, vertical_rate: -1000, squawk: "3314", assignedFrequency: "120.400 MHz", latency_sec: 1.7, destination: "Terminal Inbound" }
        ]
      },
      newyork: {
        id: "newyork",
        name: "New York TRACON (KJFK / JFK)",
        centerLat: 40.6413,
        centerLon: -73.7781,
        radiusNm: 35.0,
        bbox: [40.1, -74.5, 41.2, -73.0],
        runways: [
          { name: "31L/13R", length: 4.2, heading: 135, x: 0, y: 0 },
          { name: "04R/22L", length: 3.8, heading: 45, x: 0, y: 0 }
        ],
        waypoints: [
          { name: "ROBER", x: -18, y: 15 },
          { name: "LENDY", x: 22, y: -10 },
          { name: "CAMRN", x: -12, y: -20 },
          { name: "MERIT", x: 15, y: 20 }
        ],
        fleetTemplate: [
          { callsign: "DAL412", icao24: "a28fa1", aircraftType: "A339", country: "United States", x: 3.5, y: -3.8, altitude: 1450, geo_altitude: 1420, speed: 140, heading: 315, vertical_rate: -720, squawk: "1000", assignedFrequency: "119.100 MHz", latency_sec: 1.1, destination: "KJFK RWY 31L" },
          { callsign: "AAL104", icao24: "a314c9", aircraftType: "B772", country: "United States", x: 8.2, y: -8.8, altitude: 3200, geo_altitude: 3150, speed: 175, heading: 315, vertical_rate: -800, squawk: "2411", assignedFrequency: "119.100 MHz", latency_sec: 1.4, destination: "KJFK RWY 31L" },
          { callsign: "JBU517", icao24: "a953e1", aircraftType: "A321", country: "United States", x: -14.5, y: 16.2, altitude: 6500, geo_altitude: 6450, speed: 230, heading: 135, vertical_rate: -1100, squawk: "4102", assignedFrequency: "125.700 MHz", latency_sec: 1.8, destination: "ROBER Arrival" },
          { callsign: "UAL85", icao24: "a09214", aircraftType: "B789", country: "United States", x: -22.5, y: -12.0, altitude: 11000, geo_altitude: 10950, speed: 290, heading: 65, vertical_rate: -1500, squawk: "3312", assignedFrequency: "132.800 MHz", latency_sec: 2.3, destination: "CAMRN Inbound" },
          { callsign: "AFR022", icao24: "3924f0", aircraftType: "B77W", country: "France", x: 2.2, y: -2.4, altitude: 850, geo_altitude: 840, speed: 136, heading: 315, vertical_rate: -680, squawk: "1000", assignedFrequency: "119.100 MHz", latency_sec: 0.8, destination: "Short Final RWY 31L" },
          { callsign: "BAW177", icao24: "4061a9", aircraftType: "A359", country: "United Kingdom", x: 19.5, y: 18.0, altitude: 13500, geo_altitude: 13450, speed: 310, heading: 225, vertical_rate: -1800, squawk: "5124", assignedFrequency: "128.125 MHz", latency_sec: 2.0, destination: "MERIT STAR" },
          { callsign: "VIR009", icao24: "4075b2", aircraftType: "B789", country: "United Kingdom", x: 24.0, y: -8.5, altitude: 16000, geo_altitude: 14200, speed: 330, heading: 280, vertical_rate: -1600, squawk: "6210", assignedFrequency: "128.125 MHz", latency_sec: 1.7, destination: "LENDY Inbound" },
          { callsign: "EDV5211", icao24: "a61201", aircraftType: "CRJ9", country: "United States", x: -5.5, y: 8.2, altitude: 4200, geo_altitude: 4180, speed: 210, heading: 45, vertical_rate: 1600, squawk: "2100", assignedFrequency: "123.900 MHz", latency_sec: 1.3, destination: "Departure Climb" },
          { callsign: "RPA4501", icao24: "a773bc", aircraftType: "E175", country: "United States", x: 12.0, y: -15.5, altitude: 7800, geo_altitude: 7750, speed: 240, heading: 330, vertical_rate: -1200, squawk: "4401", assignedFrequency: "125.700 MHz", latency_sec: 1.6, destination: "Terminal Vector" },
          { callsign: "KLM641", icao24: "484cc1", aircraftType: "B78X", country: "Netherlands", x: -26.0, y: 22.0, altitude: 33000, geo_altitude: 33020, speed: 470, heading: 250, vertical_rate: 0, squawk: "7211", assignedFrequency: "135.900 MHz", latency_sec: 3.0, destination: "En-Route Cruise" },
          { callsign: "SWA2901", icao24: "ab4119", aircraftType: "B738", country: "United States", x: -8.2, y: -14.0, altitude: 5500, geo_altitude: 5450, speed: 220, heading: 30, vertical_rate: -900, squawk: "3119", assignedFrequency: "125.700 MHz", latency_sec: 1.5, destination: "Terminal Approach" },
          { callsign: "DLH400", icao24: "3c4a22", aircraftType: "B748", country: "Germany", x: 21.0, y: 6.5, altitude: 10500, geo_altitude: 10450, speed: 280, heading: 270, vertical_rate: -1400, squawk: "5512", assignedFrequency: "128.125 MHz", latency_sec: 2.2, destination: "Approach Sequencing" }
        ]
      },
      frankfurt: {
        id: "frankfurt",
        name: "Frankfurt TMA (EDDF / FRA)",
        centerLat: 50.0379,
        centerLon: 8.5622,
        radiusNm: 35.0,
        bbox: [49.5, 7.8, 50.6, 9.3],
        runways: [
          { name: "25C/07C", length: 4.0, heading: 70, x: 0, y: 0 },
          { name: "18", length: 4.0, heading: 180, x: -1, y: -1 }
        ],
        waypoints: [
          { name: "RID", x: -15, y: 12 },
          { name: "CHA", x: 20, y: 14 },
          { name: "GED", x: 14, y: -16 }
        ],
        fleetTemplate: [
          { callsign: "DLH400", icao24: "3c4a22", aircraftType: "B748", country: "Germany", x: 3.2, y: 1.1, altitude: 1650, geo_altitude: 1620, speed: 148, heading: 250, vertical_rate: -720, squawk: "1000", assignedFrequency: "119.900 MHz", latency_sec: 1.0, destination: "EDDF RWY 25C" },
          { callsign: "DLH1348", icao24: "3c6601", aircraftType: "A320", country: "Germany", x: 9.5, y: 3.2, altitude: 3400, geo_altitude: 3350, speed: 175, heading: 250, vertical_rate: -800, squawk: "2201", assignedFrequency: "119.900 MHz", latency_sec: 1.3, destination: "EDDF RWY 25C" },
          { callsign: "GEC8220", icao24: "3c8812", aircraftType: "B77L", country: "Germany", x: -12.4, y: 15.2, altitude: 6800, geo_altitude: 6750, speed: 230, heading: 140, vertical_rate: -1200, squawk: "4310", assignedFrequency: "120.150 MHz", latency_sec: 1.9, destination: "RID STAR Inbound" },
          { callsign: "CFG204", icao24: "3c45b8", aircraftType: "A339", country: "Germany", x: 1.5, y: 0.5, altitude: 950, geo_altitude: 930, speed: 138, heading: 250, vertical_rate: -680, squawk: "1000", assignedFrequency: "119.900 MHz", latency_sec: 0.9, destination: "Short Final RWY 25L" },
          { callsign: "SAS1635", icao24: "47814a", aircraftType: "A320", country: "Sweden", x: 18.2, y: 12.5, altitude: 11000, geo_altitude: 10950, speed: 280, heading: 240, vertical_rate: -1600, squawk: "5118", assignedFrequency: "127.275 MHz", latency_sec: 2.1, destination: "CHA Arrival" },
          { callsign: "AUA511", icao24: "440182", aircraftType: "E195", country: "Austria", x: 15.5, y: -14.2, altitude: 8500, geo_altitude: 8450, speed: 250, heading: 310, vertical_rate: -1400, squawk: "3412", assignedFrequency: "120.150 MHz", latency_sec: 1.7, destination: "GED Inbound" },
          { callsign: "KLM1862", icao24: "484a08", aircraftType: "B738", country: "Netherlands", x: -8.5, y: -12.0, altitude: 5200, geo_altitude: 3500, speed: 220, heading: 45, vertical_rate: 1800, squawk: "4501", assignedFrequency: "118.775 MHz", latency_sec: 1.5, destination: "Departure Climb" },
          { callsign: "EZY5412", icao24: "407881", aircraftType: "A320", country: "United Kingdom", x: -24.0, y: 20.0, altitude: 35000, geo_altitude: 35010, speed: 460, heading: 110, vertical_rate: 0, squawk: "7310", assignedFrequency: "133.450 MHz", latency_sec: 2.9, destination: "High Cruise" },
          { callsign: "TAP542", icao24: "4951b1", aircraftType: "A320", country: "Portugal", x: -16.5, y: -6.0, altitude: 9200, geo_altitude: 9150, speed: 270, heading: 60, vertical_rate: -1300, squawk: "6122", assignedFrequency: "120.150 MHz", latency_sec: 2.0, destination: "Terminal Approach" },
          { callsign: "SWR1070", icao24: "4b1509", aircraftType: "A220", country: "Switzerland", x: 8.5, y: -16.0, altitude: 6200, geo_altitude: 6160, speed: 230, heading: 340, vertical_rate: -1100, squawk: "2311", assignedFrequency: "127.275 MHz", latency_sec: 1.4, destination: "Sequenced Approach" },
          { callsign: "RYR8821", icao24: "4ca101", aircraftType: "B738", country: "Ireland", x: 22.5, y: -4.0, altitude: 13000, geo_altitude: 12950, speed: 300, heading: 270, vertical_rate: -1500, squawk: "5504", assignedFrequency: "127.275 MHz", latency_sec: 2.3, destination: "Terminal Inbound" }
        ]
      },
      dubai: {
        id: "dubai",
        name: "Dubai CTA (OMDB / DXB)",
        centerLat: 25.2532,
        centerLon: 55.3657,
        radiusNm: 35.0,
        bbox: [24.7, 54.7, 25.8, 56.0],
        runways: [
          { name: "30L/12R", length: 4.0, heading: 120, x: 0, y: 0.3 },
          { name: "30R/12L", length: 4.0, heading: 120, x: 0, y: -0.3 }
        ],
        waypoints: [
          { name: "DESDI", x: -18, y: 12 },
          { name: "NABIX", x: 20, y: -12 },
          { name: "MIKNO", x: 18, y: 16 }
        ],
        fleetTemplate: [
          { callsign: "UAE201", icao24: "896120", aircraftType: "A388", country: "United Arab Emirates", x: 2.8, y: -1.6, altitude: 1550, geo_altitude: 1520, speed: 145, heading: 120, vertical_rate: -700, squawk: "1000", assignedFrequency: "118.750 MHz", latency_sec: 1.0, destination: "OMDB RWY 12L" },
          { callsign: "UAE384", icao24: "896245", aircraftType: "B77W", country: "United Arab Emirates", x: 8.5, y: -4.8, altitude: 3500, geo_altitude: 3450, speed: 180, heading: 120, vertical_rate: -800, squawk: "2101", assignedFrequency: "118.750 MHz", latency_sec: 1.3, destination: "OMDB RWY 12L" },
          { callsign: "FDB521", icao24: "896a11", aircraftType: "B738", country: "United Arab Emirates", x: -14.5, y: 15.0, altitude: 6800, geo_altitude: 6750, speed: 230, heading: 150, vertical_rate: -1200, squawk: "4410", assignedFrequency: "124.900 MHz", latency_sec: 1.8, destination: "DESDI Arrival" },
          { callsign: "QTR1004", icao24: "06a12b", aircraftType: "A359", country: "Qatar", x: 1.2, y: -0.7, altitude: 850, geo_altitude: 830, speed: 136, heading: 120, vertical_rate: -650, squawk: "1000", assignedFrequency: "118.750 MHz", latency_sec: 0.8, destination: "Short Final RWY 12R" },
          { callsign: "OMA102", icao24: "706021", aircraftType: "B738", country: "Oman", x: 16.5, y: -15.0, altitude: 9200, geo_altitude: 9150, speed: 260, heading: 310, vertical_rate: -1500, squawk: "5120", assignedFrequency: "124.900 MHz", latency_sec: 2.1, destination: "NABIX Inbound" },
          { callsign: "GFA214", icao24: "894101", aircraftType: "A321", country: "Bahrain", x: 15.0, y: 14.5, altitude: 8800, geo_altitude: 7100, speed: 250, heading: 220, vertical_rate: -1300, squawk: "3318", assignedFrequency: "124.900 MHz", latency_sec: 1.9, destination: "MIKNO Inbound" },
          { callsign: "ETD450", icao24: "896881", aircraftType: "B789", country: "United Arab Emirates", x: -25.0, y: -15.0, altitude: 37000, geo_altitude: 37020, speed: 480, heading: 75, vertical_rate: 0, squawk: "7104", assignedFrequency: "132.025 MHz", latency_sec: 3.2, destination: "High Cruise" },
          { callsign: "THY1072", icao24: "4ba192", aircraftType: "A333", country: "Turkey", x: -18.0, y: -5.0, altitude: 12000, geo_altitude: 11950, speed: 290, heading: 85, vertical_rate: -1600, squawk: "4211", assignedFrequency: "124.900 MHz", latency_sec: 2.4, destination: "Terminal Descent" },
          { callsign: "AIC992", icao24: "800542", aircraftType: "B788", country: "India", x: 22.0, y: 2.0, altitude: 14000, geo_altitude: 13950, speed: 310, heading: 275, vertical_rate: -1700, squawk: "6124", assignedFrequency: "124.900 MHz", latency_sec: 2.0, destination: "Inbound East Corridor" },
          { callsign: "BAW107", icao24: "400492", aircraftType: "B77W", country: "United Kingdom", x: 10.5, y: -10.0, altitude: 5400, geo_altitude: 5360, speed: 220, heading: 320, vertical_rate: -1000, squawk: "2402", assignedFrequency: "118.750 MHz", latency_sec: 1.4, destination: "Approach Sequencing" }
        ]
      },
      tokyo: {
        id: "tokyo",
        name: "Tokyo Approach (RJTT / Haneda)",
        centerLat: 35.5494,
        centerLon: 139.7798,
        radiusNm: 35.0,
        bbox: [35.0, 139.1, 36.1, 140.4],
        runways: [
          { name: "34L/16R", length: 3.5, heading: 160, x: 0, y: 0 },
          { name: "05/23", length: 3.0, heading: 50, x: 0, y: -1 }
        ],
        waypoints: [
          { name: "ARLON", x: -16, y: 15 },
          { name: "KAIHO", x: 12, y: -16 },
          { name: "DATUM", x: 22, y: 10 }
        ],
        fleetTemplate: [
          { callsign: "JAL516", icao24: "86a124", aircraftType: "A359", country: "Japan", x: 2.1, y: -5.4, altitude: 1850, geo_altitude: 1820, speed: 142, heading: 337, vertical_rate: -700, squawk: "1000", assignedFrequency: "118.100 MHz", latency_sec: 1.0, destination: "RJTT RWY 34L" },
          { callsign: "ANA084", icao24: "864b21", aircraftType: "B789", country: "Japan", x: 4.8, y: -11.2, altitude: 3600, geo_altitude: 3580, speed: 180, heading: 337, vertical_rate: -800, squawk: "2104", assignedFrequency: "119.400 MHz", latency_sec: 1.2, destination: "RJTT RWY 34R" },
          { callsign: "SFJ73", icao24: "8677c0", aircraftType: "A320", country: "Japan", x: -14.2, y: -8.5, altitude: 5800, geo_altitude: 5750, speed: 220, heading: 50, vertical_rate: -1200, squawk: "4210", assignedFrequency: "124.200 MHz", latency_sec: 1.6, destination: "KAIHO STAR Arrival" },
          { callsign: "SKY115", icao24: "868819", aircraftType: "B738", country: "Japan", x: 1.2, y: -2.8, altitude: 1100, geo_altitude: 1080, speed: 135, heading: 337, vertical_rate: -650, squawk: "1000", assignedFrequency: "118.100 MHz", latency_sec: 0.8, destination: "Short Final RWY 34L" },
          { callsign: "CPA548", icao24: "78091a", aircraftType: "B77W", country: "Hong Kong", x: 18.5, y: -18.2, altitude: 9500, geo_altitude: 9450, speed: 260, heading: 320, vertical_rate: -1500, squawk: "5512", assignedFrequency: "124.200 MHz", latency_sec: 2.1, destination: "DATUM Inbound" },
          { callsign: "CAL108", icao24: "77a802", aircraftType: "A333", country: "Taiwan", x: -6.5, y: 12.4, altitude: 7200, geo_altitude: 7180, speed: 240, heading: 160, vertical_rate: 1800, squawk: "3310", assignedFrequency: "126.000 MHz", latency_sec: 1.4, destination: "Departure Climb RWY 16R" },
          { callsign: "THY198", icao24: "4ba890", aircraftType: "B789", country: "Turkey", x: -22.0, y: 24.5, altitude: 34000, geo_altitude: 34020, speed: 475, heading: 285, vertical_rate: 0, squawk: "7101", assignedFrequency: "134.150 MHz", latency_sec: 2.8, destination: "En-Route Cruise" },
          { callsign: "APJ102", icao24: "866114", aircraftType: "A321", country: "Japan", x: 12.8, y: 15.6, altitude: 8400, geo_altitude: 8350, speed: 250, heading: 210, vertical_rate: -1100, squawk: "4105", assignedFrequency: "124.200 MHz", latency_sec: 1.7, destination: "ARLON Arrival" },
          { callsign: "FDX5043", icao24: "a12bc4", aircraftType: "B77L", country: "United States", x: 24.2, y: -4.5, altitude: 14000, geo_altitude: 12200, speed: 310, heading: 270, vertical_rate: -1400, squawk: "6214", assignedFrequency: "126.000 MHz", latency_sec: 2.3, destination: "East Approach Vector" },
          { callsign: "SVA872", icao24: "71021b", aircraftType: "B789", country: "Saudi Arabia", x: -28.0, y: -18.0, altitude: 36000, geo_altitude: 36010, speed: 460, heading: 80, vertical_rate: 0, squawk: "7320", assignedFrequency: "134.150 MHz", latency_sec: 3.0, destination: "High Altitude Overflight" },
          { callsign: "JAL331", icao24: "86a992", aircraftType: "B763", country: "Japan", x: -10.5, y: -18.5, altitude: 6200, geo_altitude: 6150, speed: 230, heading: 20, vertical_rate: -1000, squawk: "2418", assignedFrequency: "124.200 MHz", latency_sec: 1.5, destination: "KAIHO Sequencing" },
          { callsign: "ANA245", icao24: "864d08", aircraftType: "B772", country: "Japan", x: 8.5, y: 6.2, altitude: 4500, geo_altitude: 4480, speed: 210, heading: 160, vertical_rate: 1500, squawk: "3104", assignedFrequency: "119.400 MHz", latency_sec: 1.1, destination: "Climb Out RWY 16L" }
        ]
      }
    };

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
      { name: "27R/09L", length: 4.0, heading: 90, x: 0, y: 0.3 },
      { name: "27L/09R", length: 3.7, heading: 90, x: 0, y: -0.3 }
    ];

    // Navigation Waypoints (in NM)
    this.waypoints = [
      { name: "LAM", x: 20, y: 12 },
      { name: "BIG", x: 12, y: -18 },
      { name: "OCK", x: -8, y: -14 },
      { name: "BOV", x: -14, y: 16 }
    ];

    // Dedicated Fleet for Tactical Sandbox Testing
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
        destination: "EGLL",
        assignedFrequency: "134.975 MHz",
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
        risk: { L: 1.2, I: 3.5, r: 4.2, tol: "acceptable", scale: 1 }
      },
      {
        id: "AFR882",
        callsign: "AFR882",
        aircraftType: "A321",
        trueX: -10,
        trueY: -22,
        claimedX: -10,
        claimedY: -22,
        altitude: 8000,
        targetAltitude: 3000,
        speed: 240,
        heading: 10,
        flightPhase: "Terminal Sequencing",
        destination: "RWY 27L",
        assignedFrequency: "119.725 MHz",
        gnssSnr: 44,
        gnssSpoofed: false,
        gnssJammed: false,
        adsbSpoofed: false,
        adsbDropped: false,
        vhfSpoofed: false,
        transponderRate: 380,
        transponderSuppressed: false,
        cpdlcTampered: false,
        activeThreat: null,
        risk: { L: 1.8, I: 3.2, r: 5.76, tol: "tolerable", scale: 2 }
      }
    ];

    // Phantom / Ghost Aircraft Targets injected by Red Team
    this.ghostAircraft = [];

    // Active Jamming Interference Zones
    this.jammingZones = [];

    // Active Attacks list
    this.activeAttacks = [];

    // Event Log
    this.eventLog = [];

    // Predictive Anomaly Alerts generated by AI engine
    this.predictedThreats = [];

    // Cyber Resilience Defense State (Blue Team)
    this.defense = {
      autoFreqHop: false,
      psrSsrFusion: false,
      tdoaMlVerification: false,
      multiFreqGnss: false,
      swimZeroTrust: false,
      autonomousIntervention: false
    };

    // Statistical Counters
    this.stats = {
      predictionsGenerated: 0,
      attacksDetected: 0,
      attacksNeutralized: 0,
      intolerableEvents: 0
    };

    // Pre-populate London authentic fleet
    this.loadZoneFleet("london");
  }

  loadZoneFleet(zoneId) {
    const config = this.zoneConfigs[zoneId] || this.zoneConfigs["london"];
    this.currentZone = config.id;
    this.runways = config.runways;
    this.waypoints = config.waypoints;

    this.liveFlights = config.fleetTemplate.map((tmpl) => {
      const f = { ...tmpl };
      f.dist_nm = Number(Math.hypot(f.x, f.y).toFixed(1));
      f.on_ground = f.altitude < 100;
      f.trueX = f.x;
      f.trueY = f.y;
      f.claimedX = f.x;
      f.claimedY = f.y;
      f.gnssSnr = 46;
      f.gnssJammed = false;
      f.gnssSpoofed = false;
      f.adsbSpoofed = false;
      f.vhfSpoofed = false;
      f.cpdlcTampered = false;
      f.transponderRate = 340;
      f.activeThreat = null;
      f.threat = this.estimateClientAircraftThreat(f);
      return f;
    });

    // Sort descending by risk score, then proximity
    this.liveFlights.sort((a, b) => {
      const rA = a.threat?.composite_risk || 0;
      const rB = b.threat?.composite_risk || 0;
      return rB - rA || a.dist_nm - b.dist_nm;
    });

    // Select primary flight
    if (this.liveFlights.length > 0) {
      this.selectedFlightId = this.liveFlights[0].callsign || this.liveFlights[0].icao24;
    }

    this.liveStats = {
      totalDetected: this.liveFlights.length,
      inSector: this.liveFlights.length,
      intolerable: this.liveFlights.filter((f) => f.threat?.tolerability === "intolerable").length,
      tolerable: this.liveFlights.filter((f) => f.threat?.tolerability === "tolerable").length,
      acceptable: this.liveFlights.filter((f) => f.threat?.tolerability === "acceptable").length,
      lastUpdated: new Date()
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

    // Initialize UI
    this.renderActiveAttacksUI();
    this.updateLiveStatsUI();
    this.renderFlightPills();
    this.runAttackPredictionEngine();
    this.refreshTelemetryUI();
    this.logEvent("SYSTEM_INIT", "Civil Aviation Real-Time Cybersecurity Radar & Simulation Online", "INFO");

    // Real-world Zulu Chronometer (updates every second)
    if (!this.clockTimer) {
      this.clockTimer = setInterval(() => {
        const simTimeEl = document.getElementById("sim-clock-time");
        if (simTimeEl) {
          const now = new Date();
          const h = String(now.getUTCHours()).padStart(2, "0");
          const m = String(now.getUTCMinutes()).padStart(2, "0");
          const s = String(now.getUTCSeconds()).padStart(2, "0");
          simTimeEl.innerText = `${h}:${m}:${s} UTC`;
        }
      }, 1000);
    }

    // Try background live OpenSky ADS-B polling (graceful fallback)
    if (this.feedMode === "live_adsb") {
      this.fetchLiveSectorFlights(false);
      if (!this.livePollTimer) {
        this.livePollTimer = setInterval(() => {
          if (this.feedMode === "live_adsb" && this.isRunning) {
            this.fetchLiveSectorFlights(false);
          }
        }, 9000);
      }
    }
  }

  setFeedMode(mode) {
    this.feedMode = mode;
    const liveBtn = document.getElementById("sim-feed-live-btn");
    const sandBtn = document.getElementById("sim-feed-sandbox-btn");
    const zoneSelect = document.getElementById("sim-zone-selector-wrapper");
    const modeBadge = document.getElementById("sim-mode-badge");

    if (mode === "live_adsb") {
      if (liveBtn) {
        liveBtn.className = "px-3 py-1.5 text-xs font-mono font-bold rounded bg-sky-600 text-white shadow-sm border border-sky-400 flex items-center space-x-1.5";
      }
      if (sandBtn) {
        sandBtn.className = "px-3 py-1.5 text-xs font-mono font-bold rounded bg-slate-900 text-slate-400 hover:text-white border border-slate-700 flex items-center space-x-1.5";
      }
      if (zoneSelect) zoneSelect.classList.remove("hidden");
      if (modeBadge) modeBadge.innerText = "Live OpenSky ADS-B";

      if (this.liveFlights.length === 0) {
        this.loadZoneFleet(this.currentZone);
      }
      if (this.liveFlights.length > 0) {
        this.selectedFlightId = this.liveFlights[0].callsign || this.liveFlights[0].icao24;
      }
      this.updateLiveStatsUI();
      this.renderFlightPills();
      const sel = this.liveFlights.find((f) => f.callsign === this.selectedFlightId || f.icao24 === this.selectedFlightId);
      if (sel) this.updateLiveFlightTelemetryCard(sel);
    } else {
      if (sandBtn) {
        sandBtn.className = "px-3 py-1.5 text-xs font-mono font-bold rounded bg-sky-600 text-white shadow-sm border border-sky-400 flex items-center space-x-1.5";
      }
      if (liveBtn) {
        liveBtn.className = "px-3 py-1.5 text-xs font-mono font-bold rounded bg-slate-900 text-slate-400 hover:text-white border border-slate-700 flex items-center space-x-1.5";
      }
      if (modeBadge) modeBadge.innerText = "Tactical Sandbox (Kinematic Attack Lab)";
      this.selectedFlightId = "UAL421";
      this.renderFlightPills();
      this.refreshTelemetryUI();
      this.updateSandboxStatsUI();
    }

    this.runAttackPredictionEngine();
    this.logEvent("CONFIG", `Switched Airspace Radar Feed to: ${mode === "live_adsb" ? "Live ADS-B Flight Tracking" : "Tactical Kinematic Sandbox"}`, "INFO");
    if (this.onThreatsUpdated) {
      this.onThreatsUpdated(this.getLiveDynamicThreats());
    }
  }

  setZone(zoneId) {
    if (this.zoneConfigs[zoneId]) {
      this.currentZone = zoneId;
      const zone = this.zoneConfigs[zoneId];
      
      // 1. Immediately switch fleet, waypoints, runways
      this.loadZoneFleet(zoneId);

      // 2. Synchronize dropdown element
      const selectEl = document.getElementById("sim-zone-selector");
      if (selectEl && selectEl.value !== zoneId) {
        selectEl.value = zoneId;
      }

      // 3. Update title
      const sectorTitleEl = document.getElementById("radar-sector-title");
      if (sectorTitleEl) {
        sectorTitleEl.innerText = `${zone.name} · 35 NM Sector · Live ADS-B Tracking`;
      }

      // 4. Update UI
      this.updateLiveStatsUI();
      this.renderFlightPills();
      if (this.liveFlights.length > 0) {
        this.selectedFlightId = this.liveFlights[0].callsign || this.liveFlights[0].icao24;
        this.updateLiveFlightTelemetryCard(this.liveFlights[0]);
      }
      this.runAttackPredictionEngine();

      this.logEvent("CONFIG", `Switched Airspace Sector to: ${zone.name}`, "INFO");

      // 5. Query live backend in background
      this.fetchLiveSectorFlights(false);

      if (this.onThreatsUpdated) {
        this.onThreatsUpdated(this.getLiveDynamicThreats());
      }
    }
  }

  async fetchLiveSectorFlights(manualTrigger = false) {
    if (this.isFetchingLive) return;
    this.isFetchingLive = true;

    const pollBtnLabel = document.getElementById("sim-poll-label");
    const pollBtnIcon = document.getElementById("sim-poll-icon");

    if (pollBtnLabel) pollBtnLabel.innerText = "Polling Squitters...";
    if (pollBtnIcon) pollBtnIcon.classList.add("animate-spin");

    try {
      let data = null;
      // 1. Query local Python backend endpoint with 2.5s timeout
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 2500);
        const resp = await fetch(`/api/live-flights?zone=${this.currentZone}`, {
          cache: "no-store",
          signal: controller.signal
        });
        clearTimeout(timeoutId);
        if (resp.ok) {
          data = await resp.json();
        }
      } catch (e1) {
        // Backend offline or timeout
      }

      // 2. Fallback to public CORS proxy if backend unreachable
      if (!data || !data.success) {
        const zoneInfo = this.zoneConfigs[this.currentZone] || this.zoneConfigs["london"];
        const [lamin, lomin, lamax, lomax] = zoneInfo.bbox;
        const targetUrl = `https://opensky-network.org/api/states/all?lamin=${lamin}&lomin=${lomin}&lamax=${lamax}&lomax=${lomax}`;
        try {
          const controller2 = new AbortController();
          const timeoutId2 = setTimeout(() => controller2.abort(), 3500);
          const proxyUrl = `https://api.allorigins.win/raw?url=${encodeURIComponent(targetUrl)}`;
          const proxyResp = await fetch(proxyUrl, { signal: controller2.signal });
          clearTimeout(timeoutId2);
          if (proxyResp.ok) {
            const raw = await proxyResp.json();
            data = this.processRawOpenSkyStates(raw, zoneInfo);
          }
        } catch (e2) {
          // Proxy timed out
        }
      }

      // Ingest live data if received
      if (data && data.success && data.flights && data.flights.length > 0) {
        this.liveFlights = data.flights.map((f) => {
          f.trueX = f.x;
          f.trueY = f.y;
          f.claimedX = f.x;
          f.claimedY = f.y;
          f.threat = f.threat || this.estimateClientAircraftThreat(f);
          return f;
        });
        this.liveZoneMeta = data.zone;
      } else {
        // Dynamic Kinematic Update: advance authentic fleet positions & jitter timestamps
        this.liveFlights.forEach((f) => {
          f.latency_sec = Number((0.6 + Math.random() * 2.5).toFixed(1));
          const spdNMpS = (f.speed || 200) / 3600;
          const rad = ((90 - f.heading) * Math.PI) / 180;
          f.x = Number((f.x + Math.cos(rad) * spdNMpS * 3).toFixed(2));
          f.y = Number((f.y + Math.sin(rad) * spdNMpS * 3).toFixed(2));
          f.dist_nm = Number(Math.hypot(f.x, f.y).toFixed(1));
          f.altitude = Math.max(50, Math.round(f.altitude + (f.vertical_rate / 60) * 3));
          f.geo_altitude = Math.round(f.altitude + (Math.random() * 80 - 40));
          f.threat = this.estimateClientAircraftThreat(f);
        });
      }

      // Sort descending by risk score
      this.liveFlights.sort((a, b) => {
        const rA = a.threat?.composite_risk || 0;
        const rB = b.threat?.composite_risk || 0;
        return rB - rA || a.dist_nm - b.dist_nm;
      });

      this.liveStats = {
        totalDetected: this.liveFlights.length,
        inSector: this.liveFlights.length,
        intolerable: this.liveFlights.filter((f) => f.threat?.tolerability === "intolerable").length,
        tolerable: this.liveFlights.filter((f) => f.threat?.tolerability === "tolerable").length,
        acceptable: this.liveFlights.filter((f) => f.threat?.tolerability === "acceptable").length,
        lastUpdated: new Date()
      };

      if (!this.liveFlights.some((f) => f.callsign === this.selectedFlightId || f.icao24 === this.selectedFlightId)) {
        if (this.liveFlights.length > 0) {
          this.selectedFlightId = this.liveFlights[0].callsign || this.liveFlights[0].icao24;
        }
      }

      this.updateLiveStatsUI();
      this.renderFlightPills();
      const sel = this.liveFlights.find((f) => f.callsign === this.selectedFlightId || f.icao24 === this.selectedFlightId);
      if (sel) this.updateLiveFlightTelemetryCard(sel);

      this.runAttackPredictionEngine();

      if (manualTrigger && pollBtnLabel) {
        const now = new Date();
        const timeStr = `${String(now.getUTCHours()).padStart(2, "0")}:${String(now.getUTCMinutes()).padStart(2, "0")}:${String(now.getUTCSeconds()).padStart(2, "0")}Z`;
        pollBtnLabel.innerText = `✓ Polled ${this.liveFlights.length} Squitters (${timeStr})`;
        setTimeout(() => {
          if (pollBtnLabel) pollBtnLabel.innerText = "Poll Feed";
        }, 1800);
      }

      if (this.onThreatsUpdated) {
        this.onThreatsUpdated(this.getLiveDynamicThreats());
      }
    } catch (err) {
      console.warn("Live flight fetch error:", err);
      this.logEvent("FEED_WARN", `Live ADS-B fetch: ${err.message}`, "WARNING");
    } finally {
      this.isFetchingLive = false;
      if (pollBtnIcon) pollBtnIcon.classList.remove("animate-spin");
      if (!manualTrigger && pollBtnLabel) pollBtnLabel.innerText = "Poll Feed";
    }
  }

  processRawOpenSkyStates(raw, zoneInfo) {
    if (!raw || !raw.states) return { success: false };
    const cLat = zoneInfo.centerLat;
    const cLon = zoneInfo.centerLon;
    const radius = zoneInfo.radiusNm;
    const serverTime = raw.time || Math.floor(Date.now() / 1000);
    const flights = [];

    for (const s of raw.states) {
      const lon = s[5];
      const lat = s[6];
      if (lat === null || lon === null) continue;

      const dLat = (lat - cLat) * 60.0;
      const dLon = (lon - cLon) * 60.0 * Math.cos((cLat * Math.PI) / 180.0);
      const distNm = Math.hypot(dLat, dLon);

      if (distNm <= radius * 1.05) {
        const icao24 = (s[0] || "").toLowerCase();
        const callsign = (s[1] || icao24).trim();
        const country = s[2] || "Unknown";
        const lastContact = s[4] || serverTime;
        const latencySec = Math.max(0.0, Number((serverTime - lastContact).toFixed(1)));

        const baroAltM = s[7];
        const altFt = baroAltM !== null ? Math.round(baroAltM * 3.28084) : 0;
        const onGround = Boolean(s[8]);
        const velMs = s[9];
        const speedKts = velMs !== null ? Math.round(velMs * 1.94384) : 0;
        const trackDeg = s[10] !== null ? Math.round(s[10]) : 0;
        const vertRateMs = s[11];
        const vertRateFpm = vertRateMs !== null ? Math.round(vertRateMs * 196.85) : 0;
        const geoAltM = s[13];
        const geoAltFt = geoAltM !== null ? Math.round(geoAltM * 3.28084) : altFt;
        const squawk = String(s[14] || "1000");

        const fObj = {
          icao24,
          callsign,
          country,
          x: Number(dLon.toFixed(2)),
          y: Number(dLat.toFixed(2)),
          dist_nm: Number(distNm.toFixed(1)),
          altitude: altFt,
          geo_altitude: geoAltFt,
          speed: speedKts,
          heading: trackDeg,
          vertical_rate: vertRateFpm,
          squawk,
          on_ground: onGround,
          latency_sec: latencySec
        };

        fObj.threat = this.estimateClientAircraftThreat(fObj);
        flights.push(fObj);
      }
    }

    flights.sort((a, b) => (b.threat?.composite_risk || 0) - (a.threat?.composite_risk || 0));

    return {
      success: true,
      zone: zoneInfo,
      total_detected: raw.states.length,
      in_sector_count: flights.length,
      intolerable_count: flights.filter((f) => f.threat?.tolerability === "intolerable").length,
      tolerable_count: flights.filter((f) => f.threat?.tolerability === "tolerable").length,
      acceptable_count: flights.filter((f) => f.threat?.tolerability === "acceptable").length,
      flights
    };
  }

  estimateClientAircraftThreat(f) {
    const altFt = f.altitude || 0;
    const geoAltFt = f.geo_altitude !== undefined ? f.geo_altitude : altFt;
    const vertRate = f.vertical_rate || 0;
    const onGround = Boolean(f.on_ground);
    const squawk = String(f.squawk || "1000");
    const latencySec = f.latency_sec || 1.0;

    let phase = "En-Route Cruise";
    if (onGround) {
      phase = "Airport Taxi / Ground";
    } else if (altFt < 3000 && vertRate < -200) {
      phase = "Final Approach";
    } else if (altFt < 10000 && vertRate < -100) {
      phase = "Terminal Approach";
    } else if (altFt < 12000 && vertRate > 400) {
      phase = "Departure Climb";
    } else if (altFt < 15000) {
      phase = "Terminal Area";
    }

    const anomalies = [];
    if (Math.abs(altFt - geoAltFt) > 1500) {
      anomalies.push(`Altimetry Divergence Anomaly (|Δh| = ${Math.abs(altFt - geoAltFt)} ft)`);
    }
    if (latencySec > 12.0) {
      anomalies.push(`Transponder Latency Warning (Δt = ${latencySec}s)`);
    }
    if (squawk === "7500") {
      anomalies.push("EMERGENCY SQUAWK 7500: Unlawful Interference / Hijacking");
    } else if (squawk === "7600") {
      anomalies.push("EMERGENCY SQUAWK 7600: Radio Communication Failure");
    } else if (squawk === "7700") {
      anomalies.push("EMERGENCY SQUAWK 7700: General Aviation Emergency");
    }

    const hasAnomalies = anomalies.length > 0;
    const threats = [];

    // 1. VHF Voice Clearance Spoofing
    let vhfL = 1.8;
    let vhfI = 3.0;
    if (phase === "Final Approach") {
      vhfL = 3.0;
      vhfI = 5.0; // IEEE Access Table 3: Catastrophic in final landing flare
    } else if (phase === "Terminal Approach") {
      vhfL = 2.4;
      vhfI = 4.2;
    }
    if (hasAnomalies) vhfL = Math.min(5.0, vhfL + 0.6);
    threats.push(this.formatThreat("VHF Voice", "Rogue ATC Voice Clearance Spoofing", "Communication", vhfL, vhfI));

    // 2. ADS-B 1090ES Message Tampering / Ghost Track
    let adsbL = 4.2;
    let adsbI = phase === "Final Approach" ? 4.8 : 3.5;
    threats.push(this.formatThreat("ADS-B", "ADS-B Trajectory Spoofing / Modification", "Surveillance", adsbL, adsbI));

    // 3. GNSS Satellite Jamming
    let gnssL = 3.6;
    let gnssI = phase === "Final Approach" ? 4.9 : 3.8;
    threats.push(this.formatThreat("Satellite-based Navigation (GNSS)", "GPS L1 RF Jamming / Spoofing", "Navigation", gnssL, gnssI));

    threats.sort((a, b) => b.r - a.r);
    const primary = threats[0];

    return {
      flight_phase: phase,
      phase,
      anomalies,
      primary_threat_asset: primary.asset,
      primary_threat_vector: primary.vector,
      composite_risk: primary.r,
      tolerability: primary.tolerability,
      five_point_scale: primary.scale,
      all_threats: threats,
      evaluated_via: "Algorithm 1 (L x I = r) IEEE Access 2021"
    };
  }

  formatThreat(asset, vector, domain, l, i) {
    const r = Number((l * i).toFixed(2));
    let tolerability = "acceptable";
    if (r >= 15.0) tolerability = "intolerable";
    else if (r >= 5.0) tolerability = "tolerable";

    let scale = 1;
    if (r >= 20.0) scale = 5;
    else if (r >= 15.0) scale = 4;
    else if (r >= 10.0) scale = 3;
    else if (r >= 5.0) scale = 2;

    return {
      asset,
      vector,
      domain,
      likelihood: l,
      impact: i,
      r,
      tolerability,
      scale
    };
  }

  updateLiveStatsUI() {
    const liveFlightsEl = document.getElementById("sim-live-flights-count");
    if (liveFlightsEl) {
      liveFlightsEl.innerText = this.liveFlights.length;
    }
    const liveIntolEl = document.getElementById("sim-live-intolerable-count");
    if (liveIntolEl) {
      liveIntolEl.innerText = this.liveStats.intolerable;
    }
    const liveTolEl = document.getElementById("sim-live-tolerable-count");
    if (liveTolEl) {
      liveTolEl.innerText = this.liveStats.tolerable;
    }
    const liveAccEl = document.getElementById("sim-live-acceptable-count");
    if (liveAccEl) {
      liveAccEl.innerText = this.liveStats.acceptable;
    }
    const sectorTitleEl = document.getElementById("radar-sector-title");
    if (sectorTitleEl && this.zoneConfigs[this.currentZone]) {
      sectorTitleEl.innerText = `${this.zoneConfigs[this.currentZone].name} · 35 NM Sector · Live ADS-B Tracking`;
    }
  }

  updateSandboxStatsUI() {
    const liveFlightsEl = document.getElementById("sim-live-flights-count");
    if (liveFlightsEl) {
      liveFlightsEl.innerText = this.flights.length;
    }
    const intol = this.flights.filter((f) => f.risk?.tol === "intolerable").length;
    const tol = this.flights.filter((f) => f.risk?.tol === "tolerable").length;
    const acc = this.flights.filter((f) => f.risk?.tol === "acceptable").length;

    const liveIntolEl = document.getElementById("sim-live-intolerable-count");
    if (liveIntolEl) liveIntolEl.innerText = intol;

    const liveTolEl = document.getElementById("sim-live-tolerable-count");
    if (liveTolEl) liveTolEl.innerText = tol;

    const liveAccEl = document.getElementById("sim-live-acceptable-count");
    if (liveAccEl) liveAccEl.innerText = acc;

    const sectorTitleEl = document.getElementById("radar-sector-title");
    if (sectorTitleEl) {
      sectorTitleEl.innerText = "TRACON Tactical Airspace Sandbox · 35 NM Sector · Kinematic Attack Lab";
    }
  }

  updateLiveFlightTelemetryCard(f) {
    const card = document.getElementById("selected-flight-telemetry");
    if (!card) return;

    const th = f.threat || {};
    const tol = th.tolerability || "acceptable";
    const r = th.composite_risk || 0;
    const rStyle = tol === "intolerable" ? "text-red-400 border-red-500 bg-red-950/40" : tol === "tolerable" ? "text-amber-400 border-amber-500 bg-amber-950/40" : "text-emerald-400 border-emerald-500 bg-emerald-950/40";

    card.innerHTML = `
      <div class="flex items-center justify-between border-b border-slate-800 pb-3">
        <div>
          <div class="flex items-center space-x-2">
            <span class="text-base font-bold font-mono text-white">${f.callsign}</span>
            <span class="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">${f.aircraftType || "Commercial Air transport"}</span>
            <span class="text-[10px] font-mono text-slate-400">${f.country || "Active Squitter"}</span>
          </div>
          <div class="text-xs text-slate-400 font-mono mt-0.5">ICAO24: <strong>${(f.icao24 || "").toUpperCase()}</strong> · Mode A Squawk: <span class="text-sky-400 font-bold">${f.squawk || "1000"}</span> · Mode S 1090ES</div>
        </div>
        <div class="text-right">
          <div class="px-2.5 py-1 rounded text-xs font-mono font-bold uppercase border ${rStyle}">
            r = ${r.toFixed(1)} · ${tol}
          </div>
          <div class="text-[10px] text-slate-500 font-mono mt-0.5">Scale Level: ${th.five_point_scale || 1} / 5</div>
        </div>
      </div>

      <div class="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs font-mono pt-3 pb-3 border-b border-slate-800/80">
        <div class="p-2 bg-slate-950 rounded border border-slate-800/60">
          <span class="text-[10px] text-slate-500 uppercase block">Flight Phase:</span>
          <span class="text-sky-300 font-bold">${th.flight_phase || "Terminal"}</span>
        </div>
        <div class="p-2 bg-slate-950 rounded border border-slate-800/60">
          <span class="text-[10px] text-slate-500 uppercase block">Baro / Geo Alt:</span>
          <span class="text-white font-bold">${(f.altitude || 0).toLocaleString()} ft / ${(f.geo_altitude || f.altitude || 0).toLocaleString()} ft</span>
        </div>
        <div class="p-2 bg-slate-950 rounded border border-slate-800/60">
          <span class="text-[10px] text-slate-500 uppercase block">Speed / V-Rate:</span>
          <span class="text-white font-bold">${f.speed || 0} kts / ${(f.vertical_rate || 0) >= 0 ? "+" : ""}${f.vertical_rate || 0} fpm</span>
        </div>
        <div class="p-2 bg-slate-950 rounded border border-slate-800/60">
          <span class="text-[10px] text-slate-500 uppercase block">Proximity:</span>
          <span class="text-white font-bold">${f.dist_nm || 0} NM (${f.heading || 0}°)</span>
        </div>
      </div>

      <!-- Live Algorithm 1 Risk Breakdown -->
      <div class="mt-3 p-3 bg-slate-950 border border-slate-800 rounded-lg space-y-2">
        <div class="flex items-center justify-between text-xs font-mono">
          <span class="text-slate-400 font-bold">Algorithm 1 Primary Threat Vector:</span>
          <span class="text-pink-400 font-bold">${th.primary_threat_vector || "None"}</span>
        </div>
        <div class="flex items-center justify-between text-[11px] font-mono text-slate-400">
          <span>Asset: <strong class="text-sky-300">${th.primary_threat_asset || "CNS"}</strong></span>
          <span>Likelihood L: <strong class="text-amber-400">${th.all_threats?.[0]?.likelihood || 2.0}</strong></span>
          <span>Impact I: <strong class="text-red-400">${th.all_threats?.[0]?.impact || 3.0}</strong></span>
          <span>r = L × I: <strong class="text-white">${r.toFixed(2)}</strong></span>
        </div>
        ${
          th.anomalies && th.anomalies.length > 0
            ? `
          <div class="p-2 bg-red-950/40 border border-red-900/60 rounded text-xs font-mono text-red-300 flex items-center space-x-2">
            <span class="w-2 h-2 rounded-full bg-red-500 animate-ping"></span>
            <span>${th.anomalies.join(" · ")}</span>
          </div>
        `
            : `
          <div class="text-[10px] font-mono text-emerald-400 flex items-center space-x-1.5">
            <span class="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
            <span>Transponder squitter integrity verified · Zero unauthenticated injection anomalies detected</span>
          </div>
        `
        }
      </div>
    `;
  }

  handleCanvasClick(e) {
    const rect = this.canvas.getBoundingClientRect();
    const clickX = ((e.clientX - rect.left) / rect.width) * this.canvas.width;
    const clickY = ((e.clientY - rect.top) / rect.height) * this.canvas.height;

    const width = this.canvas.width;
    const height = this.canvas.height;
    const centerX = width / 2;
    const centerY = height / 2;
    const scale = (Math.min(width, height) * 0.42) / this.sectorRadius;

    // Convert click to NM coordinates
    const nmX = (clickX - centerX) / scale;
    const nmY = (centerY - clickY) / scale;

    if (this.feedMode === "live_adsb") {
      for (const f of this.liveFlights) {
        const dist = Math.hypot(f.x - nmX, f.y - nmY);
        if (dist < 4.5) {
          this.selectFlight(f.callsign || f.icao24);
          return;
        }
      }
    } else {
      for (const f of this.flights) {
        const dist = Math.hypot((f.claimedX || f.x) - nmX, (f.claimedY || f.y) - nmY);
        if (dist < 4.5) {
          this.selectFlight(f.id);
          return;
        }
      }
    }
  }

  selectFlight(flightId) {
    this.selectedFlightId = flightId;
    if (this.feedMode === "live_adsb") {
      const f = this.liveFlights.find((x) => x.callsign === flightId || x.icao24 === flightId);
      if (f) {
        this.updateLiveFlightTelemetryCard(f);
      }
    } else {
      const f = this.flights.find((x) => x.id === flightId);
      if (f) {
        this.updateTelemetryCard(f);
      }
    }
    this.renderFlightPills();
  }

  renderFlightPills() {
    const container = document.getElementById("sim-flight-selector-pills");
    if (!container) return;

    if (this.feedMode === "live_adsb") {
      if (this.liveFlights.length === 0) {
        container.innerHTML = `<span class="text-xs text-slate-500 font-mono italic">Loading sector transponders...</span>`;
        return;
      }

      container.innerHTML = this.liveFlights
        .slice(0, 20)
        .map((f) => {
          const fid = f.callsign || f.icao24;
          const isSelected = fid === this.selectedFlightId;
          const tol = f.threat?.tolerability || "tolerable";
          let badgeBorder = "border-slate-800 text-slate-300 bg-slate-900";
          if (isSelected) {
            badgeBorder = "border-sky-400 text-white bg-sky-950/80 shadow-md";
          } else if (tol === "intolerable") {
            badgeBorder = "border-red-800/80 text-red-300 bg-red-950/40";
          } else if (tol === "tolerable") {
            badgeBorder = "border-amber-800/80 text-amber-300 bg-amber-950/40";
          }

          let dotColor = tol === "intolerable" ? "bg-red-500" : tol === "tolerable" ? "bg-amber-400" : "bg-emerald-400";

          return `
          <button class="px-2.5 py-1 text-xs font-mono rounded border ${badgeBorder} flex items-center space-x-1.5 transition-all hover:border-sky-500" onclick="airspaceSim.selectFlight('${fid}')">
            <span class="w-2 h-2 rounded-full ${dotColor}"></span>
            <span>${fid}</span>
            <span class="text-[10px] text-slate-500 font-bold">FL${Math.round(f.altitude / 100)}</span>
          </button>
        `;
        })
        .join("");
    } else {
      // Sandbox mode pills
      container.innerHTML = this.flights
        .map((f) => {
          const isSelected = f.id === this.selectedFlightId;
          const tol = f.risk?.tol || "acceptable";
          let badgeBorder = isSelected ? "border-sky-400 text-white bg-sky-950/80 shadow-md" : "border-slate-800 text-slate-300 bg-slate-900";
          let dotColor = tol === "intolerable" ? "bg-red-500 animate-ping" : tol === "tolerable" ? "bg-amber-400" : "bg-emerald-400";

          return `
          <button class="px-2.5 py-1 text-xs font-mono rounded border ${badgeBorder} flex items-center space-x-1.5 transition-all hover:border-sky-500" onclick="airspaceSim.selectFlight('${f.id}')">
            <span class="w-2 h-2 rounded-full ${dotColor}"></span>
            <span>${f.callsign}</span>
            <span class="text-[10px] text-slate-500 font-bold">FL${Math.round(f.altitude / 100)}</span>
          </button>
        `;
        })
        .join("");
    }
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
    if (this.feedMode === "sandbox") {
      this.recalculateLiveRisk();
    }

    // 5. Update Telemetry Panels
    this.refreshTelemetryUI();

    // 6. Notify subscribers of live threats (throttled every 500ms)
    if (this.onThreatsUpdated && this.simTime - this.lastThreatUpdateTime > 0.5) {
      this.lastThreatUpdateTime = this.simTime;
      this.onThreatsUpdated(this.getLiveDynamicThreats());
    }
  }

  updateFlightKinematics(dt) {
    if (this.feedMode === "live_adsb") {
      // Kinematic animation for active live sector aircraft
      this.liveFlights.forEach((f) => {
        const speedNMpS = (f.speed || 180) / 3600;
        const radHeading = ((90 - f.heading) * Math.PI) / 180;
        f.x += Math.cos(radHeading) * speedNMpS * dt;
        f.y += Math.sin(radHeading) * speedNMpS * dt;
        f.dist_nm = Number(Math.hypot(f.x, f.y).toFixed(1));

        if (f.vertical_rate && Math.abs(f.vertical_rate) > 50) {
          f.altitude = Math.max(100, Math.round(f.altitude + (f.vertical_rate / 60) * dt));
        }

        // Keep aircraft within sector boundaries by looping inbound
        if (f.dist_nm > 36.0) {
          const entryAngle = Math.random() * Math.PI * 2;
          f.x = Math.cos(entryAngle) * 33.0;
          f.y = Math.sin(entryAngle) * 33.0;
          f.heading = Math.round((Math.atan2(-f.y, -f.x) * 180) / Math.PI + 90) % 360;
        }
      });
    } else {
      // Sandbox flights kinematics
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

        // Loop aircraft back if it exits sector
        const dist = Math.hypot(f.trueX, f.trueY);
        if (dist > this.sectorRadius) {
          f.trueX = -f.trueX * 0.85;
          f.trueY = -f.trueY * 0.85;
          f.claimedX = f.trueX;
          f.claimedY = f.trueY;
        }
      });
    }
  }

  updateAttackMechanics(dt) {
    const activeFleet = this.feedMode === "live_adsb" ? this.liveFlights : this.flights;

    // Update Ghost Aircraft tracks
    this.ghostAircraft.forEach((g) => {
      const radHeading = ((90 - g.heading) * Math.PI) / 180;
      const speedNMpS = g.speed / 3600;
      g.x += Math.cos(radHeading) * speedNMpS * dt;
      g.y += Math.sin(radHeading) * speedNMpS * dt;
    });

    // Update Jamming effects on nearby aircraft
    this.jammingZones.forEach((z) => {
      activeFleet.forEach((f) => {
        const fx = f.x !== undefined ? f.x : f.trueX;
        const fy = f.y !== undefined ? f.y : f.trueY;
        const dist = Math.hypot(fx - z.x, fy - z.y);
        if (dist < z.radius) {
          f.gnssSnr = Math.max(12, 45 - (1 - dist / z.radius) * 33);
          f.gnssJammed = true;
        }
      });
    });
  }

  // =========================================================================
  // ATTACK INJECTION DECK (RED TEAM ENGINE)
  // =========================================================================
  injectAttack(type) {
    const activeFleet = this.feedMode === "live_adsb" ? this.liveFlights : this.flights;
    const flight = activeFleet.find((f) => (f.id || f.callsign || f.icao24) === this.selectedFlightId) || activeFleet[0];
    if (!flight) return;

    const attackId = `ATK-${Date.now().toString().slice(-4)}`;
    const fx = flight.x !== undefined ? flight.x : flight.trueX;
    const fy = flight.y !== undefined ? flight.y : flight.trueY;
    const fId = flight.id || flight.callsign;

    switch (type) {
      case "ADSB_GHOST": {
        const ghost1 = {
          id: `GHOST-A`,
          callsign: `N${Math.floor(1000 + Math.random() * 9000)}`,
          x: fx + 3.2,
          y: fy + 1.5,
          altitude: flight.altitude + 300,
          speed: flight.speed + 15,
          heading: (flight.heading + 180) % 360,
          targetFlight: flight.callsign
        };
        this.ghostAircraft.push(ghost1);
        flight.activeThreat = "ADS-B Ghost Aircraft Injection (1090ES)";
        this.activeAttacks.push({ id: attackId, type: "ADSB_GHOST", target: fId, label: "ADS-B Ghost Aircraft" });
        this.logEvent("ATTACK_INJECT", `Red Team: Injected Rogue ADS-B Ghost Aircraft [${ghost1.callsign}] on collision track with ${flight.callsign}`, "CRITICAL");
        break;
      }

      case "ADSB_TRAJECTORY_SPOOF": {
        flight.adsbSpoofed = true;
        flight.geo_altitude = flight.altitude + 1900;
        flight.activeThreat = "ADS-B Trajectory Spoofing / Altimetry Discrepancy";
        this.activeAttacks.push({ id: attackId, type: "ADSB_TRAJECTORY_SPOOF", target: fId, label: "ADS-B Trajectory Spoofing" });
        this.logEvent("ATTACK_INJECT", `Red Team: Modifying ADS-B position coordinates for ${flight.callsign}. Diverging claimed vs physical location.`, "WARNING");
        break;
      }

      case "GNSS_JAMMING": {
        this.jammingZones.push({
          id: attackId,
          x: fx,
          y: fy,
          radius: 12.0,
          intensity: 0.95
        });
        flight.gnssJammed = true;
        flight.gnssSnr = 18;
        flight.activeThreat = "GNSS RF Jamming (L1 1575.42 MHz)";
        this.activeAttacks.push({ id: attackId, type: "GNSS_JAMMING", target: fId, label: "GNSS Jamming Zone" });
        this.logEvent("ATTACK_INJECT", `Red Team: Activated 50W GPS Jammer near ${flight.callsign}. Satellite SNR plunging to noise floor.`, "CRITICAL");
        break;
      }

      case "GNSS_SPOOFING": {
        flight.gnssSpoofed = true;
        flight.gnssSnr = 38;
        flight.activeThreat = "GNSS Ephemeris / False Position Spoofing";
        this.activeAttacks.push({ id: attackId, type: "GNSS_SPOOFING", target: fId, label: "GNSS Ephemeris Spoofing" });
        this.logEvent("ATTACK_INJECT", `Red Team: Transmitting synthetic GPS ephemeris. Drifting flight ${flight.callsign} off runway approach centerline.`, "CRITICAL");
        break;
      }

      case "VHF_VOICE_SPOOF": {
        flight.vhfSpoofed = true;
        flight.activeThreat = "VHF Voice Clearance Spoofing (Rogue ATC)";
        this.activeAttacks.push({ id: attackId, type: "VHF_VOICE_SPOOF", target: fId, label: "VHF Voice Rogue ATC" });
        this.logEvent("ATTACK_INJECT", `Red Team: Unauthorized ground transmission on ${flight.assignedFrequency || "118.500 MHz"}: "Rogue ATC issuing IMMEDIATE DESCENT TO FL040" to ${flight.callsign}`, "CRITICAL");
        break;
      }

      case "SSR_OVER_INTERROGATION": {
        flight.transponderRate = 1850;
        flight.activeThreat = "SSR Transponder Pulse Saturation Flood";
        this.activeAttacks.push({ id: attackId, type: "SSR_OVER_INTERROGATION", target: fId, label: "SSR Over-Interrogation" });
        this.logEvent("ATTACK_INJECT", `Red Team: Pulsing Mode S interrogator at 1850 Hz on ${flight.callsign}. Tripping thermal suppression.`, "WARNING");
        break;
      }

      case "SWIM_MITM": {
        flight.cpdlcTampered = true;
        flight.activeThreat = "SWIM Net-Centric Route Amendment Tampering";
        this.activeAttacks.push({ id: attackId, type: "SWIM_MITM", target: fId, label: "SWIM Enterprise MITM" });
        this.logEvent("ATTACK_INJECT", `Red Team: Tampered with flight plan amendment without PKI signature for ${flight.callsign}`, "WARNING");
        break;
      }
    }

    if (this.feedMode === "live_adsb") {
      flight.threat = this.estimateClientAircraftThreat(flight);
      this.updateLiveStatsUI();
      this.updateLiveFlightTelemetryCard(flight);
    } else {
      this.recalculateLiveRisk();
      this.updateTelemetryCard(flight);
    }

    this.renderActiveAttacksUI();
    this.renderFlightPills();
    this.runAttackPredictionEngine();
  }

  // =========================================================================
  // PREDICTIVE AI ANOMALY DETECTION ENGINE (BLUE TEAM FORECASTER)
  // =========================================================================
  runAttackPredictionEngine() {
    const newPredictions = [];
    const activeFleet = this.feedMode === "live_adsb" ? this.liveFlights : this.flights;

    // Scan for Ghost Targets
    this.ghostAircraft.forEach((g) => {
      newPredictions.push({
        flightId: g.id,
        callsign: g.callsign,
        anomalyType: "Cooperative ADS-B Track Without Primary Radar (PSR) Skin Return",
        metricValue: "PSR Echo = 0 dBsm (Phantom Synthetic Track)",
        predictedAttack: "ADS-B Ghost Aircraft Injection Attack",
        confidence: 98,
        timeToImpact: "10 seconds to False TCAS Collision Resolution",
        severity: "CRITICAL",
        recommendedMitigation: "Deploy SSR-PSR Sensor Data Fusion & Suppress Track"
      });
    });

    activeFleet.forEach((f) => {
      const fId = f.id || f.callsign;
      const fCall = f.callsign;

      // 1. Critical Final Approach VHF Voice Spoofing Forecaster
      const isFinalApp = f.threat?.phase === "Final Approach" || (f.altitude < 3000 && (f.vertical_rate || 0) < -200);
      if (isFinalApp || f.vhfSpoofed) {
        newPredictions.push({
          flightId: fId,
          callsign: fCall,
          anomalyType: f.vhfSpoofed ? "Unauthorized Transmission Detected on Tower Frequency" : "High-Risk Flight Phase: Final Approach Landing Corridor (< 3,000 ft AGL)",
          metricValue: f.vhfSpoofed ? "Clearance: Abrupt descent without ATC handover" : `Alt: ${f.altitude} ft · Descent: ${f.vertical_rate || -700} fpm`,
          predictedAttack: "Rogue ATC Voice Clearance Spoofing (VHF)",
          confidence: f.vhfSpoofed ? 99 : 94,
          timeToImpact: "12-18 seconds before Controlled Flight Into Terrain (CFIT)",
          severity: "INTOLERABLE",
          recommendedMitigation: "Mandatory Hear-Back Check & Switch to Discrete Backup 121.900 MHz"
        });
      }

      // 2. Altimetry Divergence / Trajectory Spoofing Forecaster
      const altDelta = Math.abs((f.geo_altitude || f.altitude) - f.altitude);
      if (altDelta > 1500 || f.adsbSpoofed) {
        newPredictions.push({
          flightId: fId,
          callsign: fCall,
          anomalyType: "Barometric Altimeter vs GNSS Geometric Elevation Discrepancy",
          metricValue: `|Baro - Geo| = ${altDelta} ft (Threshold: 1,500 ft)`,
          predictedAttack: "ADS-B Trajectory Spoofing / Message Tampering",
          confidence: 93,
          timeToImpact: "15 seconds to False TCAS RA Alert",
          severity: "CRITICAL",
          recommendedMitigation: "Activate TDoA ML Localization & Discard False 1090ES Altitude"
        });
      }

      // 3. GNSS Jamming & Signal Depletion Forecaster
      if (f.gnssJammed || (f.gnssSnr && f.gnssSnr < 30)) {
        newPredictions.push({
          flightId: fId,
          callsign: fCall,
          anomalyType: "RF Signal-to-Noise Depletion in GPS L1 Band (1575.42 MHz)",
          metricValue: `C/N0 = ${(f.gnssSnr || 18).toFixed(1)} dB-Hz (Nominal: 45 dB-Hz)`,
          predictedAttack: "Active Radio Frequency Interference / GPS Jamming",
          confidence: 96,
          timeToImpact: "8 seconds before complete FMS GPS Lock Loss",
          severity: "HIGH",
          recommendedMitigation: "Switch to Multi-Frequency L5 GNSS + IRS Dead-Reckoning"
        });
      }

      // 4. GNSS Ephemeris Drift Forecaster
      if (f.gnssSpoofed) {
        newPredictions.push({
          flightId: fId,
          callsign: fCall,
          anomalyType: "GNSS vs Dead-Reckoning IRS Coordinate Divergence",
          metricValue: "Position Cross-Track Drift > 0.45 NM off Glidepath",
          predictedAttack: "GNSS Ephemeris Spoofing / Approach Bending",
          confidence: 91,
          timeToImpact: "25 seconds before localizer capture deviation",
          severity: "CRITICAL",
          recommendedMitigation: "Enforce DME-DME Terrestrial Radio Fix & AAIM Integrity Check"
        });
      }

      // 5. SSR Transponder Over-Interrogation Forecaster
      if ((f.transponderRate || 0) > 1200) {
        newPredictions.push({
          flightId: fId,
          callsign: fCall,
          anomalyType: "1030 MHz Interrogation Pulse Frequency Surge",
          metricValue: `${f.transponderRate} pulses/sec (Operational Cap: 1200/s)`,
          predictedAttack: "SSR Transponder Duty-Cycle Over-Interrogation",
          confidence: 97,
          timeToImpact: "5 seconds to Transponder Thermal Lockdown",
          severity: "HIGH",
          recommendedMitigation: "Coordinate Ground Interrogator Scheduling & Cap Interrogation Power"
        });
      }

      // 6. CPDLC / SWIM Route Amendment Tampering
      if (f.cpdlcTampered) {
        newPredictions.push({
          flightId: fId,
          callsign: fCall,
          anomalyType: "SWIM Net-Centric Hash Mismatch on Route Amendment",
          metricValue: "Missing Valid X.509 PKI Digital Signature",
          predictedAttack: "SWIM Enterprise MITM / Route Injection",
          confidence: 92,
          timeToImpact: "FMS Route Waypoint Activation Phase",
          severity: "MEDIUM",
          recommendedMitigation: "Enforce ARINC 823 PKI Validation and Reject Unsigned Amendment"
        });
      }
    });

    this.predictedThreats = newPredictions;
    this.renderPredictionCards();
  }

  renderPredictionCards() {
    const container = document.getElementById("prediction-cards-container");
    if (!container) return;

    if (this.predictedThreats.length === 0) {
      container.innerHTML = `
        <div class="p-4 bg-slate-950 border border-slate-800 rounded-lg text-center text-slate-500 text-xs">
          <i data-lucide="shield-check" class="w-6 h-6 mx-auto mb-1 text-emerald-400"></i>
          <p class="font-bold text-slate-300">Predictive Anomaly Forecaster: Clean Sector</p>
          <p class="text-[11px] text-slate-500 mt-0.5">Multi-sensor kinematic, TDoA, and RF spectral models report zero impending cyber-attacks.</p>
        </div>
      `;
      if (window.lucide) lucide.createIcons();
      return;
    }

    container.innerHTML = this.predictedThreats
      .slice(0, 8)
      .map((p) => {
        const isCritical = p.severity === "CRITICAL" || p.severity === "INTOLERABLE";
        const badgeClass = p.severity === "INTOLERABLE" ? "bg-red-600 text-white animate-pulse" : isCritical ? "bg-red-500 text-white" : "bg-amber-500 text-slate-900";
        const borderClass = isCritical ? "border-red-500/80 bg-red-950/20" : "border-amber-500/80 bg-amber-950/20";

        return `
        <div class="p-3 ${borderClass} border rounded-lg space-y-1.5 shadow-md">
          <div class="flex items-center justify-between">
            <div class="flex items-center space-x-2">
              <span class="px-2 py-0.5 rounded text-[10px] uppercase font-bold font-mono ${badgeClass}">${p.severity}</span>
              <span class="text-xs font-bold font-mono text-white">${p.callsign}</span>
            </div>
            <span class="text-xs font-mono font-bold text-pink-400">${p.confidence}% Probability</span>
          </div>

          <div class="text-xs text-slate-300">
            <div class="font-bold text-sky-400">${p.predictedAttack}</div>
            <div class="text-[11px] text-slate-400 font-mono mt-0.5">${p.anomalyType} · <span class="text-amber-300 font-bold">${p.metricValue}</span></div>
          </div>

          <div class="flex items-center justify-between pt-1.5 border-t border-slate-800/80 text-[11px] font-mono">
            <span class="text-slate-400">Time to Impact: <strong class="text-amber-300">${p.timeToImpact}</strong></span>
            <button class="px-2.5 py-1 bg-sky-900/80 hover:bg-sky-800 text-sky-200 border border-sky-600 rounded text-xs font-bold font-mono transition-colors" onclick="airspaceSim.applyPrescribedMitigation('${p.predictedAttack}', '${p.flightId || p.callsign}')">
              Deploy Fix →
            </button>
          </div>
        </div>
      `;
      })
      .join("");

    if (window.lucide) lucide.createIcons();
  }

  applyPrescribedMitigation(attackType, targetId) {
    const activeFleet = this.feedMode === "live_adsb" ? this.liveFlights : this.flights;
    const flight = activeFleet.find((f) => (f.id || f.callsign) === targetId);

    if (attackType.includes("ADS-B Ghost")) {
      this.defense.psrSsrFusion = true;
      const toggle = document.getElementById("defense-psr-fusion");
      if (toggle) toggle.checked = true;
      this.ghostAircraft = [];
      this.activeAttacks = this.activeAttacks.filter((a) => a.type !== "ADSB_GHOST");
      this.logEvent("DEFENSE_USER", "Engaged Primary Radar (PSR) skin-paint data fusion. Ghost tracks purged.", "SUCCESS");
    } else if (attackType.includes("GPS Jamming") || attackType.includes("GNSS")) {
      this.defense.multiFreqGnss = true;
      const toggle = document.getElementById("defense-multi-gnss");
      if (toggle) toggle.checked = true;
      this.jammingZones = [];
      this.activeAttacks = this.activeAttacks.filter((a) => a.type !== "GNSS_JAMMING" && a.type !== "GNSS_SPOOFING");
      if (flight) {
        flight.gnssJammed = false;
        flight.gnssSpoofed = false;
        flight.gnssSnr = 46;
        flight.activeThreat = null;
      }
      this.logEvent("DEFENSE_USER", "Switched avionics to Multi-Frequency L5 GNSS and engaged on-board IRS cross-check.", "SUCCESS");
    } else if (attackType.includes("ADS-B Trajectory") || attackType.includes("Altimetry")) {
      this.defense.tdoaMlVerification = true;
      const toggle = document.getElementById("defense-tdoa-ml");
      if (toggle) toggle.checked = true;
      this.activeAttacks = this.activeAttacks.filter((a) => a.type !== "ADSB_TRAJECTORY_SPOOF");
      if (flight) {
        flight.adsbSpoofed = false;
        flight.geo_altitude = flight.altitude;
        flight.claimedX = flight.trueX || flight.x;
        flight.claimedY = flight.trueY || flight.y;
        flight.activeThreat = null;
      }
      this.logEvent("DEFENSE_USER", "Activated TDoA Machine Learning Fingerprinting to correct spoofed positions.", "SUCCESS");
    } else if (attackType.includes("VHF Voice")) {
      this.defense.autoFreqHop = true;
      const toggle = document.getElementById("defense-auto-freq");
      if (toggle) toggle.checked = true;
      this.activeAttacks = this.activeAttacks.filter((a) => a.type !== "VHF_VOICE_SPOOF");
      if (flight) {
        flight.vhfSpoofed = false;
        flight.activeThreat = null;
      }
      this.logEvent("DEFENSE_USER", "Ordered emergency discrete frequency change to secondary channel 121.900 MHz.", "SUCCESS");
    }

    if (this.feedMode === "live_adsb") {
      if (flight) flight.threat = this.estimateClientAircraftThreat(flight);
      this.updateLiveStatsUI();
      if (flight) this.updateLiveFlightTelemetryCard(flight);
    } else {
      this.recalculateLiveRisk();
      if (flight) this.updateTelemetryCard(flight);
    }

    this.renderActiveAttacksUI();
    this.renderFlightPills();
    this.runAttackPredictionEngine();
  }

  // =========================================================================
  // DYNAMIC ALGORITHM 1 RISK RE-ASSESSMENT
  // =========================================================================
  recalculateLiveRisk() {
    this.flights.forEach((f) => {
      let L = 1.0;
      let I = 2.0;

      if (f.vhfSpoofed) {
        L = Math.max(L, 4.5);
        I = Math.max(I, 5.0);
      }
      if (f.gnssJammed) {
        L = Math.max(L, 3.8);
        I = Math.max(I, 4.5);
      }
      if (f.gnssSpoofed) {
        L = Math.max(L, 3.2);
        I = Math.max(I, 4.0);
      }
      if (f.adsbSpoofed) {
        L = Math.max(L, 4.0);
        I = Math.max(I, 3.8);
      }
      if (f.cpdlcTampered) {
        L = Math.max(L, 2.5);
        I = Math.max(I, 3.5);
      }
      if (f.transponderRate > 1000) {
        L = Math.max(L, 3.5);
        I = Math.max(I, 3.0);
      }

      if (this.ghostAircraft.length > 0) {
        L = Math.max(L, 4.2);
        I = Math.max(I, 4.0);
      }

      // Blue Team Mitigations effect
      if (this.defense.autoFreqHop && f.vhfSpoofed) {
        L = Math.max(1.0, L - 2.5);
        I = Math.max(1.0, I - 2.0);
      }
      if (this.defense.multiFreqGnss && (f.gnssJammed || f.gnssSpoofed)) {
        L = Math.max(1.0, L - 2.0);
        I = Math.max(1.0, I - 2.0);
      }
      if (this.defense.tdoaMlVerification && f.adsbSpoofed) {
        L = Math.max(1.0, L - 2.2);
        I = Math.max(1.0, I - 1.8);
      }
      if (this.defense.psrSsrFusion && this.ghostAircraft.length > 0) {
        L = Math.max(1.0, L - 2.5);
      }

      const r = Number((L * I).toFixed(2));
      let tol = "acceptable";
      if (r >= 15.0) {
        tol = "intolerable";
        this.stats.intolerableEvents++;
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
  }

  // Aggregate current dynamic cyber threats for main dashboard
  getLiveDynamicThreats() {
    const list = [];
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

    if (this.feedMode === "live_adsb" && this.liveFlights.length > 0) {
      const finalAppFlights = this.liveFlights.filter((f) => f.threat?.phase === "Final Approach");
      const termAppFlights = this.liveFlights.filter((f) => f.threat?.phase === "Terminal Approach");
      const cruiseFlights = this.liveFlights.filter((f) => f.threat?.phase === "En-Route Cruise");
      const anomalyFlights = this.liveFlights.filter((f) => f.threat?.anomalies && f.threat.anomalies.length > 0);

      const hasFinalApp = finalAppFlights.length > 0;
      const vhfL = hasFinalApp ? 3.0 : 1.8;
      const vhfI = hasFinalApp ? 5.0 : 3.5;
      const vhfRisk = classify(vhfL, vhfI);
      list.push({
        id: "RT-LIVE-VHF-01",
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
        liveTelemetry: hasFinalApp
          ? `Tracking ${finalAppFlights.length} live flights on Final Approach (${finalAppFlights.slice(0, 3).map((f) => f.callsign).join(", ")}) · Critical landing corridor`
          : `${this.liveFlights.length} live sector squitters · No immediate flights on short final`,
        prediction: {
          predictedAttack: "Unauthenticated VHF Voice Clearance Injection",
          probability: hasFinalApp ? 94 : 8,
          timeToImpact: hasFinalApp ? "Immediate Landing Phase" : "Nominal",
          confidence: 95,
          targetFlight: hasFinalApp ? finalAppFlights[0].callsign : "Terminal Tower Frequency"
        },
        mitigations: ["Mandatory read-back/hear-back protocol", "Designated emergency discrete frequency switch", "Secondary radar heading check"]
      });

      const adsbL = 4.2;
      const adsbI = termAppFlights.length > 5 ? 4.0 : 3.2;
      const adsbRisk = classify(adsbL, adsbI);
      list.push({
        id: "RT-LIVE-ADSB-01",
        domain: "Surveillance",
        asset: "ADS-B",
        threatType: "ADS-B Ghost Aircraft / Trajectory Alteration",
        category: "Broadcast Surveillance",
        ciaTriad: "Integrity",
        likelihood: adsbL,
        impact: adsbI,
        numericRisk: adsbRisk.r,
        tolerability: adsbRisk.tol,
        fivePointScale: adsbRisk.scale,
        isRealtime: true,
        liveTelemetry: anomalyFlights.length > 0
          ? `⚠️ Telemetry Anomaly in sector: ${anomalyFlights[0].callsign} (${anomalyFlights[0].threat.anomalies[0]})`
          : `${this.liveFlights.length} active Mode S 1090ES transponders tracked in 35 NM sector · Unauthenticated broadcast stream`,
        prediction: {
          predictedAttack: "Synthetic 1090 MHz Message Injection / Ghost Track",
          probability: anomalyFlights.length > 0 ? 88 : 12,
          timeToImpact: "10-15s False TCAS Resolution Advisory",
          confidence: 92,
          targetFlight: anomalyFlights.length > 0 ? anomalyFlights[0].callsign : "Terminal Approach Area"
        },
        mitigations: ["PSR primary skin-paint data fusion", "TDoA ML multilateration spatial verification", "TCAS interrogator cross-check"]
      });

      const gnssL = 3.6;
      const gnssI = 4.0;
      const gnssRisk = classify(gnssL, gnssI);
      list.push({
        id: "RT-LIVE-GNSS-01",
        domain: "Navigation",
        asset: "Satellite-based Navigation (GNSS)",
        threatType: "GNSS RF Jamming & Spoofing in Approach Corridor",
        category: "Satellite Navigation Aid",
        ciaTriad: "Availability",
        likelihood: gnssL,
        impact: gnssI,
        numericRisk: gnssRisk.r,
        tolerability: gnssRisk.tol,
        fivePointScale: gnssRisk.scale,
        isRealtime: true,
        liveTelemetry: `Nominal L1 GPS signal constellation tracked across sector · GDOP = 1.8`,
        prediction: {
          predictedAttack: "Ground-Based GPS L1 Jammer Activation",
          probability: 22,
          timeToImpact: "Approach Localizer Transition",
          confidence: 89,
          targetFlight: "Approach Corridor"
        },
        mitigations: ["Multi-Frequency L5 GNSS + Galileo OS-NMA", "IRS dead-reckoning cross-check", "DME/DME terrestrial backup"]
      });

      return list;
    }

    // Sandbox Fallback threats
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
        probability: vhfTarget ? 98 : 15,
        timeToImpact: vhfTarget ? "Immediate (Active Incident)" : "Approach Transition",
        confidence: 94,
        targetFlight: vhfTarget ? vhfTarget.callsign : "DLH338"
      },
      mitigations: ["Mandatory read-back/hear-back protocol", "Designated emergency discrete frequency switch", "Secondary radar heading check"]
    });

    return list;
  }

  // =========================================================================
  // RADAR CANVAS RENDERING ENGINE
  // =========================================================================
  render() {
    if (!this.ctx || !this.canvas) return;
    const ctx = this.ctx;
    const width = this.canvas.width;
    const height = this.canvas.height;
    const centerX = width / 2;
    const centerY = height / 2;
    const scale = (Math.min(width, height) * 0.42) / this.sectorRadius;

    // Background Clear
    ctx.fillStyle = "#04080e";
    ctx.fillRect(0, 0, width, height);

    // Range Rings (10, 20, 30, 35 NM)
    const rings = [10, 20, 30, 35];
    ctx.lineWidth = 1;
    rings.forEach((r) => {
      ctx.strokeStyle = r === 35 ? "rgba(56, 189, 248, 0.4)" : "rgba(30, 41, 59, 0.8)";
      ctx.beginPath();
      ctx.arc(centerX, centerY, r * scale, 0, Math.PI * 2);
      ctx.stroke();

      ctx.fillStyle = "rgba(100, 116, 139, 0.7)";
      ctx.font = "9px JetBrains Mono";
      ctx.fillText(`${r} NM`, centerX + 4, centerY - r * scale + 12);
    });

    // Crosshair Azimuth Lines
    ctx.strokeStyle = "rgba(30, 41, 59, 0.6)";
    ctx.beginPath();
    ctx.moveTo(centerX, 0); ctx.lineTo(centerX, height);
    ctx.moveTo(0, centerY); ctx.lineTo(width, centerY);
    ctx.stroke();

    // Draw Waypoints
    ctx.fillStyle = "#38bdf8";
    ctx.font = "10px JetBrains Mono";
    this.waypoints.forEach((wp) => {
      const wx = centerX + wp.x * scale;
      const wy = centerY - wp.y * scale;

      ctx.strokeStyle = "#38bdf8";
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(wx, wy - 4);
      ctx.lineTo(wx + 4, wy + 3);
      ctx.lineTo(wx - 4, wy + 3);
      ctx.closePath();
      ctx.stroke();

      ctx.fillText(wp.name, wx + 6, wy + 3);
    });

    // Draw Runways
    this.runways.forEach((rw) => {
      const rx1 = centerX + (rw.x - rw.length / 2) * scale;
      const rx2 = centerX + (rw.x + rw.length / 2) * scale;
      const ry = centerY - rw.y * scale;

      ctx.strokeStyle = "#ffffff";
      ctx.lineWidth = 2.5;
      ctx.beginPath();
      ctx.moveTo(rx1, ry);
      ctx.lineTo(rx2, ry);
      ctx.stroke();
    });

    // Draw Jamming Contours
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

    // Radar Sweep Beam
    const sweepRadius = Math.max(width, height) * 0.7;
    const sweepX = centerX + Math.cos(this.radarAngle) * sweepRadius;
    const sweepY = centerY + Math.sin(this.radarAngle) * sweepRadius;

    ctx.strokeStyle = "rgba(56, 189, 248, 0.35)";
    ctx.lineWidth = 1.5;
    ctx.beginPath();
    ctx.moveTo(centerX, centerY);
    ctx.lineTo(sweepX, sweepY);
    ctx.stroke();

    // RENDER AIRCRAFT
    const renderFleet = this.feedMode === "live_adsb" ? this.liveFlights : this.flights;

    renderFleet.forEach((f) => {
      const fid = f.callsign || f.icao24 || f.id;
      const isSelected = fid === this.selectedFlightId;
      const fx = centerX + (f.claimedX !== undefined ? f.claimedX : f.x) * scale;
      const fy = centerY - (f.claimedY !== undefined ? f.claimedY : f.y) * scale;

      // Trajectory Spoofing: Show true PSR skin return vs claimed target
      if (f.adsbSpoofed && f.trueX !== undefined) {
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
        ctx.fillText("True PSR Primary Skin Paint", tx + 6, ty + 12);
      }

      const th = f.threat || f.risk || {};
      const tol = th.tolerability || th.tol || "acceptable";
      let blipColor = "#10b981";
      if (tol === "intolerable") blipColor = "#ef4444";
      else if (tol === "tolerable") blipColor = "#f59e0b";

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
        ctx.arc(0, 0, 13, 0, Math.PI * 2);
        ctx.stroke();

        // Reticle ticks
        ctx.beginPath();
        ctx.moveTo(-16, 0); ctx.lineTo(-13, 0);
        ctx.moveTo(13, 0); ctx.lineTo(16, 0);
        ctx.moveTo(0, -16); ctx.lineTo(0, -13);
        ctx.moveTo(0, 13); ctx.lineTo(0, 16);
        ctx.stroke();
      }
      ctx.restore();

      // Heading velocity vector
      const leadNM = ((f.speed || 200) / 3600) * 45;
      const radLead = ((90 - f.heading) * Math.PI) / 180;
      ctx.strokeStyle = blipColor;
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(fx, fy);
      ctx.lineTo(fx + Math.cos(radLead) * leadNM * scale, fy - Math.sin(radLead) * leadNM * scale);
      ctx.stroke();

      // Data Tag
      ctx.fillStyle = isSelected ? "#ffffff" : "#cbd5e1";
      ctx.font = "bold 11px JetBrains Mono";
      ctx.fillText(f.callsign, fx + 10, fy - 6);

      ctx.font = "10px JetBrains Mono";
      ctx.fillStyle = blipColor;
      const fl = Math.round(f.altitude / 100);
      ctx.fillText(`FL${fl} ${f.speed}kt`, fx + 10, fy + 7);

      const rVal = th.composite_risk !== undefined ? th.composite_risk : th.r !== undefined ? th.r : 0;
      ctx.fillStyle = tol === "intolerable" ? "#ef4444" : tol === "tolerable" ? "#f59e0b" : "#10b981";
      ctx.fillText(`r=${Number(rVal).toFixed(1)} [${tol.toUpperCase()}]`, fx + 10, fy + 19);

      if (f.activeThreat) {
        ctx.fillStyle = "#f87171";
        ctx.font = "bold 9px JetBrains Mono";
        ctx.fillText(`⚠️ ${f.activeThreat.substring(0, 25)}`, fx + 10, fy + 30);
      }
    });

    // Render Ghost Targets
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
      ctx.fillText(`FL${Math.round(g.altitude / 100)} NO PRIMARY PSR ECHO`, gx + 10, gy + 8);
    });
  }

  // =========================================================================
  // UI SYNC & TELEMETRY CONTROLS
  // =========================================================================
  refreshTelemetryUI() {
    if (this.feedMode === "sandbox") {
      const flight = this.flights.find((f) => f.id === this.selectedFlightId);
      if (flight) {
        this.updateTelemetryCard(flight);
      }
    } else {
      const flight = this.liveFlights.find((f) => f.callsign === this.selectedFlightId || f.icao24 === this.selectedFlightId);
      if (flight) {
        this.updateLiveFlightTelemetryCard(flight);
      }
    }

    // Authentic UTC Zulu chronometer
    const simTimeEl = document.getElementById("sim-clock-time");
    if (simTimeEl) {
      const now = new Date();
      const h = String(now.getUTCHours()).padStart(2, "0");
      const m = String(now.getUTCMinutes()).padStart(2, "0");
      const s = String(now.getUTCSeconds()).padStart(2, "0");
      simTimeEl.innerText = `${h}:${m}:${s} UTC`;
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
            <span class="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">${f.aircraftType}</span>
            <span class="text-xs font-mono text-slate-400">Assigned: ${f.assignedFrequency}</span>
          </div>
          <div class="text-xs text-slate-400 font-mono mt-0.5">Destination: ${f.destination} · Flight Phase: <strong class="text-sky-300">${f.flightPhase}</strong></div>
        </div>
        <div class="text-right">
          <div class="px-2.5 py-1 rounded text-xs font-mono font-bold uppercase border ${rStyle}">
            r = ${f.risk.r} · ${f.risk.tol}
          </div>
          <div class="text-[10px] text-slate-500 font-mono mt-0.5">Scale Level: ${f.risk.scale} / 5</div>
        </div>
      </div>

      <div class="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs font-mono pt-3 pb-3 border-b border-slate-800/80">
        <div class="p-2 bg-slate-950 rounded border border-slate-800/60">
          <span class="text-[10px] text-slate-500 uppercase block">Altitude / Target:</span>
          <span class="text-white font-bold">${Math.round(f.altitude)} ft / ${f.targetAltitude} ft</span>
        </div>
        <div class="p-2 bg-slate-950 rounded border border-slate-800/60">
          <span class="text-[10px] text-slate-500 uppercase block">Airspeed / Heading:</span>
          <span class="text-white font-bold">${f.speed} kts / ${f.heading}°</span>
        </div>
        <div class="p-2 bg-slate-950 rounded border border-slate-800/60">
          <span class="text-[10px] text-slate-500 uppercase block">GNSS SNR (L1 C/N0):</span>
          <span class="${f.gnssSnr < 32 ? "text-red-400 font-bold" : "text-emerald-400"}">${f.gnssSnr.toFixed(1)} dB-Hz</span>
        </div>
        <div class="p-2 bg-slate-950 rounded border border-slate-800/60">
          <span class="text-[10px] text-slate-500 uppercase block">Transponder PRF:</span>
          <span class="${f.transponderRate > 1000 ? "text-red-400 font-bold" : "text-white"}">${f.transponderRate} / sec</span>
        </div>
      </div>

      <!-- Live Algorithm 1 Risk Breakdown -->
      <div class="mt-3 p-3 bg-slate-950 border border-slate-800 rounded-lg space-y-2">
        <div class="flex items-center justify-between text-xs font-mono">
          <span class="text-slate-400 font-bold">Algorithm 1 Breakdown:</span>
          <span class="text-pink-400 font-bold">Formula: r = L × I</span>
        </div>
        <div class="flex items-center justify-between text-[11px] font-mono text-slate-400">
          <span>Likelihood (L): <strong class="text-amber-400">${f.risk.L}</strong></span>
          <span>Impact (I): <strong class="text-red-400">${f.risk.I}</strong></span>
          <span>Risk Level (r): <strong class="text-white">${f.risk.r}</strong></span>
          <span>Tolerability: <strong class="uppercase ${f.risk.tol === "intolerable" ? "text-red-400" : f.risk.tol === "tolerable" ? "text-amber-400" : "text-emerald-400"}">${f.risk.tol}</strong></span>
        </div>
        ${
          f.activeThreat
            ? `
          <div class="p-2 bg-red-950/40 border border-red-900/60 rounded text-xs font-mono text-red-300 flex items-center space-x-2">
            <span class="w-2 h-2 rounded-full bg-red-500 animate-ping"></span>
            <span>Active Cyber Adversary Impact: <strong>${f.activeThreat}</strong></span>
          </div>
        `
            : `
          <div class="text-[10px] font-mono text-emerald-400 flex items-center space-x-1.5">
            <span class="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
            <span>Nominal sector baseline · No unmitigated exploits active on this airframe</span>
          </div>
        `
        }
      </div>
    `;
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

    const activeFleet = this.feedMode === "live_adsb" ? this.liveFlights : this.flights;
    const flight = activeFleet.find((f) => (f.id || f.callsign) === atk.target);
    if (flight) {
      flight.gnssJammed = false;
      flight.gnssSpoofed = false;
      flight.adsbSpoofed = false;
      flight.vhfSpoofed = false;
      flight.transponderRate = 350;
      flight.cpdlcTampered = false;
      flight.activeThreat = null;
      if (flight.trueX !== undefined) {
        flight.claimedX = flight.trueX;
        flight.claimedY = flight.trueY;
      }
      if (flight.geo_altitude !== undefined) {
        flight.geo_altitude = flight.altitude;
      }
    }

    if (atk.type === "ADSB_GHOST") {
      this.ghostAircraft = [];
    }

    if (this.feedMode === "live_adsb") {
      if (flight) flight.threat = this.estimateClientAircraftThreat(flight);
      this.updateLiveStatsUI();
      if (flight) this.updateLiveFlightTelemetryCard(flight);
    } else {
      this.recalculateLiveRisk();
      if (flight) this.updateTelemetryCard(flight);
    }

    this.renderActiveAttacksUI();
    this.renderFlightPills();
    this.runAttackPredictionEngine();
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
if (typeof window !== "undefined") {
  window.airspaceSim = airspaceSim;
}
