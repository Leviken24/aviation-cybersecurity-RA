"""
Live ADS-B Flight Tracking and Real-Time Cybersecurity Threat Estimator
Queries OpenSky Network API for real-time commercial aircraft passing overhead,
projects them onto the local TRACON sector, and calculates real-time threat scores
using Algorithm 1 (L x I = r) from Elmarady & Rahouma (IEEE Access 2021).
"""

import time
import math
import json
import os
import urllib.request
import urllib.error
from risk_engine import calculate_numeric_risk, categorize_tolerability, convert_to_five_point_scale

# Standard TRACON Airspace Sectors
SECTOR_ZONES = {
    "london": {
        "id": "london",
        "name": "London TMA (EGLL / Heathrow)",
        "center_lat": 51.4700,
        "center_lon": -0.4543,
        "radius_nm": 35.0,
        "bbox": (50.9, -1.3, 52.0, 0.4),  # lamin, lomin, lamax, lomax
        "runway": "27R / 09L",
        "elevation_ft": 83
    },
    "newyork": {
        "id": "newyork",
        "name": "New York TRACON (KJFK / JFK)",
        "center_lat": 40.6413,
        "center_lon": -73.7781,
        "radius_nm": 35.0,
        "bbox": (40.1, -74.5, 41.2, -73.0),
        "runway": "31L / 13R",
        "elevation_ft": 13
    },
    "frankfurt": {
        "id": "frankfurt",
        "name": "Frankfurt TMA (EDDF / FRA)",
        "center_lat": 50.0379,
        "center_lon": 8.5622,
        "radius_nm": 35.0,
        "bbox": (49.5, 7.8, 50.6, 9.3),
        "runway": "25C / 07C",
        "elevation_ft": 364
    },
    "dubai": {
        "id": "dubai",
        "name": "Dubai CTA (OMDB / DXB)",
        "center_lat": 25.2532,
        "center_lon": 55.3657,
        "radius_nm": 35.0,
        "bbox": (24.7, 54.7, 25.8, 56.0),
        "runway": "30L / 12R",
        "elevation_ft": 62
    },
    "tokyo": {
        "id": "tokyo",
        "name": "Tokyo Approach (RJTT / Haneda)",
        "center_lat": 35.5494,
        "center_lon": 139.7798,
        "radius_nm": 35.0,
        "bbox": (35.0, 139.1, 36.1, 140.4),
        "runway": "34L / 16R",
        "elevation_ft": 35
    }
}

# Cache store to respect OpenSky rate limits (10s anonymous cooldown)
_CACHE = {
    "zone": None,
    "timestamp": 0,
    "data": None
}

CACHE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "live_flights_cache.json")


def fetch_opensky_raw(bbox):
    """
    Fetches raw state vectors from OpenSky Network API within bounding box.
    bbox: tuple of (lamin, lomin, lamax, lomax)
    """
    lamin, lomin, lamax, lomax = bbox
    url = f"https://opensky-network.org/api/states/all?lamin={lamin}&lomin={lomin}&lamax={lamax}&lomax={lomax}"
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "AviationCybersecurityResearch/2.0 (IEEE-Access-2021-Algorithm1-Engine)"
        }
    )
    with urllib.request.urlopen(req, timeout=9) as res:
        content = res.read().decode("utf-8")
        return json.loads(content)


def estimate_aircraft_cyber_threat(
    callsign: str,
    country: str,
    alt_ft: int,
    geo_alt_ft: int,
    speed_kts: int,
    vertical_rate_fpm: int,
    dist_nm: float,
    on_ground: bool,
    squawk: str,
    latency_sec: float
):
    """
    Calculates cybersecurity threat level for an actual live flight using Algorithm 1.
    Implements:
      r = L x I (Eq. 1)
      R = { acceptable (r < 5), tolerable (5 <= r < 15), intolerable (r >= 15) } (Eq. 2)
      Scale = 1 to 5 (Table 5)
    """
    anomalies = []

    # 1. Determine Real Flight Phase
    if on_ground or (alt_ft < 120 and speed_kts < 50):
        phase = "Taxi / Ground"
    elif alt_ft < 3000 and vertical_rate_fpm < -150:
        phase = "Final Approach"
    elif alt_ft < 10000 and vertical_rate_fpm < -100:
        phase = "Terminal Approach"
    elif vertical_rate_fpm > 350 and alt_ft < 15000:
        phase = "Climb / Departure"
    else:
        phase = "En-Route Cruise"

    # 2. Real Telemetry Anomaly Checks
    # Barometric vs Geometric altitude discrepancy
    if geo_alt_ft is not None and alt_ft > 500:
        delta_alt = abs(geo_alt_ft - alt_ft)
        if delta_alt > 1500:
            anomalies.append(f"Altimetry Discrepancy: Baro ({alt_ft} ft) vs Geo ({geo_alt_ft} ft) differs by {delta_alt} ft. Potential ADS-B/GNSS drift.")

    # Squawk Code Anomaly Analysis
    if squawk == "7500":
        anomalies.append("CRITICAL SQUAWK 7500: Unlawful Interference / Hijack Code Active!")
    elif squawk == "7600":
        anomalies.append("COMMUNICATION SQUAWK 7600: Radio Link Failure / VHF Jamming Suspected.")
    elif squawk == "7700":
        anomalies.append("EMERGENCY SQUAWK 7700: General In-Flight Emergency Reported.")
    elif not squawk or squawk == "0000":
        anomalies.append("Transponder squawk unassigned or missing Mode 3/A code.")

    # Telemetry Update Latency
    if latency_sec > 12.0:
        anomalies.append(f"Squitter Latency Warning: Last transponder contact was {latency_sec:.1f}s ago (>12s threshold).")

    # 3. Domain 1: VHF Voice Communication Risk
    # In Final Approach / Terminal Approach, VHF AM voice is safety critical without encryption (Paper Sec III)
    if phase == "Final Approach":
        vhf_l = 3.0
        vhf_i = 5.0  # Serious operational impact (CFIT / collision risk)
        vhf_threat = "Rogue ATC Voice Clearance Spoofing (Critical Landing Phase)"
    elif phase == "Terminal Approach":
        vhf_l = 2.5
        vhf_i = 4.0
        vhf_threat = "VHF Voice Clearance Spoofing / Noise Jamming"
    elif phase == "Climb / Departure":
        vhf_l = 2.0
        vhf_i = 3.5
        vhf_threat = "Unauthorized Departure Vectoring"
    else:  # En-Route Cruise
        vhf_l = 1.5
        vhf_i = 3.0
        vhf_threat = "VHF Voice Eavesdropping / Message Jamming"

    vhf_r = calculate_numeric_risk(vhf_l, vhf_i)

    # 4. Domain 2: ADS-B Surveillance Risk (Paper Sec V)
    # Broadcast open 1090 MHz squitters without crypto
    if dist_nm < 15.0 and phase in ["Final Approach", "Terminal Approach"]:
        adsb_l = 4.2  # Readily available SDRs < $1000 (Table 2)
        adsb_i = 3.5  # Major impact on high-density separation
        adsb_threat = "ADS-B Ghost Aircraft Injection / False TCAS Resolution"
    else:
        adsb_l = 3.5
        adsb_i = 2.5
        adsb_threat = "ADS-B Trajectory Spoofing / Squitter Eavesdropping"

    # Escalate if anomaly detected
    if len(anomalies) > 0:
        adsb_l = min(5.0, adsb_l + 0.8)
        adsb_i = min(5.0, adsb_i + 0.8)

    adsb_r = calculate_numeric_risk(adsb_l, adsb_i)

    # 5. Domain 3: GNSS Satellite Navigation Risk (Paper Sec IV)
    if phase in ["Final Approach", "Terminal Approach"]:
        gnss_l = 3.6  # Cheap $50 PPD jammers available
        gnss_i = 4.0  # Approach path disruption
        gnss_threat = "GNSS L1 RF Jamming / Ephemeris Centerline Drift"
    else:
        gnss_l = 3.0
        gnss_i = 2.5
        gnss_threat = "GNSS En-Route Signal Masking"

    gnss_r = calculate_numeric_risk(gnss_l, gnss_i)

    # 6. Composite Threat Calculation (Algorithm 1)
    risks = [
        {"domain": "Communication", "asset": "VHF Voice", "r": vhf_r, "L": vhf_l, "I": vhf_i, "threat": vhf_threat},
        {"domain": "Surveillance", "asset": "ADS-B", "r": adsb_r, "L": adsb_l, "I": adsb_i, "threat": adsb_threat},
        {"domain": "Navigation", "asset": "GNSS", "r": gnss_r, "L": gnss_l, "I": gnss_i, "threat": gnss_threat}
    ]

    # Special emergency override if squawk 7500/7600/7700
    if squawk in ["7500", "7600", "7700"]:
        primary = {
            "domain": "Surveillance & Comms",
            "asset": "Transponder / VHF",
            "r": 20.0,
            "L": 4.0,
            "I": 5.0,
            "threat": f"Emergency Squawk {squawk} Active"
        }
    else:
        primary = max(risks, key=lambda x: x["r"])

    comp_r = primary["r"]
    comp_tol = categorize_tolerability(comp_r)
    comp_scale = convert_to_five_point_scale(comp_r)

    # Prescribed Mitigations from Research Paper
    mitigations = []
    if primary["asset"] == "VHF Voice":
        mitigations = [
            "Mandatory pilot read-back/hear-back protocol",
            "Emergency switch to designated discrete tower frequency",
            "Secondary radar cross-check on issued heading/alt"
        ]
    elif primary["asset"] == "ADS-B":
        mitigations = [
            "Primary Surveillance Radar (PSR) skin-paint echo correlation",
            "TDoA ML multilateration spatial verification",
            "Airborne TCAS collision sensor cross-check"
        ]
    else:  # GNSS
        mitigations = [
            "Multi-frequency L5 GNSS / Galileo authenticated OS-NMA",
            "Inertial Reference System (IRS) fallback dead-reckoning",
            "Terrestrial DME/DME ground fix cross-validation"
        ]

    return {
        "phase": phase,
        "composite_risk": comp_r,
        "tolerability": comp_tol,
        "five_point_scale": comp_scale,
        "primary_asset": primary["asset"],
        "primary_threat": primary["threat"],
        "likelihood": primary["L"],
        "impact": primary["I"],
        "anomalies": anomalies,
        "mitigations": mitigations,
        "domain_breakdown": {
            "vhf_voice": {"r": vhf_r, "L": vhf_l, "I": vhf_i, "tol": categorize_tolerability(vhf_r)},
            "adsb": {"r": adsb_r, "L": adsb_l, "I": adsb_i, "tol": categorize_tolerability(adsb_r)},
            "gnss": {"r": gnss_r, "L": gnss_l, "I": gnss_i, "tol": categorize_tolerability(gnss_r)}
        }
    }


def get_live_sector_flights(zone_key="london", custom_lat=None, custom_lon=None, custom_radius_nm=35.0):
    """
    Fetches real-time aircraft passing overhead in the selected TRACON sector,
    projects their coordinates onto the sector radar grid, and evaluates their
    cybersecurity threat metrics using Algorithm 1.
    """
    global _CACHE

    zone = SECTOR_ZONES.get(zone_key, SECTOR_ZONES["london"])
    c_lat = custom_lat if custom_lat is not None else zone["center_lat"]
    c_lon = custom_lon if custom_lon is not None else zone["center_lon"]
    radius = custom_radius_nm if custom_radius_nm is not None else zone["radius_nm"]
    bbox = zone["bbox"]

    now = time.time()
    raw_data = None

    # Check cache (10s TTL to prevent OpenSky 429 rate limit)
    if _CACHE["zone"] == zone_key and (now - _CACHE["timestamp"] < 10.0) and _CACHE["data"]:
        raw_data = _CACHE["data"]
    else:
        try:
            raw_data = fetch_opensky_raw(bbox)
            _CACHE["zone"] = zone_key
            _CACHE["timestamp"] = now
            _CACHE["data"] = raw_data
            # Save to disk as safety backup
            try:
                with open(CACHE_FILE, "w", encoding="utf-8") as f:
                    json.dump({"zone": zone_key, "timestamp": now, "data": raw_data}, f)
            except Exception:
                pass
        except Exception as e:
            # Fallback to cached state if available
            if _CACHE["data"]:
                raw_data = _CACHE["data"]
            elif os.path.exists(CACHE_FILE):
                try:
                    with open(CACHE_FILE, "r", encoding="utf-8") as f:
                        cached = json.load(f)
                        raw_data = cached.get("data")
                except Exception:
                    pass

    if not raw_data or not raw_data.get("states"):
        return {
            "success": False,
            "zone": zone,
            "flight_count": 0,
            "flights": [],
            "message": "No active aircraft states returned from live ADS-B network."
        }

    states = raw_data.get("states", [])
    flights = []
    server_time = raw_data.get("time", int(now))

    for s in states:
        lon = s[5]
        lat = s[6]
        if lon is None or lat is None:
            continue

        # Coordinate projection onto TRACON Sector (NM)
        # dx: East-West nautical miles from sector center
        # dy: North-South nautical miles from sector center
        dx_nm = (lon - c_lon) * 60.0 * math.cos(c_lat * math.pi / 180.0)
        dy_nm = (lat - c_lat) * 60.0
        dist_nm = math.hypot(dx_nm, dy_nm)

        # Include flights within sector boundary (plus 5 NM transition corridor)
        if dist_nm > (radius + 5.0):
            continue

        icao24 = (s[0] or "").lower()
        callsign = (s[1] or icao24).strip()
        country = s[2] or "Unknown"
        time_pos = s[3] or server_time
        last_contact = s[4] or server_time
        latency_sec = max(0.0, float(server_time - last_contact))

        baro_alt_m = s[7]
        alt_ft = round(baro_alt_m * 3.28084) if baro_alt_m is not None else 0

        on_ground = bool(s[8])

        vel_ms = s[9]
        speed_kts = round(vel_ms * 1.94384) if vel_ms is not None else 0

        track_deg = round(s[10], 1) if s[10] is not None else 0.0

        vert_rate_ms = s[11]
        vert_rate_fpm = round(vert_rate_ms * 196.85) if vert_rate_ms is not None else 0

        geo_alt_m = s[13]
        geo_alt_ft = round(geo_alt_m * 3.28084) if geo_alt_m is not None else None

        squawk = str(s[14] or "----")

        # Algorithm 1 Threat Assessment for this specific aircraft
        threat = estimate_aircraft_cyber_threat(
            callsign=callsign,
            country=country,
            alt_ft=alt_ft,
            geo_alt_ft=geo_alt_ft,
            speed_kts=speed_kts,
            vertical_rate_fpm=vert_rate_fpm,
            dist_nm=dist_nm,
            on_ground=on_ground,
            squawk=squawk,
            latency_sec=latency_sec
        )

        flights.append({
            "icao24": icao24,
            "callsign": callsign,
            "country": country,
            "lat": round(lat, 4),
            "lon": round(lon, 4),
            "x": round(dx_nm, 2),
            "y": round(dy_nm, 2),
            "dist_nm": round(dist_nm, 1),
            "altitude": alt_ft,
            "geo_altitude": geo_alt_ft,
            "speed": speed_kts,
            "heading": track_deg,
            "vertical_rate": vert_rate_fpm,
            "squawk": squawk,
            "on_ground": on_ground,
            "latency_sec": round(latency_sec, 1),
            "threat": threat
        })

    # Sort descending by risk score, then proximity
    flights.sort(key=lambda f: (f["threat"]["composite_risk"], -f["dist_nm"]), reverse=True)

    return {
        "success": True,
        "zone": zone,
        "timestamp": server_time,
        "total_detected": len(states),
        "in_sector_count": len(flights),
        "intolerable_count": sum(1 for f in flights if f["threat"]["tolerability"] == "intolerable"),
        "tolerable_count": sum(1 for f in flights if f["threat"]["tolerability"] == "tolerable"),
        "acceptable_count": sum(1 for f in flights if f["threat"]["tolerability"] == "acceptable"),
        "flights": flights
    }


if __name__ == "__main__":
    res = get_live_sector_flights("london")
    print(f"=== OpenSky Live ADS-B Ingestion for {res['zone']['name']} ===")
    print(f"Total Detected in BBox: {res['total_detected']} | Within 35 NM Sector: {res['in_sector_count']}")
    print(f"Intolerable: {res['intolerable_count']} | Tolerable: {res['tolerable_count']} | Acceptable: {res['acceptable_count']}")
    for f in res["flights"][:6]:
        th = f["threat"]
        print(f"Flight: {f['callsign']:8} | Phase: {th['phase']:16} | Alt: {f['altitude']:5}ft | Spd: {f['speed']:3}kts | Dist: {f['dist_nm']:4.1f}NM | Risk: r={th['composite_risk']:4.1f} ({th['tolerability'].upper()}) | Vector: {th['primary_threat']}")
