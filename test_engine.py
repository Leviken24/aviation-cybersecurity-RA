"""
Unit Test Suite for Civil Aviation Cybersecurity Risk Assessment Engine
Validates all equations, tables, criteria, and research findings from:
Elmarady & Rahouma (IEEE Access 2021)
"""

import unittest
from risk_engine import (
    calculate_numeric_risk,
    categorize_tolerability,
    convert_to_five_point_scale,
    run_algorithm_1,
    PAPER_THREATS_DATASET
)

class TestAviationRiskMethodology(unittest.TestCase):

    def test_formula_1_numeric_risk(self):
        """Test Equation (1): r = L x I"""
        self.assertEqual(calculate_numeric_risk(5.0, 5.0), 25.0)
        self.assertEqual(calculate_numeric_risk(1.0, 1.0), 1.0)
        self.assertEqual(calculate_numeric_risk(4.0, 3.0), 12.0)
        self.assertEqual(calculate_numeric_risk(3.0, 5.0), 15.0)
        self.assertEqual(calculate_numeric_risk(4.8, 1.0), 4.8)
        self.assertEqual(calculate_numeric_risk(4.8, 3.0), 14.4)

    def test_formula_2_tolerability_categorization(self):
        """Test Equation (2): Intolerable (>=15), Tolerable (15 > r >= 5), Acceptable (<5)"""
        self.assertEqual(categorize_tolerability(25.0), "intolerable")
        self.assertEqual(categorize_tolerability(15.0), "intolerable")
        self.assertEqual(categorize_tolerability(14.99), "tolerable")
        self.assertEqual(categorize_tolerability(5.0), "tolerable")
        self.assertEqual(categorize_tolerability(4.99), "acceptable")
        self.assertEqual(categorize_tolerability(1.0), "acceptable")

    def test_table_5_conversion_to_five_point_scale(self):
        """Test Table 5 Conversion to 5-point scale"""
        self.assertEqual(convert_to_five_point_scale(25.0), 5)
        self.assertEqual(convert_to_five_point_scale(20.0), 5)
        self.assertEqual(convert_to_five_point_scale(19.9), 4)
        self.assertEqual(convert_to_five_point_scale(15.0), 4)
        self.assertEqual(convert_to_five_point_scale(14.9), 3)
        self.assertEqual(convert_to_five_point_scale(10.0), 3)
        self.assertEqual(convert_to_five_point_scale(9.9), 2)
        self.assertEqual(convert_to_five_point_scale(5.0), 2)
        self.assertEqual(convert_to_five_point_scale(4.9), 1)
        self.assertEqual(convert_to_five_point_scale(1.0), 1)

    def test_paper_core_findings_communication(self):
        """Validate Communication domain findings: VHF Voice highest, CPDLC lowest"""
        summary = run_algorithm_1()
        com_summary = summary["domain_summary"]["Communication"]
        self.assertEqual(com_summary["highest_risk_asset"], "VHF Voice")
        self.assertEqual(com_summary["lowest_risk_asset"], "CPDLC")
        self.assertEqual(com_summary["max_risk"], 15.0)

    def test_paper_core_findings_navigation(self):
        """Validate Navigation domain findings: GNSS highest, ILS/VOR lowest"""
        summary = run_algorithm_1()
        nav_summary = summary["domain_summary"]["Navigation"]
        self.assertEqual(nav_summary["highest_risk_asset"], "GNSS")
        self.assertIn(nav_summary["lowest_risk_asset"], ["VOR", "ILS"])
        self.assertAlmostEqual(nav_summary["max_risk"], 14.4, places=1)

    def test_paper_core_findings_surveillance(self):
        """Validate Surveillance domain findings: ADS-B highest, SSR/MLAT lowest"""
        summary = run_algorithm_1()
        sur_summary = summary["domain_summary"]["Surveillance"]
        self.assertEqual(sur_summary["highest_risk_asset"], "ADS-B")
        self.assertIn(sur_summary["lowest_risk_asset"], ["SSR", "MLAT"])
        self.assertAlmostEqual(sur_summary["max_risk"], 14.7, places=1)

    def test_paper_core_findings_swim(self):
        """Validate SWIM finding: Medium risk level (Tolerable, scale 3)"""
        summary = run_algorithm_1()
        swim_summary = summary["domain_summary"]["Networking"]
        self.assertEqual(swim_summary["highest_risk_asset"], "SWIM")
        self.assertAlmostEqual(swim_summary["max_risk"], 10.5, places=1)

    def test_live_threat_estimation_final_approach(self):
        """Test Algorithm 1 threat estimation on real flight in Final Approach"""
        from live_tracker import estimate_aircraft_cyber_threat
        # Low altitude, descending -> Final approach (VHF Voice Spoofing risk = 15.0 Intolerable)
        threat = estimate_aircraft_cyber_threat(
            callsign="BAW381",
            country="United Kingdom",
            alt_ft=1200,
            geo_alt_ft=1180,
            speed_kts=135,
            vertical_rate_fpm=-650,
            dist_nm=3.5,
            on_ground=False,
            squawk="1200",
            latency_sec=1.2
        )
        self.assertEqual(threat["phase"], "Final Approach")
        self.assertEqual(threat["composite_risk"], 15.0)
        self.assertEqual(threat["tolerability"], "intolerable")
        self.assertEqual(threat["primary_asset"], "VHF Voice")

    def test_live_threat_estimation_altimetry_anomaly(self):
        """Test detection of Baro vs Geo altimetry discrepancy anomaly"""
        from live_tracker import estimate_aircraft_cyber_threat
        # Baro vs Geo difference > 1500 ft (ADS-B spoofing anomaly)
        threat = estimate_aircraft_cyber_threat(
            callsign="GHOST99",
            country="Unknown",
            alt_ft=5000,
            geo_alt_ft=7200,
            speed_kts=250,
            vertical_rate_fpm=0,
            dist_nm=12.0,
            on_ground=False,
            squawk="2000",
            latency_sec=2.0
        )
        self.assertTrue(any("Altimetry Discrepancy" in a for a in threat["anomalies"]))
        self.assertEqual(threat["phase"], "En-Route Cruise")

if __name__ == "__main__":
    unittest.main()
