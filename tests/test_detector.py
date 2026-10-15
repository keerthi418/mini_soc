import unittest
from app.detector import analyze_logs

class DetectorTests(unittest.TestCase):
    def test_brute_force_is_detected(self):
        rows = [
            {"timestamp": f"2026-10-14 09:10:{i:02d}", "username": "admin",
             "source_ip": "203.0.113.44", "event": "login", "status": "failed"}
            for i in range(6)
        ]
        result = analyze_logs(rows)
        self.assertTrue(any("brute-force" in a["title"].lower() for a in result["alerts"]))

    def test_privilege_change_is_detected(self):
        result = analyze_logs([{
            "timestamp": "2026-10-14 10:00:00", "username": "root",
            "source_ip": "192.0.2.9", "event": "privilege_change", "status": "success"
        }])
        self.assertTrue(any(a["title"] == "Privilege change event" for a in result["alerts"]))

    def test_empty_input(self):
        result = analyze_logs([])
        self.assertEqual(result["summary"]["total_logs"], 0)
        self.assertEqual(result["summary"]["total_alerts"], 0)

if __name__ == "__main__":
    unittest.main()
