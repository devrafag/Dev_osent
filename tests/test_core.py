import unittest
from datetime import datetime
from raev_guard.core import Config, Event, analyze, parse_text

class ParserTests(unittest.TestCase):
    def test_valid_line(self):
        events, errors = parse_text("2026-09-02T10:00:00 127.0.0.1 rafael OK /panel")
        self.assertEqual(events[0].username, "rafael")
        self.assertEqual(errors, [])

    def test_invalid_line_is_reported(self):
        events, errors = parse_text("esto no es un log")
        self.assertEqual(events, [])
        self.assertEqual(len(errors), 1)

class RuleTests(unittest.TestCase):
    def test_brute_force_inside_window(self):
        events = [Event(datetime(2026, 9, 2, 10, 0, second), "1.2.3.4",
                        "admin", "FAIL", "/login") for second in range(5)]
        self.assertIn("BRUTE_FORCE", {a.rule for a in analyze(events, Config())})

    def test_spread_out_failures_are_not_brute_force(self):
        events = [Event(datetime(2026, 9, 2, hour), "1.2.3.4",
                        "admin", "FAIL", "/login") for hour in range(5)]
        self.assertNotIn("BRUTE_FORCE", {a.rule for a in analyze(events, Config())})

    def test_sensitive_path(self):
        event = Event(datetime(2026, 9, 2, 12), "1.2.3.4", "x", "FAIL", "/.env")
        self.assertIn("SENSITIVE_PATH_PROBE", {a.rule for a in analyze([event])})

if __name__ == "__main__":
    unittest.main()

