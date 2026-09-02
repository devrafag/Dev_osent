import unittest
from datetime import datetime, timedelta
from raev_guard.core import Alert, Config, Event, analyze, parse_text
from raev_guard.simulator import evaluate, generate, run

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

    def test_sensitive_path_with_query_string(self):
        event = Event(datetime(2026, 9, 2, 12), "1.2.3.4", "x", "FAIL",
                      "/.env?cache=123")
        self.assertIn("SENSITIVE_PATH_PROBE", {a.rule for a in analyze([event])})

    def test_slow_brute_force(self):
        events = [Event(datetime(2026, 9, 2, 8 + hour // 3, (hour % 3) * 20),
                        "1.2.3.4", "admin", "FAIL", "/login") for hour in range(8)]
        rules = {a.rule for a in analyze(events)}
        self.assertIn("SLOW_BRUTE_FORCE", rules)
        self.assertNotIn("BRUTE_FORCE", rules)

    def test_unrelated_daily_failures_do_not_trigger_slow_rule(self):
        events = [Event(datetime(2026, 9, 2, 8 + hour), "1.2.3.4",
                        f"user{hour}", "FAIL", "/login") for hour in range(8)]
        self.assertNotIn("SLOW_BRUTE_FORCE", {a.rule for a in analyze(events)})

    def test_distributed_attack_is_correlated_across_ips(self):
        events = [Event(datetime(2026, 9, 2, 12) + timedelta(seconds=second * 20),
                        f"198.51.100.{second}", "direccion", "FAIL", "/login")
                  for second in range(6)]
        distributed = [a for a in analyze(events)
                       if a.rule == "DISTRIBUTED_CREDENTIAL_ATTACK"]
        self.assertEqual({a.ip for a in distributed},
                         {f"198.51.100.{second}" for second in range(6)})

class SimulatorTests(unittest.TestCase):
    def test_same_seed_produces_same_events(self):
        self.assertEqual(generate(seed=7).events, generate(seed=7).events)

    def test_all_injected_attacks_are_detected(self):
        scenario, alerts, score = run(seed=42, normal_events=500)
        self.assertEqual(score.true_positives, 14)
        self.assertEqual(score.false_negatives, 0)
        self.assertEqual(score.precision, 1.0)
        self.assertEqual(score.recall, 1.0)

    def test_evaluation_counts_false_positive(self):
        scenario = generate(normal_events=0)
        extra = Alert("HIGH", "TEST", "10.0.0.1", "prueba", "a", "b", 1)
        score = evaluate(scenario, analyze(scenario.events) + [extra])
        self.assertEqual(score.false_positives, 1)

if __name__ == "__main__":
    unittest.main()
