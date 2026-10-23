"""Tests for analyzer/report.py."""

import unittest

from analyzer.parser import FailedLogin
from analyzer.report import build_report, count_by_ip, describe_attack, usernames_by_ip


def attempt(ip: str, username: str = "root") -> FailedLogin:
    """Small helper that builds a FailedLogin so each test stays short."""
    return FailedLogin(timestamp="Oct 12 03:00:00", username=username, ip=ip, port=22)


class TestCounting(unittest.TestCase):
    def test_count_by_ip(self):
        attempts = [attempt("1.1.1.1"), attempt("1.1.1.1"), attempt("2.2.2.2")]
        counts = count_by_ip(attempts)
        self.assertEqual(counts["1.1.1.1"], 2)
        self.assertEqual(counts["2.2.2.2"], 1)

    def test_count_by_ip_with_no_attempts(self):
        self.assertEqual(len(count_by_ip([])), 0)

    def test_usernames_are_unique_per_ip(self):
        attempts = [attempt("1.1.1.1", "root"), attempt("1.1.1.1", "root"), attempt("1.1.1.1", "admin")]
        self.assertEqual(usernames_by_ip(attempts)["1.1.1.1"], {"root", "admin"})


class TestDescribeAttack(unittest.TestCase):
    def test_one_username_is_password_guessing(self):
        self.assertIn("password guessing", describe_attack({"root"}))

    def test_many_usernames_is_enumeration(self):
        self.assertIn("enumeration", describe_attack({"root", "admin", "test"}))


class TestBuildReport(unittest.TestCase):
    def setUp(self):
        # setUp runs before every test in this class, giving each a fresh copy.
        self.attempts = [attempt("1.1.1.1")] * 5 + [attempt("2.2.2.2")]

    def test_ip_at_threshold_is_flagged(self):
        report = build_report(self.attempts, threshold=5)
        self.assertIn("1.1.1.1", report)

    def test_ip_below_threshold_is_not_flagged(self):
        report = build_report(self.attempts, threshold=5)
        self.assertNotIn("2.2.2.2", report)

    def test_report_says_none_when_nobody_is_flagged(self):
        report = build_report(self.attempts, threshold=100)
        self.assertIn("none", report)

    def test_report_shows_totals(self):
        report = build_report(self.attempts, threshold=3)
        self.assertIn("Total failed logins: 6", report)
        self.assertIn("Unique IP addresses: 2", report)


if __name__ == "__main__":
    unittest.main()
