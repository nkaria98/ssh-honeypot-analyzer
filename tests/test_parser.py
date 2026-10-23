"""Tests for analyzer/parser.py.

A test is a small function that runs our code with a known input and checks
that the output is what we expect. If it isn't, the test fails and tells us.
"""

import unittest
from pathlib import Path

from analyzer.parser import parse_file, parse_line

# Path to the sample log, built from this file's location so the tests work
# no matter which folder they are started from.
SAMPLE_LOG = Path(__file__).parent.parent / "sample_data" / "auth.log"


class TestParseLine(unittest.TestCase):
    def test_failed_login_for_existing_user(self):
        line = "Oct 12 03:14:07 server sshd[1234]: Failed password for root from 203.0.113.5 port 52144 ssh2"
        result = parse_line(line)
        self.assertIsNotNone(result)
        self.assertEqual(result.timestamp, "Oct 12 03:14:07")
        self.assertEqual(result.username, "root")
        self.assertEqual(result.ip, "203.0.113.5")
        self.assertEqual(result.port, 52144)

    def test_failed_login_for_invalid_user(self):
        # "invalid user" must not end up as part of the username
        line = "Oct 12 03:14:14 server sshd[1236]: Failed password for invalid user admin from 198.51.100.23 port 40022 ssh2"
        result = parse_line(line)
        self.assertEqual(result.username, "admin")
        self.assertEqual(result.ip, "198.51.100.23")

    def test_port_is_a_number_not_text(self):
        line = "Oct 12 03:14:07 server sshd[1234]: Failed password for root from 203.0.113.5 port 52144 ssh2"
        self.assertIsInstance(parse_line(line).port, int)

    def test_successful_login_is_ignored(self):
        line = "Oct 12 08:01:11 server sshd[2001]: Accepted password for neal from 192.168.1.10 port 51000 ssh2"
        self.assertIsNone(parse_line(line))

    def test_unrelated_line_is_ignored(self):
        line = "Oct 12 08:01:12 server sshd[2001]: pam_unix(sshd:session): session opened for user neal"
        self.assertIsNone(parse_line(line))

    def test_empty_line_is_ignored(self):
        self.assertIsNone(parse_line(""))


class TestParseFile(unittest.TestCase):
    def test_sample_log_has_11_failed_logins(self):
        self.assertEqual(len(parse_file(str(SAMPLE_LOG))), 11)


if __name__ == "__main__":
    unittest.main()
