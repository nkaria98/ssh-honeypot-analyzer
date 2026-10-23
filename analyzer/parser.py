"""Parse SSH authentication logs and extract failed login attempts."""

import re
import sys
from dataclasses import dataclass

# A regular expression (regex) describes the *shape* of a line of text.
# re.compile() builds the pattern once so Python can reuse it for every line.
#
# Example line this pattern should match:
#   Oct 12 03:14:09 server sshd[1236]: Failed password for invalid user admin from 198.51.100.23 port 40022 ssh2
#
# Named groups, written (?P<name>...), let us fetch the pieces by name later.
FAILED_LOGIN = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d+\s[\d:]{8})"    # "Oct 12 03:14:09"
    r".*?sshd\[\d+\]: Failed password for "     # fixed text; the process id is skipped
    r"(?:invalid user )?"                       # optional text, not captured
    r"(?P<username>\S+) "                       # one or more non-space characters
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) "    # an IPv4 address
    r"port (?P<port>\d+)"                       # the source port
)


@dataclass
class FailedLogin:
    """One failed login attempt. A dataclass is a simple container for related values."""

    timestamp: str
    username: str
    ip: str
    port: int


def parse_line(line: str) -> FailedLogin | None:
    """Return a FailedLogin if the line is a failed SSH login, otherwise None."""
    match = FAILED_LOGIN.search(line)
    if match is None:
        return None  # not a failed login (e.g. "Accepted password" or a session line)
    return FailedLogin(
        timestamp=match.group("timestamp"),
        username=match.group("username"),
        ip=match.group("ip"),
        port=int(match.group("port")),  # regex gives text, so convert to a number
    )


def parse_file(path: str) -> list[FailedLogin]:
    """Read a log file and return every failed login found in it."""
    results = []
    # "with" closes the file automatically, even if an error happens.
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:  # reads one line at a time, which is memory-friendly for big logs
            attempt = parse_line(line)
            if attempt is not None:
                results.append(attempt)
    return results


def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: python -m analyzer.parser <logfile>")
        sys.exit(1)

    attempts = parse_file(sys.argv[1])
    print(f"Found {len(attempts)} failed login attempts\n")
    for a in attempts:
        print(f"{a.timestamp}  {a.ip:<15}  user={a.username}")


# This block only runs when the file is started directly, not when imported.
if __name__ == "__main__":
    main()
