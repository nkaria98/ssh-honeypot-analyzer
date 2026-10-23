"""Analyze failed SSH logins and print a brute-force report."""

import argparse
from collections import Counter, defaultdict

from analyzer.parser import FailedLogin, parse_file


def count_by_ip(attempts: list[FailedLogin]) -> Counter:
    """Count how many failed attempts each IP address has.

    Counter is a dictionary built for counting: Counter(["a", "b", "a"])
    gives {"a": 2, "b": 1}. We feed it one IP per attempt.
    """
    return Counter(a.ip for a in attempts)


def usernames_by_ip(attempts: list[FailedLogin]) -> dict[str, set[str]]:
    """Collect which different usernames each IP has tried.

    defaultdict(set) creates an empty set automatically the first time we
    see a new IP, so we can call .add() without checking if the key exists.
    A set only keeps unique values, so "root" added 5 times is stored once.
    """
    result = defaultdict(set)
    for a in attempts:
        result[a.ip].add(a.username)
    return result


def describe_attack(usernames: set[str]) -> str:
    """Give a rough label for what the attacker seems to be doing."""
    if len(usernames) == 1:
        return "password guessing against one account"
    return "trying many usernames (account enumeration)"


def build_report(attempts: list[FailedLogin], threshold: int) -> str:
    """Build the report as text. IPs with >= threshold attempts are flagged."""
    counts = count_by_ip(attempts)
    users = usernames_by_ip(attempts)

    lines = [
        f"Total failed logins: {len(attempts)}",
        f"Unique IP addresses: {len(counts)}",
        "",
        f"Suspected brute-force sources (>= {threshold} attempts):",
    ]

    # most_common() returns (ip, count) pairs sorted from highest to lowest count.
    suspects = [(ip, n) for ip, n in counts.most_common() if n >= threshold]
    if not suspects:
        lines.append("  none")
    for ip, n in suspects:
        names = ", ".join(sorted(users[ip]))
        lines.append(f"  {ip:<15}  {n:>3} attempts  users: {names}")
        lines.append(f"  {'':<15}  -> {describe_attack(users[ip])}")

    return "\n".join(lines)


def main() -> None:
    # argparse reads options from the command line and generates --help for free.
    p = argparse.ArgumentParser(description="Report brute-force activity in an SSH log.")
    p.add_argument("logfile", help="path to the auth log")
    p.add_argument("--threshold", type=int, default=3,
                   help="attempts needed to flag an IP (default: 3)")
    args = p.parse_args()

    attempts = parse_file(args.logfile)
    print(build_report(attempts, args.threshold))


if __name__ == "__main__":
    main()
