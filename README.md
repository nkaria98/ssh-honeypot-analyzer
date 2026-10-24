# ssh-honeypot-analyzer

A small Python tool that reads SSH authentication logs, finds IP addresses that look like brute-force attackers, and tells you what kind of attack each one is running.

I built it to learn how real SSH attacks look in the logs, and how to turn raw log lines into something a person can act on. It uses only the Python standard library and has automated tests.

## What it does

Any SSH server exposed to the internet gets hit by bots guessing passwords. Every attempt ends up in `auth.log`. This tool:

1. **Parses** the log and extracts every failed login (time, username, IP, port).
2. **Counts** attempts per IP address and which usernames each IP tried.
3. **Flags** IPs at or above a threshold (default: 3 attempts) and labels the pattern:
   - **one username, many attempts**: password guessing against a single account (typically `root`)
   - **many different usernames**: account enumeration, where the attacker is looking for accounts that exist

## Example

```text
$ python -m analyzer.report sample_data/auth.log

Total failed logins: 11
Unique IP addresses: 4

Suspected brute-force sources (>= 3 attempts):
  203.0.113.5        6 attempts  users: root
                   -> password guessing against one account
  198.51.100.23      3 attempts  users: admin, test, ubuntu
                   -> trying many usernames (account enumeration)
```

The IP addresses in `sample_data/auth.log` are from ranges reserved for documentation (RFC 5737), so no real hosts or people are involved.

## Quick start

Requires Python 3.10 or newer. No packages to install.
On Windows use `python`, on Mac/Linux use `python3`.

```bash
git clone https://github.com/nkaria98/ssh-honeypot-analyzer.git
cd ssh-honeypot-analyzer

# Report suspected brute-force sources
python -m analyzer.report sample_data/auth.log

# Change the threshold
python -m analyzer.report sample_data/auth.log --threshold 5

# Just list every failed login
python -m analyzer.parser sample_data/auth.log
```

## Tests

```bash
python -m unittest -v
```

16 tests cover the log parser (valid and invalid users, ignored lines, port conversion) and the report (counting, thresholds, attack classification). The tests use `unittest` from the standard library.

## Project structure

```text
analyzer/
  parser.py     regex-based parser, one FailedLogin per failed attempt
  report.py     counting, flagging and the command-line report
sample_data/
  auth.log      small example log with documentation-range IPs
tests/          unit tests for parser and report
```

## Design notes

- **Standard library only.** `re` for parsing, `collections.Counter` and `defaultdict` for counting, `argparse` for the command line, `unittest` for tests. Nothing to install, nothing to break.
- **Parsing and analysis are separate.** `parser.py` only turns text into data, and `report.py` only works with that data. That makes each part easy to test and lets a future honeypot reuse the same analysis.
- **Real logs stay out of the repo.** `.gitignore` blocks `*.log` except the sample file, since real logs contain real IPs and usernames.

## Limitations

- Only recognises `Failed password` lines from `sshd` (not failed public-key logins or `Invalid user` lines without a password attempt).
- IPv4 only.
- Counts attempts over the whole file. It does not look at time windows, so it cannot tell 3 attempts in a second from 3 attempts in a week.
- Internal addresses (for example `192.168.x.x`) are not filtered out.

## Roadmap

- [x] Log parser
- [x] Brute-force report with attack classification
- [x] Unit tests
- [ ] Filter private/internal IP addresses
- [ ] Time-window detection (many attempts in a short time)
- [ ] SSH honeypot that logs login attempts (run in Docker or on an isolated VPS only)
- [ ] Analyse honeypot data and add a real-world example to this README
