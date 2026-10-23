# ssh-honeypot-analyzer

A small security project in two parts:

1. **analyzer**: reads SSH authentication logs and reports brute-force activity.
2. **honeypot** (planned): a fake SSH service that logs login attempts.

> Work in progress. Done: log parser, brute-force report.

## Quick start

Requires Python 3.10+. On Windows use `python`, on Mac/Linux `python3`.

```bash
# List every failed login
python -m analyzer.parser sample_data/auth.log

# Report suspected brute-force sources (default threshold: 3 attempts)
python -m analyzer.report sample_data/auth.log
python -m analyzer.report sample_data/auth.log --threshold 5
```

## Tests

Uses only the standard library (`unittest`), nothing to install.

```bash
python -m unittest -v
```
