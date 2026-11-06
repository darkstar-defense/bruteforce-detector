# SSH Brute-Force Detector

A Python command-line tool that detects SSH brute-force attacks by analyzing failed-login timing patterns in syslog data not just raw failure counts.

## Why timing matters

Five failed logins spread across a month isn't suspicious. Five failed logins in five minutes is. This tool parses SSH authentication logs, groups failures by source IP, and uses a sliding time-window check to flag genuine attack bursts while ignoring scattered, ordinary noise.

## How it works

1. Parses `auth.log` lines with a regex that extracts the timestamp, username, and source IP from each failed SSH login (handling both normal and "invalid user" log variants).
2. Groups failure timestamps by IP address.
3. For each IP, slides a window across its sorted timestamps and checks whether N failures occurred within M minutes of each other.
4. Prints an alert for any IP that crosses the threshold, and exports flagged IPs to a CSV report.

## Usage

```
python3 detector.py <logfile> [--threshold N] [--window M]
```

- `--threshold` — number of failures required to trigger an alert (default: 5)
- `--window` — time window in minutes (default: 5)

### Example

```
python3 detector.py sample_auth.log
```

```
ALERT: 203.0.113.55 had 5+ failures within 5 minutes (total 6 failures)
198.51.100.23: 3 failures, but not within the 5-minute window
Wrote 1 flagged IP(s) to flagged_ips.csv
```

## Testing

This tool was built and tested in an isolated Hyper-V lab (an attacker VM and a target VM on a private virtual switch, no connection to any production or home network):

- **True positive test:** ran real Hydra brute-force attacks against a lab SSH server and confirmed the tool correctly flagged the attacking IP.
- **False positive test:** built a clean dataset of scattered, non-bursty failures spread across multiple days and confirmed the tool correctly did *not* flag it.

`sample_auth.log` included in this repo is a sanitized example using RFC 5737 documentation-reserved IP addresses, demonstrating both a flagged burst and a non-flagged scattered pattern.

## MITRE ATT&CK mapping

Maps to **T1110 — Brute Force**.

## Limitations

- Only parses SSH (`sshd`) log entries — not other services.
- Blind to distributed brute-force attempts (many source IPs, each trying only a few times).
- Doesn't currently flag a successful login that follows a burst of failures, which would be a stronger signal of an actual compromise.

## Built with AI-assisted development

I used an AI coding assistant throughout development to help debug regex patterns and work through Python's datetime handling, while independently writing, testing, and validating the core logic and the detection approach itself.
