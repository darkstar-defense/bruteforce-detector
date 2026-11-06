import re
import argparse
from collections import Counter
from datetime import datetime
from collections import defaultdict
import csv

parser = argparse.ArgumentParser(description="Detect brute-force SSH login attempts from a log file.")
parser.add_argument("logfile", help="Path to the auth.log file to analyze")
parser.add_argument("--threshold", type=int, default=5, help="Number of failures to trigger an alert")
parser.add_argument("--window", type=int, default=5, help="Time window in minutes")
args = parser.parse_args()

pattern= re.compile(
    r"^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]: "
    r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)"
)

timestamps = defaultdict(list)

with open(args.logfile) as f:
    for line in f:
        m= pattern.search(line)
        if m:
            #failures[m.group(3)] += 1
            ts_str = "2026 " + re.sub(r"\s+", " ", m.group(1))
            ts = datetime.strptime(ts_str, "%Y %b %d %H:%M:%S")
            timestamps[m.group(3)].append(ts)
            
THRESHOLD = args.threshold
WINDOW_MINUTES = args.window
       
flagged_results =[]            
for ip, times in timestamps.items():
    times.sort()
    flagged = False
    for i in range(len(times) - THRESHOLD +1):
        start = times[i]
        end = times[i + THRESHOLD - 1]
        gap = (end - start).total_seconds() / 60
        if gap <= WINDOW_MINUTES:
            flagged = True
            break
    if flagged:
        print(f"ALERT: {ip} had {THRESHOLD}+ failures within {WINDOW_MINUTES} minutes (total {len(times)} failures)")
        flagged_results.append({"ip": ip, "total_failures": len(times), "first_seen": times[0], "last_seen": times[-1]})
    else:
        print(f"{ip}: {len(times)} failures, but not within the {WINDOW_MINUTES}-minute window")
if flagged_results:
    with open("flagged_ips.csv", "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=["ip", "total_failures", "first_seen", "last_seen"])
        writer.writeheader()
        writer.writerows(flagged_results)
    print(f"\nWrote {len(flagged_results)} flagged IP(s) to flagged_ips.csv")
