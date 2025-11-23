import json
from collections import Counter
import os

LOG_FILE = os.getenv("LOG_FILE", "logs/ssh_honeypot_logs.jsonl")

usernames = Counter()
passwords = Counter()
commands = Counter()
countries = Counter()

if not os.path.exists(LOG_FILE):
    raise SystemExit(f"Log file not found at {LOG_FILE}")

with open(LOG_FILE, "r", encoding="utf-8") as f:
    for line in f:
        entry = json.loads(line)

        if entry.get("event") == "auth_attempt":
            usernames[entry["username"]] += 1
            passwords[entry["password"]] += 1

        if entry.get("event") == "command":
            commands[entry["command"]] += 1

        geo = entry.get("geoip") or {}
        if geo.get("country_name"):
            countries[geo["country_name"]] += 1

print("\n=== Top Usernames Attempted ===")
for user, count in usernames.most_common(10):
    print(f"{user}: {count}")

print("\n=== Top Passwords Attempted ===")
for pwd, count in passwords.most_common(10):
    print(f"{pwd}: {count}")

print("\n=== Top Commands Executed ===")
for cmd, count in commands.most_common(10):
    print(f"{cmd}: {count}")

print("\n=== Top Source Countries ===")
for c, count in countries.most_common(10):
    print(f"{c}: {count}")
