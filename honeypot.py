import socket
import threading
import json
import os
from datetime import datetime

import paramiko
from paramiko import RSAKey, ServerInterface, AUTH_SUCCESSFUL, OPEN_SUCCEEDED

# Optional libraries – enabled via requirements.txt
try:
    import geoip2.database
except ImportError:
    geoip2 = None

try:
    import requests
except ImportError:
    requests = None

# === Configuration ===
HOST_KEY_PATH = os.getenv("HOST_KEY_PATH", "honeypot_host_key")
LOG_DIR = os.getenv("LOG_DIR", "logs")
LOG_FILE = os.getenv("LOG_FILE", "ssh_honeypot_logs.jsonl")
LISTEN_HOST = os.getenv("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.getenv("LISTEN_PORT", "2222"))

GEOIP_DB_PATH = os.getenv("GEOIP_DB_PATH", "geoip/GeoLite2-City.mmdb")
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")  # optional

os.makedirs(LOG_DIR, exist_ok=True)

_geoip_reader = None


def get_geoip_reader():
    """Load GeoIP DB if available."""
    global _geoip_reader
    if _geoip_reader is None and geoip2 is not None and os.path.exists(GEOIP_DB_PATH):
        _geoip_reader = geoip2.database.Reader(GEOIP_DB_PATH)
    return _geoip_reader


def enrich_with_geoip(data: dict, ip: str):
    reader = get_geoip_reader()
    if not reader:
        return data
    try:
        resp = reader.city(ip)
        data["geoip"] = {
            "country_iso": resp.country.iso_code,
            "country_name": resp.country.name,
            "city_name": resp.city.name,
        }
    except Exception:
        pass
    return data


def send_discord_alert(event_type: str, data: dict):
    if not DISCORD_WEBHOOK_URL or not requests:
        return
    try:
        content = (
            f"**SSH Honeypot Alert** – `{event_type}`\n"
            f"IP: `{data.get('source_ip')}`\n"
            f"User: `{data.get('username')}`\n"
            f"Command: `{data.get('command', '')}`"
        )
        requests.post(DISCORD_WEBHOOK_URL, json={"content": content}, timeout=3)
    except Exception:
        pass


def log_event(data: dict):
    data["timestamp"] = datetime.utcnow().isoformat() + "Z"
    ip = data.get("source_ip")
    if ip:
        data = enrich_with_geoip(data, ip)

    with open(os.path.join(LOG_DIR, LOG_FILE), "a", encoding="utf-8") as f:
        f.write(json.dumps(data) + "\n")

    if data.get("event") in {"auth_attempt", "command"}:
        send_discord_alert(data["event"], data)


class HoneypotServer(ServerInterface):
    def __init__(self, client_addr):
        self.client_addr = client_addr
        self.username = None

    def check_auth_password(self, username, password):
        self.username = username
        log_event({
            "event": "auth_attempt",
            "source_ip": self.client_addr[0],
            "source_port": self.client_addr[1],
            "username": username,
            "password": password,
        })
        return AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        log_event({
            "event": "channel_request",
            "source_ip": self.client_addr[0],
            "source_port": self.client_addr[1],
            "channel_type": kind,
        })
        if kind == "session":
            return OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        log_event({
            "event": "shell_requested",
            "source_ip": self.client_addr[0],
            "source_port": self.client_addr[1],
            "username": self.username,
        })
        return True

    def check_channel_pty_request(self, *args, **kwargs):
        return True


def fake_shell(channel, addr, server):
    channel.send("Welcome to Ubuntu 22.04 LTS (GNU/Linux)\r\n")
    channel.send("Type 'help' for available commands.\r\n\r\n")

    prompt = "fakeuser@fakehost:~$ "
    channel.send(prompt)

    buffer = ""

    while True:
        data = channel.recv(1024)
        if not data:
            break

        text = data.decode("utf-8", errors="ignore")

        for ch in text:
            if ch in ("\r", "\n"):
                cmd = buffer.strip()

                if cmd:
                    log_event({
                        "event": "command",
                        "source_ip": addr[0],
                        "source_port": addr[1],
                        "username": server.username,
                        "command": cmd,
                    })

                    if cmd in ("exit", "quit", "logout"):
                        channel.send("logout\r\n")
                        channel.close()
                        return

                    elif cmd == "help":
                        channel.send("Available commands: ls, pwd, whoami, uname -a, cat, exit\r\n")

                    elif cmd == "whoami":
                        channel.send("root\r\n")

                    elif cmd == "pwd":
                        channel.send("/root\r\n")

                    elif cmd == "ls":
                        channel.send("secret.txt  config.cfg  backup.tar.gz  notes.md\r\n")

                    elif cmd.startswith("cat "):
                        filename = cmd.split(" ", 1)[1]
                        if filename == "secret.txt":
                            channel.send("TOP SECRET: This is a honeypot.\r\n")
                        elif filename == "config.cfg":
                            channel.send("db_user=admin\ndb_pass=admin123\r\n")
                        else:
                            channel.send(f"cat: {filename}: No such file\r\n")

                    elif cmd == "uname -a":
                        channel.send("Linux fakehost 5.15.0 x86_64 GNU/Linux\r\n")

                    else:
                        channel.send(f"bash: {cmd}: command not found\r\n")

                buffer = ""
                channel.send(prompt)

            else:
                buffer += ch
                channel.send(ch)


def handle_client(client, addr, host_key):
    transport = paramiko.Transport(client)
    transport.add_server_key(host_key)

    server = HoneypotServer(addr)

    try:
        transport.start_server(server=server)
    except paramiko.SSHException:
        return

    channel = transport.accept(20)
    if channel is None:
        return

    try:
        fake_shell(channel, addr, server)
    except Exception:
        pass
    finally:
        channel.close()
        transport.close()


def main():
    if not os.path.exists(HOST_KEY_PATH):
        raise SystemExit(
            f"Missing host key. Generate it with:\n"
            f"ssh-keygen -t rsa -b 2048 -f {HOST_KEY_PATH} -N \"\""
        )

    host_key = RSAKey(filename=HOST_KEY_PATH)

    sock = socket.socket()
    sock.bind((LISTEN_HOST, LISTEN_PORT))
    sock.listen(100)

    print(f"[+] SSH honeypot listening on {LISTEN_HOST}:{LISTEN_PORT}")

    while True:
        client, addr = sock.accept()
        log_event({
            "event": "connection",
            "source_ip": addr[0],
            "source_port": addr[1],
        })
        threading.Thread(target=handle_client, args=(client, addr, host_key), daemon=True).start()


if __name__ == "__main__":
    main()
