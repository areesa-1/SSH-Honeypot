# Advanced SSH Honeypot 🎣

A Python-based SSH honeypot that simulates a realistic Linux environment to capture attacker behaviour such as credentials, commands, and geolocation data. Includes Docker support, a log analysis tool, and optional Discord alerting.

## ✨ Features
- Fake interactive SSH shell  
- Logs usernames, passwords, and commands  
- GeoIP enrichment (optional)  
- Discord webhook alerts (optional)  
- Docker container for easy deployment  
- Log analysis tool (`analyse-logs.py`)

## 🛠 Installation

Install dependencies:

```bash
pip install -r requirements.txt
ssh-keygen -t rsa -b 2048 -f honeypot_host_key -N ""
python honeypot.py
docker build -t ssh-honeypot .
docker run -p 2222:2222 ssh-honeypot
python analyse-logs.py
