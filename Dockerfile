FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ssh && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 2222

ENV LISTEN_HOST=0.0.0.0
ENV LISTEN_PORT=2222
ENV LOG_DIR=logs
ENV LOG_FILE=ssh_honeypot_logs.jsonl

CMD ["python", "honeypot.py"]
