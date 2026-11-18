FROM python:3.12-slim

WORKDIR /app

# rsync + ssh fuer den Backup-Proxy-Sync (siehe BACKUP_SYNC_* in .env.example)
RUN apt-get update \
    && apt-get install -y --no-install-recommends rsync openssh-client \
    && rm -rf /var/lib/apt/lists/*

COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ .

ENV DB_PATH=/data/proxy_events.db
VOLUME ["/data"]

EXPOSE 8098

CMD ["python", "app.py"]
