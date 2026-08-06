FROM python:3.12-slim

WORKDIR /app

COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ .

ENV DB_PATH=/data/proxy_events.db
VOLUME ["/data"]

EXPOSE 8098

CMD ["python", "app.py"]
