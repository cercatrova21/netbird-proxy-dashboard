import ipaddress
import os
import sqlite3
import threading
import time
import json
import logging
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

import requests
from flask import Flask, jsonify, request, render_template

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("netbird-proxy-dashboard")

NB_API_BASE = os.environ.get("NB_API_BASE", "").rstrip("/")
NB_API_TOKEN = os.environ.get("NB_API_TOKEN", "")
POLL_INTERVAL_SECONDS = int(os.environ.get("POLL_INTERVAL_SECONDS", "30"))
INITIAL_BACKFILL_DAYS = int(os.environ.get("INITIAL_BACKFILL_DAYS", "7"))
DB_PATH = os.environ.get("DB_PATH", "/data/proxy_events.db")
RETENTION_DAYS = int(os.environ.get("RETENTION_DAYS", "0"))  # 0 = keine Loeschung
ANOMALY_DENY_THRESHOLD = int(os.environ.get("ANOMALY_DENY_THRESHOLD", "10"))
PRUNE_INTERVAL_SECONDS = 3600
STATS_CACHE_SECONDS = int(os.environ.get("STATS_CACHE_SECONDS", "20"))

if not NB_API_BASE or not NB_API_TOKEN:
    log.warning(
        "NB_API_BASE oder NB_API_TOKEN ist nicht gesetzt - der Poller kann keine Daten abrufen."
    )

app = Flask(__name__)

# ---------------------------------------------------------------------------
# DB
# ---------------------------------------------------------------------------

_db_lock = threading.Lock()

# /api/stats runs ~15 GROUP BY aggregates over a growing events table (each
# 100ms-1s on its own); with the 30s auto-refresh and several browser tabs,
# the same (range + filters) query was being recomputed from scratch every
# few seconds. A short TTL cache collapses those into one computation per
# cycle - dashboard data doesn't need to be fresher than the poller anyway.
_stats_cache = {}
_stats_cache_lock = threading.Lock()


def cached(key, compute_fn):
    now = time.monotonic()
    with _stats_cache_lock:
        entry = _stats_cache.get(key)
        if entry and (now - entry[0]) < STATS_CACHE_SECONDS:
            return entry[1]
    result = compute_fn()
    with _stats_cache_lock:
        if len(_stats_cache) > 300:  # crude cap against unbounded growth from odd filter combos
            _stats_cache.clear()
        _stats_cache[key] = (now, result)
    return result


def get_conn():
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS proxy_events (
            id TEXT PRIMARY KEY,
            service_id TEXT,
            timestamp TEXT NOT NULL,
            method TEXT,
            host TEXT,
            path TEXT,
            duration_ms INTEGER,
            status_code INTEGER,
            source_ip TEXT,
            reason TEXT,
            user_id TEXT,
            auth_method_used TEXT,
            country_code TEXT,
            city_name TEXT,
            subdivision_code TEXT,
            bytes_upload INTEGER,
            bytes_download INTEGER,
            protocol TEXT,
            metadata TEXT
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON proxy_events(timestamp)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_country ON proxy_events(country_code)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_host ON proxy_events(host)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_source_ip ON proxy_events(source_ip)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_user_id ON proxy_events(user_id)")
    # Deckt die "neues Land"-Anomalie-Query ab: MIN(timestamp) GROUP BY country_code
    # kann so per Index-Skip pro Gruppe beantwortet werden statt die Tabelle voll zu scannen.
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_country_ts ON proxy_events(country_code, timestamp)")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS sync_state (
            key TEXT PRIMARY KEY,
            value TEXT
        )
        """
    )
    conn.commit()
    conn.close()


def get_sync_state(key, default=None):
    conn = get_conn()
    row = conn.execute("SELECT value FROM sync_state WHERE key = ?", (key,)).fetchone()
    conn.close()
    return row["value"] if row else default


def set_sync_state(key, value):
    with _db_lock:
        conn = get_conn()
        conn.execute(
            """
            INSERT INTO sync_state (key, value) VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            (key, value),
        )
        conn.commit()
        conn.close()


def insert_events(events):
    if not events:
        return
    with _db_lock:
        conn = get_conn()
        conn.executemany(
            """
            INSERT OR IGNORE INTO proxy_events (
                id, service_id, timestamp, method, host, path, duration_ms, status_code,
                source_ip, reason, user_id, auth_method_used, country_code, city_name,
                subdivision_code, bytes_upload, bytes_download, protocol, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    e.get("id"),
                    e.get("service_id"),
                    e.get("timestamp"),
                    e.get("method"),
                    e.get("host"),
                    e.get("path"),
                    e.get("duration_ms"),
                    e.get("status_code"),
                    e.get("source_ip"),
                    e.get("reason"),
                    e.get("user_id"),
                    e.get("auth_method_used"),
                    e.get("country_code"),
                    e.get("city_name"),
                    e.get("subdivision_code"),
                    e.get("bytes_upload"),
                    e.get("bytes_download"),
                    e.get("protocol"),
                    json.dumps(e.get("metadata")) if e.get("metadata") is not None else None,
                )
                for e in events
            ],
        )
        conn.commit()
        conn.close()


def prune_old_events():
    """Loescht Events aelter als RETENTION_DAYS. Wird aus dem Poller-Loop
    heraus aufgerufen, aber via sync_state auf max. 1x/Stunde gedrosselt,
    damit nicht jeder Poll-Zyklus (Default alle 30s) einen DELETE-Scan macht.
    """
    if RETENTION_DAYS <= 0:
        return
    last_prune = get_sync_state("last_prune_at")
    now = datetime.now(timezone.utc)
    if last_prune:
        try:
            elapsed = (now - datetime.fromisoformat(last_prune)).total_seconds()
            if elapsed < PRUNE_INTERVAL_SECONDS:
                return
        except ValueError:
            pass

    cutoff = (now - timedelta(days=RETENTION_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    with _db_lock:
        conn = get_conn()
        cur = conn.execute("DELETE FROM proxy_events WHERE timestamp < ?", (cutoff,))
        deleted = cur.rowcount
        conn.commit()
        conn.close()
    set_sync_state("last_prune_at", now.isoformat())
    if deleted:
        log.info("Aufbewahrung: %d Events aelter als %d Tage geloescht", deleted, RETENTION_DAYS)


# ---------------------------------------------------------------------------
# NetBird API polling
# ---------------------------------------------------------------------------


def fetch_page(start_date, page):
    url = f"{NB_API_BASE}/api/events/proxy"
    headers = {"Accept": "application/json", "Authorization": f"Token {NB_API_TOKEN}"}
    params = {
        "start_date": start_date,
        "sort_by": "timestamp",
        "sort_order": "asc",
        "page": page,
        "page_size": 100,
    }
    resp = requests.get(url, headers=headers, params=params, timeout=30)
    resp.raise_for_status()
    return resp.json()


def poll_once():
    last_ts = get_sync_state("last_timestamp")
    if not last_ts:
        start = datetime.now(timezone.utc) - timedelta(days=INITIAL_BACKFILL_DAYS)
        last_ts = start.strftime("%Y-%m-%dT%H:%M:%SZ")
        log.info("Kein Sync-Status gefunden, starte Backfill ab %s", last_ts)

    page = 1
    newest_ts = last_ts
    total_new = 0
    max_pages_per_cycle = 500  # Sicherheitsnetz gegen Endlosschleifen

    while page <= max_pages_per_cycle:
        try:
            data = fetch_page(last_ts, page)
        except requests.RequestException as exc:
            log.error("Fehler beim Abruf von Seite %d (NetBird Proxy Events): %s", page, exc)
            break  # Fortschritt der vorherigen Seiten wurde bereits gespeichert

        events = data.get("data", [])

        try:
            if events:
                insert_events(events)
                total_new += len(events)
                newest_ts = events[-1]["timestamp"]
                # Fortschritt SOFORT sichern, nicht erst am Ende der ganzen Pagination.
                # Damit geht bei einem Abbruch auf einer spaeteren Seite nichts verloren.
                set_sync_state("last_timestamp", newest_ts)
        except Exception:
            log.exception("Fehler beim Verarbeiten von Seite %d - breche diesen Zyklus ab", page)
            break

        total_pages = data.get("total_pages", 1)
        if page >= total_pages or not events:
            break
        page += 1
    else:
        log.warning(
            "max_pages_per_cycle (%d) erreicht - es gibt vermutlich mehr Backlog als in einem "
            "Zyklus verarbeitet werden kann. Naechster Zyklus setzt automatisch dort fort.",
            max_pages_per_cycle,
        )

    if total_new:
        log.info("%d neue Proxy-Events synchronisiert (bis %s)", total_new, newest_ts)


def poller_loop():
    while True:
        if NB_API_BASE and NB_API_TOKEN:
            try:
                poll_once()
            except Exception:
                log.exception("Unerwarteter Fehler im Poller")
        try:
            prune_old_events()
        except Exception:
            log.exception("Unerwarteter Fehler beim Pruning")
        time.sleep(POLL_INTERVAL_SECONDS)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

RANGE_TO_DELTA = {
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
    "all": None,
}


def range_cutoff(range_key):
    delta = RANGE_TO_DELTA.get(range_key, RANGE_TO_DELTA["24h"])
    if delta is None:
        return None
    return (datetime.now(timezone.utc) - delta).strftime("%Y-%m-%dT%H:%M:%SZ")


BUCKET_CONDITIONS = {
    "2xx": "(status_code >= 200 AND status_code < 300)",
    "3xx": "(status_code >= 300 AND status_code < 400)",
    "4xx": "(status_code >= 400 AND status_code < 500)",
    "5xx": "(status_code >= 500)",
    "n/a": "(status_code IS NULL)",
    "sonstige": "(status_code IS NOT NULL AND status_code < 200)",
}


def status_bucket(status_code):
    """Python-Gegenstueck zu BUCKET_CONDITIONS - fuer die Status-Verteilung
    in _compute_stats, wo Zeilen bereits in Python vorliegen statt per SQL
    CASE WHEN gebucketed zu werden. Muss mit BUCKET_CONDITIONS in Sync bleiben."""
    if status_code is None:
        return "n/a"
    if 200 <= status_code < 300:
        return "2xx"
    if 300 <= status_code < 400:
        return "3xx"
    if 400 <= status_code < 500:
        return "4xx"
    if status_code >= 500:
        return "5xx"
    return "sonstige"

# Placeholder labels used in GROUP BY panels for NULL/empty values (see api_stats).
# Clicking one of those bars must still filter correctly, hence the special-casing below.
UNKNOWN_HOST_LABEL = "(unbekannt)"
UNKNOWN_COUNTRY_LABEL = "??"
UNKNOWN_CITY_LABEL = "(unbekannt)"

# NetBird liefert fuer Requests von privaten LAN-IPs (192.168.x, 10.x, ...) kein
# GeoIP country_code/city_name, weil sich private Adressen nicht geolokalisieren
# lassen. Ohne Sonderbehandlung landen diese Events in denselben "unbekannt"-Buckets
# wie echte GeoIP-Ausfaelle bei oeffentlichen IPs - das macht die beiden Faelle im
# Dashboard ununterscheidbar. Eigene Labels, damit klar ist: das ist internes LAN.
INTERNAL_COUNTRY_LABEL = "LAN"
INTERNAL_CITY_LABEL = "Internes Netzwerk (LAN)"

# SQL-Gegenstueck zu is_private_ip() - deckt RFC1918 (10/8, 172.16/12, 192.168/16),
# Loopback und Link-Local ab, damit Klicks auf einen "LAN"/"unbekannt"-Balken serverseitig
# dieselbe Menge an Events treffen wie die Python-seitige Zuordnung unten.
_PRIVATE_IP_SQL = (
    "(source_ip LIKE '10.%' OR source_ip LIKE '192.168.%' OR "
    + " OR ".join(f"source_ip LIKE '172.{i}.%'" for i in range(16, 32))
    + " OR source_ip LIKE '127.%' OR source_ip LIKE '169.254.%'"
    " OR source_ip = '::1' OR source_ip LIKE 'fe80:%'"
    " OR source_ip LIKE 'fc%' OR source_ip LIKE 'fd%')"
)


def is_private_ip(ip):
    """True fuer RFC1918/Loopback/Link-Local-Adressen. Muss mit _PRIVATE_IP_SQL
    in Sync bleiben, da beide dieselben Events als "intern" markieren sollen."""
    if not ip:
        return False
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def label_country(raw_country, source_ip):
    if raw_country:
        return raw_country
    return INTERNAL_COUNTRY_LABEL if is_private_ip(source_ip) else UNKNOWN_COUNTRY_LABEL


def label_city(raw_city, source_ip):
    if raw_city:
        return raw_city
    return INTERNAL_CITY_LABEL if is_private_ip(source_ip) else UNKNOWN_CITY_LABEL


def apply_common_filters(args, where_clauses, params):
    """Cross-filter conditions shared by /api/stats and /api/events.

    Kept in one place so clicking a chart segment or table cell filters
    every panel identically, Grafana-style.
    """
    host = args.get("host", "").strip()
    country = args.get("country", "").strip()
    ip = args.get("ip", "").strip()
    status = args.get("status", "").strip()  # allowed/denied (reason-based)
    bucket = args.get("bucket", "").strip()  # 2xx/3xx/4xx/5xx/n/a (status_code-based)
    reason = args.get("reason", "").strip()
    path = args.get("path", "").strip()
    user_id = args.get("user_id", "").strip()
    city = args.get("city", "").strip()

    if host:
        if host == UNKNOWN_HOST_LABEL:
            where_clauses.append("(host IS NULL OR host = '')")
        else:
            where_clauses.append("host = ?")
            params.append(host)
    if country:
        if country == INTERNAL_COUNTRY_LABEL:
            where_clauses.append(f"((country_code IS NULL OR country_code = '') AND {_PRIVATE_IP_SQL})")
        elif country == UNKNOWN_COUNTRY_LABEL:
            where_clauses.append(f"((country_code IS NULL OR country_code = '') AND NOT {_PRIVATE_IP_SQL})")
        else:
            where_clauses.append("country_code = ?")
            params.append(country)
    if ip:
        where_clauses.append("source_ip = ?")
        params.append(ip)
    if status == "denied":
        where_clauses.append("(reason IS NOT NULL AND reason != '')")
    elif status == "allowed":
        where_clauses.append("(reason IS NULL OR reason = '')")
    if bucket in BUCKET_CONDITIONS:
        where_clauses.append(BUCKET_CONDITIONS[bucket])
    if reason:
        where_clauses.append("reason = ?")
        params.append(reason)
    if path:
        where_clauses.append("path = ?")
        params.append(path)
    if user_id:
        where_clauses.append("user_id = ?")
        params.append(user_id)
    if city:
        if city == INTERNAL_CITY_LABEL:
            where_clauses.append(f"((city_name IS NULL OR city_name = '') AND {_PRIVATE_IP_SQL})")
        elif city == UNKNOWN_CITY_LABEL:
            where_clauses.append(f"((city_name IS NULL OR city_name = '') AND NOT {_PRIVATE_IP_SQL})")
        else:
            where_clauses.append("city_name = ?")
            params.append(city)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/healthz")
def healthz():
    return jsonify(status="ok")


@app.route("/api/stats")
def api_stats():
    return jsonify(cached(request.full_path, lambda: _compute_stats(request.args)))


def _compute_stats(args):
    range_key = args.get("range", "24h")
    cutoff = range_cutoff(range_key)
    conn = get_conn()

    where_clauses = []
    params = []
    if cutoff:
        where_clauses.append("timestamp >= ?")
        params.append(cutoff)
    apply_common_filters(args, where_clauses, params)

    where = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    # One scan of the filtered rows, aggregated in Python, instead of ~15
    # separate GROUP BY queries that each re-scanned the same rowset - on a
    # wide range (7d/30d/all) that used to add up to several seconds/request.
    # Plain tuples here, not the connection's usual sqlite3.Row: named-key
    # access on a Row costs roughly as much as the fetch itself at this scale
    # (~260k rows x 13 columns), which defeated the point of a single scan.
    conn.row_factory = None
    rows = conn.execute(
        f"""
        SELECT country_code, host, path, city_name, source_ip, duration_ms,
               bytes_upload, bytes_download, reason, user_id, auth_method_used,
               status_code, timestamp
        FROM proxy_events {where}
        """,
        params,
    ).fetchall()
    conn.row_factory = sqlite3.Row

    countries, hosts, paths, cities, ips = Counter(), Counter(), Counter(), Counter(), Counter()
    users, auth_methods_c, reasons_c, status_buckets_c = Counter(), Counter(), Counter(), Counter()
    denies_by_ip = Counter()
    traffic_by_host = defaultdict(lambda: [0, 0])
    hourly_count = Counter()
    hourly_duration_sum, hourly_duration_n = defaultdict(int), defaultdict(int)
    durations = []
    slowest = []  # (duration_ms, timestamp, host, path, status_code, source_ip)
    denied = 0
    traffic_upload_total = traffic_download_total = 0

    for (raw_country, raw_host, path, raw_city, source_ip, duration_ms,
         bytes_upload, bytes_download, reason, user_id, auth_method_used,
         status_code, timestamp) in rows:
        country_code = label_country(raw_country, source_ip)
        host = raw_host or UNKNOWN_HOST_LABEL
        city = label_city(raw_city, source_ip)
        bucket = timestamp[:13] + ":00:00Z"

        countries[country_code] += 1
        hosts[host] += 1
        paths[(host, path)] += 1
        cities[(city, country_code)] += 1
        if source_ip is not None:
            ips[source_ip] += 1

        up, down = bytes_upload or 0, bytes_download or 0
        host_traffic = traffic_by_host[host]
        host_traffic[0] += up
        host_traffic[1] += down
        traffic_upload_total += up
        traffic_download_total += down

        if user_id:
            users[user_id] += 1
        if auth_method_used:
            auth_methods_c[auth_method_used] += 1
        if reason:
            denied += 1
            reasons_c[reason] += 1
            denies_by_ip[source_ip] += 1

        status_buckets_c[status_bucket(status_code)] += 1
        hourly_count[bucket] += 1

        if duration_ms is not None:
            durations.append(duration_ms)
            hourly_duration_sum[bucket] += duration_ms
            hourly_duration_n[bucket] += 1
            slowest.append((duration_ms, timestamp, raw_host, path, status_code, source_ip))

    total_requests = len(rows)
    unique_ips = len(ips)

    durations.sort()
    n = len(durations)

    def pct(p):
        return durations[min(int(n * p), n - 1)] if n else None

    latency_p50, latency_p95 = pct(0.5), pct(0.95)
    latency_avg = (sum(durations) / n) if n else None

    slowest.sort(key=lambda x: x[0], reverse=True)
    slowest_events = [
        {"timestamp": ts, "host": h, "path": p, "duration_ms": d, "status_code": sc, "source_ip": ip}
        for d, ts, h, p, sc, ip in slowest[:15]
    ]

    timeseries = [{"bucket": b, "c": c} for b, c in sorted(hourly_count.items())]
    latency_timeseries = [
        {"bucket": b, "avg_ms": hourly_duration_sum[b] / hourly_duration_n[b]}
        for b in sorted(hourly_duration_n)
    ]

    traffic_hosts = sorted(
        ({"host": h, "bytes_upload": u, "bytes_download": down} for h, (u, down) in traffic_by_host.items()),
        key=lambda x: x["bytes_upload"] + x["bytes_download"],
        reverse=True,
    )[:10]

    anomalies = []
    if range_key != "all" and cutoff:
        # "Neu" heisst: die fruehesten jemals gesehenen Requests dieses Landes
        # liegen innerhalb des gewaehlten Zeitfensters. Das ist ein globales
        # Erst-Auftreten-Signal ueber die GESAMTE Historie (nicht nur die oben
        # gefetchten, bereits gefilterten Zeilen), bleibt daher eine eigene
        # Query (bei range=all waere jedes Land trivial "neu", daher ausgenommen).
        new_countries = conn.execute(
            """
            SELECT country_code, MIN(timestamp) first_seen, COUNT(*) c
            FROM proxy_events
            WHERE country_code IS NOT NULL AND country_code != ''
            GROUP BY country_code
            HAVING first_seen >= ?
            ORDER BY first_seen ASC
            LIMIT 10
            """,
            [cutoff],
        ).fetchall()
        for r in new_countries:
            anomalies.append({
                "type": "new_country",
                "country_code": r["country_code"],
                "first_seen": r["first_seen"],
                "count": r["c"],
            })

    for ip, c in denies_by_ip.most_common(10):
        if c >= ANOMALY_DENY_THRESHOLD:
            anomalies.append({"type": "ip_deny_spike", "source_ip": ip, "count": c})

    conn.close()

    return dict(
        total_requests=total_requests,
        unique_ips=unique_ips,
        denied=denied,
        countries=[{"country_code": k, "c": v} for k, v in countries.most_common(15)],
        hosts=[{"host": k, "c": v} for k, v in hosts.most_common(10)],
        status_buckets=[{"bucket": k, "c": v} for k, v in status_buckets_c.items()],
        reasons=[{"reason": k, "c": v} for k, v in reasons_c.most_common(10)],
        timeseries=timeseries,
        traffic_hosts=traffic_hosts,
        traffic_total=dict(bytes_upload=traffic_upload_total, bytes_download=traffic_download_total),
        top_users=[{"user_id": k, "c": v} for k, v in users.most_common(10)],
        auth_methods=[{"auth_method_used": k, "c": v} for k, v in auth_methods_c.most_common(10)],
        top_paths=[{"host": h, "path": p, "c": v} for (h, p), v in paths.most_common(10)],
        top_cities=[{"city_name": c, "country_code": cc, "c": v} for (c, cc), v in cities.most_common(10)],
        top_ips=[{"source_ip": k, "c": v} for k, v in ips.most_common(10)],
        latency=dict(p50=latency_p50, p95=latency_p95, avg=latency_avg),
        latency_timeseries=latency_timeseries,
        slowest_events=slowest_events,
        anomalies=anomalies,
    )


@app.route("/api/events")
def api_events():
    range_key = request.args.get("range", "24h")
    cutoff = range_cutoff(range_key)
    search = request.args.get("search", "").strip()
    limit = min(int(request.args.get("limit", "200")), 500)

    where_clauses = []
    params = []
    if cutoff:
        where_clauses.append("timestamp >= ?")
        params.append(cutoff)
    if search:
        where_clauses.append("(host LIKE ? OR path LIKE ? OR source_ip LIKE ? OR user_id LIKE ?)")
        like = f"%{search}%"
        params.extend([like, like, like, like])
    apply_common_filters(request.args, where_clauses, params)

    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    conn = get_conn()
    rows = conn.execute(
        f"""
        SELECT timestamp, method, host, path, status_code, duration_ms, source_ip,
               country_code, city_name, user_id, auth_method_used, reason, protocol
        FROM proxy_events
        {where_sql}
        ORDER BY timestamp DESC
        LIMIT ?
        """,
        params + [limit],
    ).fetchall()
    conn.close()

    events = []
    for r in rows:
        e = dict(r)
        e["country_code"] = label_country(e["country_code"], e["source_ip"])
        e["city_name"] = label_city(e["city_name"], e["source_ip"])
        events.append(e)

    return jsonify(events=events)


@app.route("/api/poller-status")
def api_poller_status():
    conn = get_conn()
    total_events = conn.execute("SELECT COUNT(*) c FROM proxy_events").fetchone()["c"]
    conn.close()

    last_timestamp = get_sync_state("last_timestamp")
    lag_seconds = None
    if last_timestamp:
        try:
            last_dt = datetime.fromisoformat(last_timestamp.replace("Z", "+00:00"))
            lag_seconds = max(0, (datetime.now(timezone.utc) - last_dt).total_seconds())
        except ValueError:
            pass

    return jsonify(
        last_timestamp=last_timestamp,
        lag_seconds=lag_seconds,
        total_events=total_events,
        retention_days=RETENTION_DAYS,
        poller_configured=bool(NB_API_BASE and NB_API_TOKEN),
    )


if __name__ == "__main__":
    init_db()
    t = threading.Thread(target=poller_loop, daemon=True)
    t.start()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8098")))
