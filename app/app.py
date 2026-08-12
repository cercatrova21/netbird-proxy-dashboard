import ipaddress
import os
import re
import sqlite3
import threading
import time
import json
import logging
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

import docker as docker_sdk
import maxminddb
import requests
import yaml
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

# --- CrowdSec (optional) ---
# Liest Alerts/Entscheidungen der lokalen CrowdSec-Engine, die auch den netbird-proxy
# Bouncer versorgt (dieselbe LAPI, per Machine-Login statt Bouncer-Key, weil nur die
# Machine-Rolle Zugriff auf /v1/alerts inkl. GeoIP/AS-Anreicherung hat - der Bouncer-Key
# sieht nur die blanken, aktiven Decisions ohne Kontext).
CROWDSEC_API_URL = os.environ.get("CROWDSEC_API_URL", "").rstrip("/")
CROWDSEC_MACHINE_ID = os.environ.get("CROWDSEC_MACHINE_ID", "")
CROWDSEC_MACHINE_PASSWORD = os.environ.get("CROWDSEC_MACHINE_PASSWORD", "")
CROWDSEC_CONFIGURED = bool(CROWDSEC_API_URL and CROWDSEC_MACHINE_ID and CROWDSEC_MACHINE_PASSWORD)

# Lokale Whitelist-Datei von netbird-logparser (Postoverflow-Parser) - read-write
# gemountet, damit das Whitelist-Widget Eintraege pflegen kann. Wirksam wird eine
# Aenderung erst nach einem Neustart von WHITELIST_CONTAINER_NAME (CrowdSec liest
# Parser-Config nur beim Start neu ein), siehe /api/crowdsec/whitelist/apply.
WHITELIST_FILE_PATH = os.environ.get("WHITELIST_FILE_PATH", "")
WHITELIST_CONTAINER_NAME = os.environ.get("WHITELIST_CONTAINER_NAME", "netbird-logparser")

# --- ASN-Anreicherung (optional) ---
# Reichert jedes Event um Autonomous-System-Nummer/-Name der Quell-IP an, per
# lokaler MaxMind-GeoLite2-ASN-Datenbank - demselben kostenlosen Download, den
# CrowdSecs eigene Hub-Parser verwenden (kein MaxMind-Account noetig). Bewusst
# per Default AUS: das ist die einzige Integration hier, die selbststaendig
# etwas aus dem Internet nachlaedt, und dieses Repo wird auch als oeffentliches
# Self-Hosting-Template verteilt (siehe crowdsec/README.md) - Selbsthoster ohne
# Interesse an ASN-Daten sollen nicht ungefragt einen neuen externen Download
# bekommen. ASN_MMDB_URL ist bewusst ueberschreibbar, falls der oeffentliche
# CrowdSec-Mirror mal verschwindet und jemand einen eigenen MaxMind-Download nutzen will.
ASN_ENRICHMENT_ENABLED = os.environ.get("ASN_ENRICHMENT_ENABLED", "false").lower() == "true"
ASN_MMDB_URL = os.environ.get(
    "ASN_MMDB_URL", "https://hub-data.crowdsec.net/mmdb_update/GeoLite2-ASN.mmdb"
)
ASN_MMDB_PATH = os.path.join(os.path.dirname(DB_PATH) or ".", "GeoLite2-ASN.mmdb")
ASN_REFRESH_INTERVAL_SECONDS = 7 * 24 * 3600  # woechentlich, wie CrowdSecs eigener Hub-Refresh

if not NB_API_BASE or not NB_API_TOKEN:
    log.warning(
        "NB_API_BASE oder NB_API_TOKEN ist nicht gesetzt - der Poller kann keine Daten abrufen."
    )
if not CROWDSEC_CONFIGURED:
    log.info("CROWDSEC_API_URL/MACHINE_ID/MACHINE_PASSWORD nicht gesetzt - CrowdSec-Integration deaktiviert.")
if ASN_ENRICHMENT_ENABLED:
    log.info("ASN-Anreicherung aktiviert - laedt bei Bedarf %s", ASN_MMDB_URL)

app = Flask(__name__)

# ---------------------------------------------------------------------------
# DB
# ---------------------------------------------------------------------------

_db_lock = threading.Lock()
_whitelist_lock = threading.Lock()  # eigener Lock fuer die YAML-Datei, unabhaengig von _db_lock

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


def migrate_schema(conn):
    """One place for schema changes made after the initial CREATE TABLE -
    idempotent, checked via PRAGMA table_info() rather than a version number
    table, since this is currently the only migration this app has ever needed."""
    existing_columns = {row["name"] for row in conn.execute("PRAGMA table_info(proxy_events)")}
    if "as_number" not in existing_columns:
        conn.execute("ALTER TABLE proxy_events ADD COLUMN as_number TEXT")
    if "as_name" not in existing_columns:
        conn.execute("ALTER TABLE proxy_events ADD COLUMN as_name TEXT")


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
    migrate_schema(conn)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_as_number ON proxy_events(as_number)")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS sync_state (
            key TEXT PRIMARY KEY,
            value TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS crowdsec_alerts (
            alert_id INTEGER PRIMARY KEY,
            decision_id INTEGER,
            created_at TEXT NOT NULL,
            scenario TEXT,
            message TEXT,
            events_count INTEGER,
            source_ip TEXT,
            country_code TEXT,
            as_number TEXT,
            as_name TEXT,
            decision_type TEXT,
            expires_at TEXT
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_crowdsec_created ON crowdsec_alerts(created_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_crowdsec_ip ON crowdsec_alerts(source_ip)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_crowdsec_expires ON crowdsec_alerts(expires_at)")
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


def log_security_event(e):
    """Emits one structured stdout line per denied event, so CrowdSec's docker-log
    acquisition (which already tails netbird-proxy) can also tail this container and
    catch failed logins / sensitive-path scans - the NetBird proxy's own stdout only
    logs actual backend connection errors (502s), never blocked/404 requests, so
    without this CrowdSec had no visibility into denied traffic at all."""
    log.warning(
        'security_event source_ip=%s host=%s method=%s path=%s status=%s reason="%s" user_id=%s',
        e.get("source_ip") or "-",
        e.get("host") or "-",
        e.get("method") or "-",
        e.get("path") or "-",
        e.get("status_code") if e.get("status_code") is not None else "-",
        e.get("reason"),
        e.get("user_id") or "-",
    )


def insert_events(events):
    if not events:
        return
    newly_inserted = []
    with _db_lock:
        conn = get_conn()
        cur = conn.cursor()
        for e in events:
            as_number, as_name = lookup_asn(e.get("source_ip"))
            cur.execute(
                """
                INSERT OR IGNORE INTO proxy_events (
                    id, service_id, timestamp, method, host, path, duration_ms, status_code,
                    source_ip, reason, user_id, auth_method_used, country_code, city_name,
                    subdivision_code, bytes_upload, bytes_download, protocol, metadata,
                    as_number, as_name
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
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
                    as_number,
                    as_name,
                ),
            )
            if cur.rowcount:
                newly_inserted.append(e)
        conn.commit()
        conn.close()

    for e in newly_inserted:
        if e.get("reason"):
            log_security_event(e)


def backfill_asn_data():
    """insert_events() only enriches NEW events going forward - without this,
    historical rows (and therefore 'Top ASNs' for anything wider than a fresh
    install) would stay blank for a long time. Runs once at startup in its
    own thread; a cheap no-op on every later restart once everything's
    filled in. Deduped to unique source_ip first (a handful of thousand, not
    every row) and updated via the existing source_ip index, so it doesn't
    need a full-table scan - small per-IP transactions under _db_lock rather
    than one lock for the whole run, so it doesn't starve the poller."""
    if not ASN_ENRICHMENT_ENABLED:
        return
    try:
        conn = get_conn()
        ips = [
            r["source_ip"]
            for r in conn.execute(
                "SELECT DISTINCT source_ip FROM proxy_events WHERE as_number IS NULL AND source_ip IS NOT NULL"
            )
        ]
        if not ips:
            conn.close()
            return
        log.info("ASN-Backfill: %d eindeutige Quell-IPs ohne ASN-Daten gefunden", len(ips))
        updated = 0
        for ip in ips:
            as_number, as_name = lookup_asn(ip)
            if as_number is None and as_name is None:
                continue
            with _db_lock:
                conn.execute(
                    "UPDATE proxy_events SET as_number = ?, as_name = ? WHERE source_ip = ? AND as_number IS NULL",
                    (as_number, as_name, ip),
                )
                conn.commit()
            updated += 1
        conn.close()
        log.info("ASN-Backfill abgeschlossen: %d/%d IPs angereichert", updated, len(ips))
    except Exception:
        log.exception("ASN-Backfill fehlgeschlagen")


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
# CrowdSec sync
# ---------------------------------------------------------------------------

_GO_DURATION_RE = re.compile(r"^(-?)(?:(\d+)h)?(?:(\d+)m)?(?:([\d.]+)s)?$")


def parse_go_duration_seconds(value):
    """Parst Go-Duration-Strings, wie CrowdSec sie in decisions[].duration liefert
    (z.B. '23h31m14s' fuer eine noch aktive Entscheidung, '-80h34m27s' fuer eine
    bereits abgelaufene). Gibt None bei leerem/unbekanntem Format zurueck."""
    if not value:
        return None
    m = _GO_DURATION_RE.match(value.strip())
    if not m:
        return None
    sign, h, mn, sec = m.groups()
    total = (int(h) if h else 0) * 3600 + (int(mn) if mn else 0) * 60 + (float(sec) if sec else 0)
    return -total if sign else total


_crowdsec_token = {"value": None, "expires_at": 0}


def crowdsec_login():
    resp = requests.post(
        f"{CROWDSEC_API_URL}/v1/watchers/login",
        json={"machine_id": CROWDSEC_MACHINE_ID, "password": CROWDSEC_MACHINE_PASSWORD},
        timeout=15,
    )
    resp.raise_for_status()
    data = resp.json()
    _crowdsec_token["value"] = data["token"]
    # 60s Sicherheitsmarge vor dem eigentlichen Ablauf, damit ein Request nicht
    # mitten in der Bearbeitung auf einen gerade abgelaufenen Token trifft.
    _crowdsec_token["expires_at"] = datetime.fromisoformat(data["expire"]).timestamp() - 60
    return _crowdsec_token["value"]


def crowdsec_token():
    if _crowdsec_token["value"] and time.time() < _crowdsec_token["expires_at"]:
        return _crowdsec_token["value"]
    return crowdsec_login()


def sync_crowdsec():
    """Holt alle Alerts (inkl. GeoIP/AS-Anreicherung und zugehoeriger Ban-Decision)
    von der zentralen CrowdSec-LAPI und spiegelt sie lokal. Noetig, weil CrowdSec
    selbst nur ~7 Tage Historie haelt (flush.max_age) - ohne eigene Kopie waere
    "welche IP wurde wann und wieso geblockt" nach ein paar Tagen nicht mehr
    beantwortbar. Der Bouncer-Key (den netbird-proxy fuers Blocken nutzt) sieht nur
    die blanken aktiven Decisions ohne Kontext, daher hier Machine-Login wie der
    netbird-logparser-Agent."""
    if not CROWDSEC_CONFIGURED:
        return
    resp = requests.get(
        f"{CROWDSEC_API_URL}/v1/alerts",
        params={"scope": "Ip"},
        headers={"Authorization": f"Bearer {crowdsec_token()}"},
        timeout=30,
    )
    resp.raise_for_status()
    alerts = resp.json() or []

    now = datetime.now(timezone.utc)
    rows = []
    for a in alerts:
        decisions = a.get("decisions") or []
        decision = decisions[0] if decisions else {}
        remaining = parse_go_duration_seconds(decision.get("duration"))
        expires_at = (
            (now + timedelta(seconds=remaining)).strftime("%Y-%m-%dT%H:%M:%SZ")
            if remaining is not None else None
        )
        source = a.get("source") or {}
        rows.append((
            a.get("id"),
            decision.get("id"),
            a.get("created_at"),
            a.get("scenario"),
            a.get("message"),
            a.get("events_count"),
            source.get("ip"),
            source.get("cn"),
            source.get("as_number"),
            source.get("as_name"),
            decision.get("type"),
            expires_at,
        ))

    if not rows:
        return
    with _db_lock:
        conn = get_conn()
        conn.executemany(
            """
            INSERT INTO crowdsec_alerts (
                alert_id, decision_id, created_at, scenario, message, events_count,
                source_ip, country_code, as_number, as_name, decision_type, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(alert_id) DO UPDATE SET
                decision_id = excluded.decision_id,
                expires_at = excluded.expires_at,
                events_count = excluded.events_count,
                message = excluded.message
            """,
            rows,
        )
        conn.commit()
        conn.close()
    set_sync_state("crowdsec_last_sync_at", now.isoformat())


def crowdsec_delete_decision(decision_id):
    """Loescht eine einzelne Entscheidung (Unban) ueber die CrowdSec-LAPI.
    Nutzt denselben Machine-Login wie sync_crowdsec()."""
    resp = requests.delete(
        f"{CROWDSEC_API_URL}/v1/decisions/{decision_id}",
        headers={"Authorization": f"Bearer {crowdsec_token()}"},
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()


def read_whitelist_file():
    with open(WHITELIST_FILE_PATH, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    whitelist = data.setdefault("whitelist", {})
    whitelist.setdefault("ip", [])
    whitelist.setdefault("cidr", [])
    return data


def write_whitelist_file(data):
    # WHITELIST_FILE_PATH ist ein einzeln gebindmounteter Pfad (nicht nur das
    # Elternverzeichnis) - das macht ihn selbst zum Mountpoint, weshalb der sonst
    # uebliche "in Temp-Datei schreiben + os.replace()" Trick hier mit
    # "Device or resource busy" scheitert (ein Rename kann einen Mountpoint nicht
    # ersetzen). Also direkt in die bestehende Datei schreiben (trunkieren).
    with open(WHITELIST_FILE_PATH, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
        f.flush()
        os.fsync(f.fileno())


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
            sync_crowdsec()
        except Exception:
            log.exception("Unerwarteter Fehler beim CrowdSec-Sync")
        try:
            prune_old_events()
        except Exception:
            log.exception("Unerwarteter Fehler beim Pruning")
        try:
            ensure_asn_db()  # No-op fast path, prueft nur den mtime der lokalen Datei
        except Exception:
            log.exception("Unerwarteter Fehler bei der ASN-Datenbank-Aktualisierung")
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


def resolve_range(range_key, args):
    """Resolves the (cutoff, until) bounds for a request's range param.

    range=custom uses explicit from/to query params (UTC ISO strings, as
    produced by the browser's Date.toISOString() from a datetime-local input)
    for an exact bounded window - either end may be omitted for an open-ended
    custom range. Every other range key keeps the existing preset-delta-from-
    now behavior, which is unbounded above (there's never a future row to
    exclude, so no explicit "until" is needed there).
    """
    if range_key == "custom":
        from_ts = args.get("from", "").strip()
        to_ts = args.get("to", "").strip()
        return (from_ts or None), (to_ts or None)
    return range_cutoff(range_key), None


def _parse_iso(ts):
    """Parses the ISO-UTC timestamp strings used throughout this module
    (both the bare-second ones from range_cutoff()/strftime and the
    millisecond ones the browser sends for range=custom) into an aware
    datetime. Python 3.11+'s fromisoformat() accepts the trailing 'Z' directly."""
    return datetime.fromisoformat(ts)


def _format_ts_with_millis(dt):
    """Always includes a fractional-seconds part, unlike the bare-second
    '%Y-%m-%dT%H:%M:%SZ' strings used elsewhere - avoids a lexical string-
    comparison pitfall where a fractionless boundary can sort as "later" than
    a fraction-suffixed timestamp in the exact same second (ASCII 'Z' > '.')."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


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

# NetBird-Mesh-Peers kommunizieren ueber eine CGNAT-Adresse (100.64.0.0/10, RFC 6598) -
# ipaddress.is_private() rechnet dieses Sonder-Range NICHT zu den privaten Adressen,
# ohne eigene Erkennung landen diese Events also im "unbekannt"-Bucket statt als das
# erkannt zu werden was sie sind: eigener Mesh-Traffic, kein echtes Ausland/GeoIP-Fehler.
NBM_COUNTRY_LABEL = "NBM"
NBM_CITY_LABEL = "NetBird-Mesh"
_NETBIRD_MESH_NET = ipaddress.ip_network("100.64.0.0/10")

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

# SQL-Gegenstueck zu is_netbird_mesh_ip() - 100.64.0.0/10 deckt die zweiten Oktette
# 64-127 ab, dafuer gibt es kein kurzes LIKE-Muster wie bei den /8- und /16-Netzen oben.
_NETBIRD_MESH_SQL = "(" + " OR ".join(f"source_ip LIKE '100.{i}.%'" for i in range(64, 128)) + ")"


def is_private_ip(ip):
    """True fuer RFC1918/Loopback/Link-Local-Adressen. Muss mit _PRIVATE_IP_SQL
    in Sync bleiben, da beide dieselben Events als "intern" markieren sollen."""
    if not ip:
        return False
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def is_netbird_mesh_ip(ip):
    """True fuer NetBird-Mesh-CGNAT-Adressen (100.64.0.0/10). Muss mit
    _NETBIRD_MESH_SQL in Sync bleiben, siehe dortigen Kommentar."""
    if not ip:
        return False
    try:
        return ipaddress.ip_address(ip) in _NETBIRD_MESH_NET
    except ValueError:
        return False


_asn_reader = None  # lazily geoeffnet; False = Oeffnen ist fehlgeschlagen, nicht erneut versuchen
_asn_reader_lock = threading.Lock()


def ensure_asn_db():
    """Laedt die (kostenlose, unauthentifizierte) GeoLite2-ASN-mmdb, die auch
    CrowdSecs eigene Hub-Parser nutzen, in denselben Volume-Pfad wie die SQLite-
    DB - falls die Anreicherung aktiviert ist und noch keine/eine veraltete
    Kopie vorliegt. Jeder Fehlerfall (Netzwerk, Platte, kaputter Download) wird
    nur geloggt - blockiert nie den Start und wirft nie aus dem Poller-Loop."""
    if not ASN_ENRICHMENT_ENABLED:
        return
    try:
        needs_download = not os.path.exists(ASN_MMDB_PATH)
        if not needs_download:
            age_seconds = time.time() - os.path.getmtime(ASN_MMDB_PATH)
            needs_download = age_seconds >= ASN_REFRESH_INTERVAL_SECONDS
        if not needs_download:
            return

        tmp_path = ASN_MMDB_PATH + ".tmp"
        resp = requests.get(ASN_MMDB_URL, timeout=60)
        resp.raise_for_status()
        with open(tmp_path, "wb") as f:
            f.write(resp.content)

        maxminddb.open_database(tmp_path).close()  # wirft bei kaputter/unvollstaendiger Datei
        os.replace(tmp_path, ASN_MMDB_PATH)  # atomar - ueberschreibt eine funktionierende Datei nur nach Erfolg
        global _asn_reader
        with _asn_reader_lock:
            _asn_reader = None  # naechster lookup_asn() oeffnet die frische Datei neu
        log.info("ASN-Datenbank aktualisiert (%s)", ASN_MMDB_URL)
    except Exception:
        log.exception("ASN-Datenbank konnte nicht aktualisiert werden - ASN-Anreicherung bleibt ggf. inaktiv")


def _get_asn_reader():
    global _asn_reader
    if not ASN_ENRICHMENT_ENABLED:
        return None
    with _asn_reader_lock:
        if _asn_reader is None and os.path.exists(ASN_MMDB_PATH):
            try:
                _asn_reader = maxminddb.open_database(ASN_MMDB_PATH)
            except Exception:
                log.exception("ASN-Datenbank konnte nicht geoeffnet werden")
                _asn_reader = False
        return _asn_reader or None


def lookup_asn(ip):
    """(as_number, as_name) fuer eine oeffentliche IP, sonst (None, None) -
    Anreicherung deaktiviert, IP privat/NetBird-Mesh, DB nicht geladen, oder
    IP schlicht nicht gefunden. Jeder Aufrufer muss (None, None) dauerhaft
    tolerieren, auch bei komplett deaktiviertem Feature."""
    if not ip or is_private_ip(ip) or is_netbird_mesh_ip(ip):
        return None, None
    reader = _get_asn_reader()
    if not reader:
        return None, None
    try:
        result = reader.get(ip)
    except (ValueError, maxminddb.InvalidDatabaseError):
        return None, None
    if not result:
        return None, None
    as_number = result.get("autonomous_system_number")
    as_name = result.get("autonomous_system_organization")
    return (str(as_number) if as_number is not None else None), as_name


def label_country(raw_country, source_ip):
    if raw_country:
        return raw_country
    if is_private_ip(source_ip):
        return INTERNAL_COUNTRY_LABEL
    if is_netbird_mesh_ip(source_ip):
        return NBM_COUNTRY_LABEL
    return UNKNOWN_COUNTRY_LABEL


def label_city(raw_city, source_ip):
    if raw_city:
        return raw_city
    if is_private_ip(source_ip):
        return INTERNAL_CITY_LABEL
    if is_netbird_mesh_ip(source_ip):
        return NBM_CITY_LABEL
    return UNKNOWN_CITY_LABEL


SEARCH_FIELDS = ("host", "path", "source_ip", "user_id")


def apply_search(search, where_clauses, params, fields=SEARCH_FIELDS):
    """Freitextsuche ueber `fields` (Leerzeichen-getrennte Tokens).
    Ein Token mit '!'-Praefix schliesst Treffer aus (z.B. "!10.0.0.5", um eine
    laute IP aus der Tabelle herauszufiltern), alle anderen Tokens muessen in
    mindestens einem der Felder vorkommen (UND ueber Tokens, ODER ueber Felder)."""
    for token in search.split():
        negate = len(token) > 1 and token.startswith("!")
        term = token[1:] if negate else token
        if not term:
            continue
        like = f"%{term}%"
        clause = "(" + " OR ".join(f"{f} LIKE ?" for f in fields) + ")"
        where_clauses.append(f"NOT {clause}" if negate else clause)
        params.extend([like] * len(fields))


def apply_common_filters(args, where_clauses, params):
    """Cross-filter conditions shared by /api/stats and /api/events.

    Kept in one place so clicking a chart segment or table cell filters
    every panel identically, Grafana-style.

    `exclude` is a comma-separated list of filter keys (from the query
    string) that should be negated - i.e. "everything EXCEPT this value"
    instead of "only this value" - set from the dashboard's filter chips
    (click chip to invert) or Ctrl/Cmd-click on a clickable value.

    host/country/ip/asn/reason/path/city/user_id additionally accept several
    comma-separated values (e.g. "country=DE,CH"), matched with OR - lets the
    dashboard's additive multi-select ("DE" then also "CH") turn into a single
    IN-like clause, still with the same include/exclude semantics for the
    whole set (see `add`/`add_multi`).
    """
    exclude = {k for k in args.get("exclude", "").split(",") if k}

    def add(key, clause, clause_params=()):
        # "IS NOT TRUE" statt NOT(...): eine Zeile mit NULL-Spalte (z.B. IP ohne
        # ASN-Daten, Deny ohne Grund) ist SQL-technisch weder col=? noch NOT(col=?)
        # - beides ergibt NULL, nicht TRUE/FALSE, und die Zeile würde bei einem
        # blossen NOT(...) aus BEIDEN Richtungen (Include UND Exclude) verschwinden.
        # Gilt genauso fuer eine ganze OR-Gruppe aus add_multi() - NULL OR NULL
        # ist wieder NULL, "IS NOT TRUE" faengt das fuer die gesamte Gruppe ab.
        where_clauses.append(f"({clause}) IS NOT TRUE" if key in exclude else clause)
        params.extend(clause_params)

    def split_multi(raw):
        return [v.strip() for v in raw.split(",") if v.strip()]

    def add_multi(key, raw, clause_builder):
        values = split_multi(raw)
        if not values:
            return
        clauses, all_params = [], []
        for v in values:
            clause, clause_params = clause_builder(v)
            clauses.append(clause)
            all_params.extend(clause_params)
        group = clauses[0] if len(clauses) == 1 else "(" + " OR ".join(clauses) + ")"
        add(key, group, all_params)

    host = args.get("host", "").strip()
    country = args.get("country", "").strip()
    ip = args.get("ip", "").strip()
    asn = args.get("asn", "").strip()
    status = args.get("status", "").strip()  # allowed/denied (reason-based)
    bucket = args.get("bucket", "").strip()  # 2xx/3xx/4xx/5xx/n/a (status_code-based)
    reason = args.get("reason", "").strip()
    path = args.get("path", "").strip()
    user_id = args.get("user_id", "").strip()
    city = args.get("city", "").strip()

    def host_clause(h):
        if h == UNKNOWN_HOST_LABEL:
            return "(host IS NULL OR host = '')", []
        return "host = ?", [h]

    add_multi("host", host, host_clause)

    def country_clause(c):
        if c == INTERNAL_COUNTRY_LABEL:
            return f"((country_code IS NULL OR country_code = '') AND {_PRIVATE_IP_SQL})", []
        if c == NBM_COUNTRY_LABEL:
            return f"((country_code IS NULL OR country_code = '') AND {_NETBIRD_MESH_SQL})", []
        if c == UNKNOWN_COUNTRY_LABEL:
            return (
                f"((country_code IS NULL OR country_code = '') AND NOT {_PRIVATE_IP_SQL} AND NOT {_NETBIRD_MESH_SQL})",
                [],
            )
        return "country_code = ?", [c]

    add_multi("country", country, country_clause)
    add_multi("ip", ip, lambda v: ("source_ip = ?", [v]))
    add_multi("asn", asn, lambda v: ("as_number = ?", [v]))

    if status == "denied":
        add("status", "(reason IS NOT NULL AND reason != '')")
    elif status == "allowed":
        add("status", "(reason IS NULL OR reason = '')")
    if bucket in BUCKET_CONDITIONS:
        add("bucket", BUCKET_CONDITIONS[bucket])
    status_code = args.get("status_code", "").strip()
    if status_code:
        try:
            add("status_code", "status_code = ?", [int(status_code)])
        except ValueError:
            pass  # nicht-numerische Eingabe wird ignoriert statt einen 500er zu werfen

    add_multi("reason", reason, lambda v: ("reason = ?", [v]))
    add_multi("path", path, lambda v: ("path = ?", [v]))
    add_multi("user_id", user_id, lambda v: ("user_id = ?", [v]))

    def city_clause(c):
        if c == INTERNAL_CITY_LABEL:
            return f"((city_name IS NULL OR city_name = '') AND {_PRIVATE_IP_SQL})", []
        if c == NBM_CITY_LABEL:
            return f"((city_name IS NULL OR city_name = '') AND {_NETBIRD_MESH_SQL})", []
        if c == UNKNOWN_CITY_LABEL:
            return (
                f"((city_name IS NULL OR city_name = '') AND NOT {_PRIVATE_IP_SQL} AND NOT {_NETBIRD_MESH_SQL})",
                [],
            )
        return "city_name = ?", [c]

    add_multi("city", city, city_clause)


def crowdsec_source_ip_filter(args, cutoff=None, until=None):
    """Links the page's cross-filters to the CrowdSec tables.

    A crowdsec_alerts row has no host/path/status/reason of its own (a ban
    covers everything from that IP, not one request) - only source_ip and
    country_code overlap with proxy_events. So when any cross-filter is
    active, scope CrowdSec results to IPs that also appear in the currently
    filtered proxy_events view instead of leaving the CrowdSec tables
    unfiltered. Returns (None, []) when no cross-filter is set, so CrowdSec
    scenarios unrelated to proxy traffic (e.g. port-scan decisions from other
    collections) still show up by default.
    """
    filter_where, filter_params = [], []
    apply_common_filters(args, filter_where, filter_params)
    if not filter_where:
        return None, []
    if cutoff:
        filter_where.append("timestamp >= ?")
        filter_params.append(cutoff)
    if until:
        filter_where.append("timestamp <= ?")
        filter_params.append(until)
    sub_where = " AND ".join(filter_where)
    return (
        f"source_ip IN (SELECT DISTINCT source_ip FROM proxy_events WHERE {sub_where} AND source_ip IS NOT NULL)",
        filter_params,
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/healthz")
def healthz():
    return jsonify(status="ok")


@app.route("/manifest.webmanifest")
def manifest():
    """Web App Manifest, damit Chromium/Vanadium (Android) 'Zum Startbildschirm
    hinzufuegen' als eigenstaendige App ohne Adressleiste startet statt als
    normaler Browser-Tab."""
    return jsonify(
        name="NetBird Proxy Access Dashboard",
        short_name="Proxy Dashboard",
        description="Zugriffs- und CrowdSec-Uebersicht fuer den NetBird Reverse Proxy",
        start_url="/",
        scope="/",
        display="standalone",
        background_color="#0d1117",
        theme_color="#0d1117",
        lang="de",
        icons=[
            {"src": "/static/icon-192.png", "sizes": "192x192", "type": "image/png", "purpose": "any maskable"},
            {"src": "/static/icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any maskable"},
        ],
    ), 200, {"Content-Type": "application/manifest+json"}


@app.route("/api/stats")
def api_stats():
    return jsonify(cached(request.full_path, lambda: _compute_stats(request.args)))


def _compute_stats(args):
    range_key = args.get("range", "24h")
    cutoff, until = resolve_range(range_key, args)
    conn = get_conn()

    where_clauses = []
    params = []
    if cutoff:
        where_clauses.append("timestamp >= ?")
        params.append(cutoff)
    if until:
        where_clauses.append("timestamp <= ?")
        params.append(until)
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
               status_code, timestamp, metadata, as_number, as_name
        FROM proxy_events {where}
        """,
        params,
    ).fetchall()
    conn.row_factory = sqlite3.Row

    countries, hosts, paths, cities, ips = Counter(), Counter(), Counter(), Counter(), Counter()
    asns = Counter()
    users, auth_methods_c, reasons_c, status_buckets_c = Counter(), Counter(), Counter(), Counter()
    denies_by_ip = Counter()
    traffic_by_host = defaultdict(lambda: [0, 0])
    hourly_count = Counter()
    hourly_duration_sum, hourly_duration_n = defaultdict(int), defaultdict(int)
    hourly_upload_sum, hourly_download_sum = defaultdict(int), defaultdict(int)
    durations = []
    slowest = []  # (duration_ms, timestamp, host, path, status_code, source_ip)
    endpoint_duration_sum, endpoint_duration_n = defaultdict(int), defaultdict(int)
    denied = 0
    crowdsec_unavailable_count = 0
    traffic_upload_total = traffic_download_total = 0

    for (raw_country, raw_host, path, raw_city, source_ip, duration_ms,
         bytes_upload, bytes_download, reason, user_id, auth_method_used,
         status_code, timestamp, metadata, as_number, as_name) in rows:
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
        if as_number is not None:
            asns[(as_number, as_name)] += 1

        up, down = bytes_upload or 0, bytes_download or 0
        host_traffic = traffic_by_host[host]
        host_traffic[0] += up
        host_traffic[1] += down
        traffic_upload_total += up
        traffic_download_total += down
        hourly_upload_sum[bucket] += up
        hourly_download_sum[bucket] += down

        if user_id:
            users[user_id] += 1
        if auth_method_used:
            auth_methods_c[auth_method_used] += 1
        if reason:
            denied += 1
            reasons_c[reason] += 1
            denies_by_ip[source_ip] += 1
        if metadata:
            try:
                if json.loads(metadata).get("crowdsec_verdict") == "crowdsec_unavailable":
                    crowdsec_unavailable_count += 1
            except (ValueError, AttributeError):
                pass  # kaputtes/unerwartetes JSON ignorieren statt die ganze Stats-Berechnung zu werfen

        status_buckets_c[status_bucket(status_code)] += 1
        hourly_count[bucket] += 1

        if duration_ms is not None:
            durations.append(duration_ms)
            hourly_duration_sum[bucket] += duration_ms
            hourly_duration_n[bucket] += 1
            slowest.append((duration_ms, timestamp, raw_host, path, status_code, source_ip))
            endpoint_key = (raw_host, path)
            endpoint_duration_sum[endpoint_key] += duration_ms
            endpoint_duration_n[endpoint_key] += 1

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

    # Ab 5 Requests pro Endpunkt, damit nicht ein einzelner Ausreisser (z.B. ein
    # kalter Start) einen sonst schnellen Endpunkt an die Spitze setzt.
    MIN_SLOW_ENDPOINT_SAMPLES = 5
    slow_endpoints = sorted(
        (
            {"host": h, "path": p, "avg_ms": endpoint_duration_sum[(h, p)] / n_samples, "n": n_samples}
            for (h, p), n_samples in endpoint_duration_n.items()
            if n_samples >= MIN_SLOW_ENDPOINT_SAMPLES
        ),
        key=lambda x: x["avg_ms"],
        reverse=True,
    )[:15]

    timeseries = [{"bucket": b, "c": c} for b, c in sorted(hourly_count.items())]
    latency_timeseries = [
        {"bucket": b, "avg_ms": hourly_duration_sum[b] / hourly_duration_n[b]}
        for b in sorted(hourly_duration_n)
    ]
    traffic_timeseries = [
        {"bucket": b, "bytes_upload": hourly_upload_sum[b], "bytes_download": hourly_download_sum[b]}
        for b in sorted(hourly_count)
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

    # Traffic-Spike: Requests im gewaehlten Fenster vs. das direkt davor liegende,
    # gleich lange Fenster - MIT denselben Cross-Filtern, sonst wuerde eine
    # gefilterte Ansicht (z.B. host=x) staendig gegen den ungefilterten Vorher-
    # Wert verglichen. "all" hat kein sinnvolles "davor", ein offenes
    # range=custom (nur "from" oder nur "to") hat keine bestimmbare
    # Fensterlaenge - beides daher ausgenommen.
    window_delta = (
        RANGE_TO_DELTA.get(range_key) if range_key != "custom"
        else (_parse_iso(until) - _parse_iso(cutoff)) if (cutoff and until) else None
    )
    if window_delta:
        try:
            prior_until = cutoff
            prior_cutoff = _format_ts_with_millis(_parse_iso(cutoff) - window_delta)
            prior_where = ["timestamp >= ?", "timestamp < ?"]
            prior_params = [prior_cutoff, prior_until]
            apply_common_filters(args, prior_where, prior_params)
            previous_count = conn.execute(
                f"SELECT COUNT(*) c FROM proxy_events WHERE {' AND '.join(prior_where)}",
                prior_params,
            ).fetchone()["c"]
            if previous_count >= 20 and total_requests >= previous_count * 3:
                anomalies.append({
                    "type": "traffic_spike",
                    "current": total_requests,
                    "previous": previous_count,
                })
        except (ValueError, TypeError):
            log.warning("Traffic-Spike-Anomalie uebersprungen - Range-Grenzen nicht parsbar")

    for ip, c in denies_by_ip.most_common(10):
        if c >= ANOMALY_DENY_THRESHOLD:
            anomalies.append({"type": "ip_deny_spike", "source_ip": ip, "count": c})

    if crowdsec_unavailable_count:
        anomalies.append({"type": "crowdsec_unavailable", "count": crowdsec_unavailable_count})

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
        traffic_timeseries=traffic_timeseries,
        traffic_hosts=traffic_hosts,
        traffic_total=dict(bytes_upload=traffic_upload_total, bytes_download=traffic_download_total),
        top_users=[{"user_id": k, "c": v} for k, v in users.most_common(10)],
        auth_methods=[{"auth_method_used": k, "c": v} for k, v in auth_methods_c.most_common(10)],
        top_paths=[{"host": h, "path": p, "c": v} for (h, p), v in paths.most_common(10)],
        top_cities=[{"city_name": c, "country_code": cc, "c": v} for (c, cc), v in cities.most_common(10)],
        top_ips=[{"source_ip": k, "c": v} for k, v in ips.most_common(10)],
        top_asns=[{"as_number": k[0], "as_name": k[1], "c": v} for k, v in asns.most_common(10)],
        latency=dict(p50=latency_p50, p95=latency_p95, avg=latency_avg),
        latency_timeseries=latency_timeseries,
        slowest_events=slowest_events,
        slow_endpoints=slow_endpoints,
        anomalies=anomalies,
    )


@app.route("/api/events")
def api_events():
    range_key = request.args.get("range", "24h")
    cutoff, until = resolve_range(range_key, request.args)
    search = request.args.get("search", "").strip()
    limit = min(int(request.args.get("limit", "200")), 500)

    where_clauses = []
    params = []
    if cutoff:
        where_clauses.append("timestamp >= ?")
        params.append(cutoff)
    if until:
        where_clauses.append("timestamp <= ?")
        params.append(until)
    if search:
        apply_search(search, where_clauses, params)
    apply_common_filters(request.args, where_clauses, params)

    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    conn = get_conn()
    rows = conn.execute(
        f"""
        SELECT timestamp, method, host, path, status_code, duration_ms, source_ip,
               country_code, city_name, user_id, auth_method_used, reason, protocol, metadata,
               as_number, as_name
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
        metadata = e.pop("metadata")
        e["crowdsec_verdict"] = None
        if metadata:
            try:
                e["crowdsec_verdict"] = json.loads(metadata).get("crowdsec_verdict")
            except (ValueError, AttributeError):
                pass
        events.append(e)

    return jsonify(events=events)


CROWDSEC_SEARCH_FIELDS = ("source_ip", "scenario", "message", "country_code", "as_name")


@app.route("/api/crowdsec/current")
def api_crowdsec_current():
    """Aktueller Block-Status: alle lokal bekannten CrowdSec-Bans, deren berechnetes
    Ablaufdatum noch in der Zukunft liegt - das "wer ist JETZT gerade blockiert".
    Pro IP zu einer Zeile zusammengefasst, weil dieselbe IP oft mehrere Szenarien
    gleichzeitig ausloest (z.B. auth-bruteforce + sensitive-path-scan)."""
    conn = get_conn()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    where_clauses = ["expires_at IS NOT NULL", "expires_at > ?"]
    params = [now]
    ip_filter, ip_params = crowdsec_source_ip_filter(request.args)
    if ip_filter:
        where_clauses.append(ip_filter)
        params.extend(ip_params)
    rows = conn.execute(
        f"""
        SELECT * FROM crowdsec_alerts
        WHERE {' AND '.join(where_clauses)}
        ORDER BY created_at ASC
        """,
        params,
    ).fetchall()
    conn.close()

    by_ip = {}
    for r in rows:
        ip = r["source_ip"]
        entry = by_ip.get(ip)
        if entry is None:
            entry = {
                "source_ip": ip,
                "country_code": r["country_code"],
                "as_name": r["as_name"],
                "as_number": r["as_number"],
                "scenarios": [],
                "events_count": 0,
                "first_seen": r["created_at"],
                "last_seen": r["created_at"],
                "expires_at": r["expires_at"],
            }
            by_ip[ip] = entry
        if r["scenario"] not in entry["scenarios"]:
            entry["scenarios"].append(r["scenario"])
        entry["events_count"] += r["events_count"] or 0
        entry["last_seen"] = max(entry["last_seen"], r["created_at"])
        entry["expires_at"] = max(entry["expires_at"], r["expires_at"])

    decisions = sorted(by_ip.values(), key=lambda d: d["last_seen"], reverse=True)
    return jsonify(configured=CROWDSEC_CONFIGURED, decisions=decisions)


@app.route("/api/crowdsec/history")
def api_crowdsec_history():
    """Verlauf aller je gesehenen CrowdSec-Bans (auch abgelaufene) - haelt laenger
    vor als CrowdSecs eigene ~7-Tage-Historie, siehe sync_crowdsec()."""
    range_key = request.args.get("range", "24h")
    cutoff, until = resolve_range(range_key, request.args)
    search = request.args.get("search", "").strip()
    limit = min(int(request.args.get("limit", "200")), 500)

    where_clauses, params = [], []
    if cutoff:
        where_clauses.append("created_at >= ?")
        params.append(cutoff)
    if until:
        where_clauses.append("created_at <= ?")
        params.append(until)
    if search:
        apply_search(search, where_clauses, params, fields=CROWDSEC_SEARCH_FIELDS)
    ip_filter, ip_params = crowdsec_source_ip_filter(request.args, cutoff=cutoff, until=until)
    if ip_filter:
        where_clauses.append(ip_filter)
        params.extend(ip_params)

    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    conn = get_conn()
    rows = conn.execute(
        f"""
        SELECT *, (expires_at IS NOT NULL AND expires_at > ?) AS is_active
        FROM crowdsec_alerts
        {where_sql}
        ORDER BY created_at DESC
        LIMIT ?
        """,
        [now] + params + [limit],
    ).fetchall()
    conn.close()
    return jsonify(configured=CROWDSEC_CONFIGURED, alerts=[dict(r) for r in rows])


@app.route("/api/crowdsec/ban/<ip>", methods=["DELETE"])
def api_crowdsec_delete_ban(ip):
    """Loescht alle aktuell aktiven Entscheidungen einer IP (Unban) - fuer den
    Fall, dass sie irrtuemlich blockiert wurde. Wirkt sofort auf der LAPI; die
    lokale Kopie wird direkt mitaktualisiert, statt auf den naechsten Sync-Zyklus
    zu warten, damit das Widget die IP nicht mehr als aktiv blockiert zeigt."""
    if not CROWDSEC_CONFIGURED:
        return jsonify(error="CrowdSec ist nicht konfiguriert"), 400

    conn = get_conn()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    rows = conn.execute(
        """
        SELECT decision_id FROM crowdsec_alerts
        WHERE source_ip = ? AND decision_id IS NOT NULL AND expires_at IS NOT NULL AND expires_at > ?
        """,
        (ip, now),
    ).fetchall()
    conn.close()

    deleted, errors = [], []
    for r in rows:
        decision_id = r["decision_id"]
        try:
            crowdsec_delete_decision(decision_id)
            deleted.append(decision_id)
        except requests.RequestException as exc:
            errors.append(str(exc))

    if deleted:
        placeholders = ",".join("?" * len(deleted))
        with _db_lock:
            conn = get_conn()
            conn.execute(
                f"UPDATE crowdsec_alerts SET expires_at = ? WHERE source_ip = ? AND decision_id IN ({placeholders})",
                [now, ip] + deleted,
            )
            conn.commit()
            conn.close()

    if errors and not deleted:
        return jsonify(error="; ".join(errors)), 502
    return jsonify(ok=True, deleted_decision_ids=deleted, errors=errors)


@app.route("/api/crowdsec/whitelist")
def api_crowdsec_whitelist_get():
    if not WHITELIST_FILE_PATH:
        return jsonify(configured=False, ip=[], cidr=[], dirty=False)
    try:
        data = read_whitelist_file()
    except OSError as exc:
        log.warning("Whitelist-Datei nicht lesbar: %s", exc)
        return jsonify(configured=False, error=str(exc), ip=[], cidr=[], dirty=False)
    dirty = get_sync_state("whitelist_dirty") == "1"
    return jsonify(configured=True, ip=data["whitelist"]["ip"], cidr=data["whitelist"]["cidr"], dirty=dirty)


@app.route("/api/crowdsec/whitelist/entries", methods=["POST"])
def api_crowdsec_whitelist_add():
    if not WHITELIST_FILE_PATH:
        return jsonify(error="Whitelist-Datei nicht konfiguriert"), 400
    value = ((request.get_json(silent=True) or {}).get("value") or "").strip()
    if not value:
        return jsonify(error="Kein Wert angegeben"), 400

    kind = "cidr" if "/" in value else "ip"
    try:
        if kind == "ip":
            ipaddress.ip_address(value)
        else:
            ipaddress.ip_network(value, strict=False)
    except ValueError:
        return jsonify(error=f"'{value}' ist keine gueltige IP-Adresse oder CIDR-Range"), 400

    with _whitelist_lock:
        try:
            data = read_whitelist_file()
        except OSError as exc:
            return jsonify(error=str(exc)), 500
        entries = data["whitelist"][kind]
        if value not in entries:
            entries.append(value)
            write_whitelist_file(data)
            set_sync_state("whitelist_dirty", "1")

    return jsonify(configured=True, ip=data["whitelist"]["ip"], cidr=data["whitelist"]["cidr"], dirty=True)


@app.route("/api/crowdsec/whitelist/entries", methods=["DELETE"])
def api_crowdsec_whitelist_remove():
    if not WHITELIST_FILE_PATH:
        return jsonify(error="Whitelist-Datei nicht konfiguriert"), 400
    value = (request.args.get("value") or "").strip()
    if not value:
        return jsonify(error="Kein Wert angegeben"), 400

    with _whitelist_lock:
        try:
            data = read_whitelist_file()
        except OSError as exc:
            return jsonify(error=str(exc)), 500
        changed = False
        for kind in ("ip", "cidr"):
            if value in data["whitelist"][kind]:
                data["whitelist"][kind].remove(value)
                changed = True
        if changed:
            write_whitelist_file(data)
            set_sync_state("whitelist_dirty", "1")

    dirty = get_sync_state("whitelist_dirty") == "1"
    return jsonify(configured=True, ip=data["whitelist"]["ip"], cidr=data["whitelist"]["cidr"], dirty=dirty)


@app.route("/api/crowdsec/whitelist/apply", methods=["POST"])
def api_crowdsec_whitelist_apply():
    """Startet WHITELIST_CONTAINER_NAME (netbird-logparser) neu, damit eine
    geaenderte Whitelist-Datei tatsaechlich geladen wird - CrowdSec liest
    Postoverflow-Parser nur beim Start ein, kein Hot-Reload. Bewusst ein
    separater, vom Nutzer ausgeloester Schritt statt automatisch bei jeder
    Aenderung, damit der (kurze) Neustart der Log-Verarbeitung kontrolliert
    passiert und nicht bei jedem Klick."""
    if not WHITELIST_FILE_PATH:
        return jsonify(error="Whitelist-Datei nicht konfiguriert"), 400
    try:
        client = docker_sdk.from_env()
        container = client.containers.get(WHITELIST_CONTAINER_NAME)
        container.restart(timeout=10)
    except Exception as exc:
        log.exception("Neustart von %s fehlgeschlagen", WHITELIST_CONTAINER_NAME)
        return jsonify(error=str(exc)), 502
    set_sync_state("whitelist_dirty", "0")
    return jsonify(ok=True)


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

    try:
        db_size_bytes = os.path.getsize(DB_PATH)
    except OSError:
        db_size_bytes = None

    crowdsec_last_sync = get_sync_state("crowdsec_last_sync_at")
    crowdsec_lag_seconds = None
    if crowdsec_last_sync:
        try:
            crowdsec_lag_seconds = max(
                0, (datetime.now(timezone.utc) - datetime.fromisoformat(crowdsec_last_sync)).total_seconds()
            )
        except ValueError:
            pass

    return jsonify(
        last_timestamp=last_timestamp,
        lag_seconds=lag_seconds,
        total_events=total_events,
        retention_days=RETENTION_DAYS,
        poller_configured=bool(NB_API_BASE and NB_API_TOKEN),
        db_size_bytes=db_size_bytes,
        crowdsec_configured=CROWDSEC_CONFIGURED,
        crowdsec_lag_seconds=crowdsec_lag_seconds,
    )


if __name__ == "__main__":
    init_db()
    ensure_asn_db()
    threading.Thread(target=poller_loop, daemon=True).start()
    threading.Thread(target=backfill_asn_data, daemon=True).start()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8098")))
