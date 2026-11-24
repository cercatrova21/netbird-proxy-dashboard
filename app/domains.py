"""Domain-Verwaltung: zentrale Sicht und Steuerung von NetBird-Reverse-Proxy,
BunkerWeb und Traefik.

Verkehrswege einer Domain:
  passthrough:  Internet -> Traefik (TCP, TLS-Passthrough, HostSNI(*)) -> netbird-proxy -> Backend
  bunkerweb:    Internet -> Traefik (TLS/LE, HTTP-Router) -> BunkerWeb (WAF) -> netbird-proxy -> Backend
  traefik:      Internet -> Traefik (HTTP-Router auf einen anderen Container, z.B. NetBird selbst)

Quellen der Wahrheit:
  NetBird     REST-API /api/reverse-proxies/services
  BunkerWeb   BW_SITES_FILE (docker-compose.override.yml im BunkerWeb-Compose-Verzeichnis,
              environment von bw-scheduler: SERVER_NAME + <domain>_<SETTING>). Wird von hier
              geschrieben; aktiv wird es durch Neuerstellen von bw-scheduler.
  Traefik     TRAEFIK_DYNAMIC_PATH (File-Provider, live neu geladen) - HTTP-Router mit
              service == TRAEFIK_BW_SERVICE. Docker-Label-Router werden nur gelesen.

Aenderungen laufen als Job (eine Aenderung gleichzeitig) mit Schritt-Protokoll und
Rollback der bereits ausgefuehrten Schritte bei einem Fehler.
"""

import copy
import hashlib
import ipaddress
import json
import logging
import os
import re
import shutil
import socket
import ssl
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import requests
import yaml
from flask import Blueprint, jsonify, render_template, request

log = logging.getLogger("netbird-proxy-dashboard.domains")

BW_COMPOSE_DIR = os.environ.get("BW_COMPOSE_DIR", "").rstrip("/")
BW_SITES_FILE = os.environ.get("BW_SITES_FILE", "") or (
    os.path.join(BW_COMPOSE_DIR, "docker-compose.override.yml") if BW_COMPOSE_DIR else ""
)
BW_SCHEDULER_SERVICE = os.environ.get("BW_SCHEDULER_SERVICE", "bw-scheduler")
BW_SCHEDULER_CONTAINER = os.environ.get("BW_SCHEDULER_CONTAINER", "bw-scheduler")
BW_UPSTREAM = os.environ.get("BW_UPSTREAM", "https://netbird-proxy:8443")
BW_APPLY_TIMEOUT = int(os.environ.get("BW_APPLY_TIMEOUT_SECONDS", "240"))
TRAEFIK_DYNAMIC_PATH = os.environ.get("TRAEFIK_DYNAMIC_PATH", "")
TRAEFIK_BW_SERVICE = os.environ.get("TRAEFIK_BW_SERVICE", "bunkerweb@docker")
TRAEFIK_ENTRYPOINT = os.environ.get("TRAEFIK_ENTRYPOINT", "websecure")
TRAEFIK_CERT_RESOLVER = os.environ.get("TRAEFIK_CERT_RESOLVER", "letsencrypt")
PROBE_HOST = os.environ.get("DOMAINS_PROBE_HOST", "").strip()
PROBE_PORT = int(os.environ.get("DOMAINS_PROBE_PORT", "443"))
CERT_WAIT_SECONDS = int(os.environ.get("DOMAINS_CERT_WAIT_SECONDS", "180"))
COMPOSE_BIN = os.environ.get("DOCKER_COMPOSE_BIN", "/usr/local/bin/docker-compose")
BACKUP_KEEP = 30

SITES_HEADER = """\
# BunkerWeb-Sites - VERWALTET VOM PROXY-DASHBOARD (Seite "Domains").
#
# Compose laedt diese Datei automatisch zusaetzlich zu docker-compose.yml
# (Override). Sie enthaelt SERVER_NAME und alle <domain>_<SETTING> von
# bw-scheduler. Globale Einstellungen bleiben in docker-compose.yml.
#
# Manuell aendern geht, wenn das Format erhalten bleibt: ein Block pro Site,
# eingeleitet mit "# ==== site: <domain> ====", Kommentare direkt ueber einem
# Setting gehoeren zu diesem Setting. "$" in Werten wird als "$$" geschrieben.
# Aktivieren: docker compose up -d --no-deps --force-recreate bw-scheduler
# Backups vor jeder Dashboard-Aenderung: ./backups/
"""

TRAEFIK_HEADER = """\
# Traefik File-Provider (live neu geladen) - BunkerWeb-Router werden vom
# Proxy-Dashboard (Seite "Domains") verwaltet: ein Router pro Domain mit
# service bunkerweb@docker. Domain ohne Router = Catch-all HostSNI(*) ->
# netbird-proxy (Passthrough).
# WICHTIG: Datei ist als Einzeldatei in Traefik gemountet -> nur in place
# aendern (gleiche Inode), nicht per "mv"/Editor-Swap ersetzen.
# Backups vor jeder Dashboard-Aenderung: <datei>.bak-* bzw. backups/
"""

# Settings, die das Dashboard pro Site immer selbst setzt (im UI gesperrt).
LOCKED_KEYS = {
    "USE_REVERSE_PROXY": lambda d: "yes",
    "REVERSE_PROXY_HOST": lambda d: BW_UPSTREAM,
    "REVERSE_PROXY_URL": lambda d: "/",
    "REVERSE_PROXY_SSL_SNI": lambda d: "yes",
    "REVERSE_PROXY_SSL_SNI_NAME": lambda d: d,
}

ALL_METHODS = "GET|POST|HEAD|PUT|DELETE|PATCH|OPTIONS"
APP_HEADER_KEYS = [
    "X_FRAME_OPTIONS", "CONTENT_SECURITY_POLICY", "PERMISSIONS_POLICY",
    "CROSS_ORIGIN_OPENER_POLICY", "CROSS_ORIGIN_EMBEDDER_POLICY",
    "CROSS_ORIGIN_RESOURCE_POLICY", "COOKIE_FLAGS",
]

PRESETS = {
    "static": {
        "label": "Statische Website",
        "description": "Nur GET/HEAD, kleine Uploads, WAF blockiert, BunkerWeb-Security-Header aktiv.",
        "settings": [
            ("REVERSE_PROXY_WS", "yes", ""),
            ("LIMIT_REQ_RATE", "20r/s", ""),
            ("ALLOWED_METHODS", "GET|HEAD", "Statische Seite: keine Formulare/Uploads"),
            ("MAX_CLIENT_SIZE", "1m", ""),
        ],
    },
    "webapp": {
        "label": "Web-App mit eigenen Security-Headern",
        "description": "Alle Methoden, Header der App unveraendert, Fehlerseiten der App durchreichen, "
                       "WAF zuerst nur protokollieren (fuer Logins, Passkeys, SSO, Zahlungen, APIs).",
        "settings": [
            ("REVERSE_PROXY_WS", "yes", "WebSockets (z.B. SignalR, Live-Updates)"),
            ("REVERSE_PROXY_HEADERS", "X-Forwarded-Prefix ''",
             "BunkerWeb sendet sonst \"X-Forwarded-Prefix: /\" -> manche Apps (ASP.NET) bauen daraus //-Redirects"),
            ("REVERSE_PROXY_INTERCEPT_ERRORS", "no", "Fehlerantworten der App (z.B. JSON) nicht durch BunkerWeb-Fehlerseite ersetzen"),
            ("REVERSE_PROXY_READ_TIMEOUT", "300s", ""),
            ("REVERSE_PROXY_SEND_TIMEOUT", "300s", ""),
            ("LIMIT_REQ_RATE", "20r/s", ""),
            ("ALLOWED_METHODS", ALL_METHODS, "APIs brauchen PUT/DELETE/PATCH, CORS-Preflights OPTIONS"),
        ] + [(k, "", "App setzt eigene Security-Header -> BunkerWeb-Defaults nicht hinzufuegen" if i == 0 else "")
             for i, k in enumerate(APP_HEADER_KEYS)] + [
            ("MODSECURITY_SEC_RULE_ENGINE", "DetectionOnly",
             "WAF erst nur protokollieren, nach Pruefung der Treffer auf \"On\" stellen"),
        ],
    },
    "standard": {
        "label": "Standard (BunkerWeb-Defaults)",
        "description": "Alle Methoden, BunkerWeb-Security-Header aktiv, WAF zuerst nur protokollieren.",
        "settings": [
            ("REVERSE_PROXY_WS", "yes", ""),
            ("REVERSE_PROXY_HEADERS", "X-Forwarded-Prefix ''", ""),
            ("REVERSE_PROXY_INTERCEPT_ERRORS", "no", ""),
            ("LIMIT_REQ_RATE", "20r/s", ""),
            ("ALLOWED_METHODS", ALL_METHODS, ""),
            ("MODSECURITY_SEC_RULE_ENGINE", "DetectionOnly",
             "WAF erst nur protokollieren, nach Pruefung der Treffer auf \"On\" stellen"),
        ],
    },
}

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
SETTING_KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]*(_[A-Za-z0-9][A-Za-z0-9_.-]*)?$")
HOST_RULE_RE = re.compile(r"^\s*Host\(`([^`]+)`\)\s*$")
HOSTS_IN_RULE_RE = re.compile(r"Host(?:SNI)?\(`([^`]+)`\)")


class DomainError(Exception):
    pass


def _now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ts_compact():
    return datetime.now().strftime("%Y%m%d-%H%M%S")


# --------------------------------------------------------------------------- #
# BunkerWeb-Sites-Datei
# --------------------------------------------------------------------------- #

_ENV_LINE_RE = re.compile(r"^      ([^\s:#][^:]*?):\s?(.*)$")
_SITE_HDR_RE = re.compile(r"^\s*#\s*=+\s*site:\s*(\S+)\s*=+\s*$")
_META_RE = re.compile(r"^\s*#\s*@meta:\s*(\{.*\})\s*$")
_COMMENT_RE = re.compile(r"^\s*#\s?(.*)$")


def _unescape(v):
    return v.replace("$$", "$")


def _escape(v):
    return v.replace("$", "$$")


def _yaml_scalar(v):
    return json.dumps(_escape(str(v)), ensure_ascii=True)


def empty_sites_state():
    return {"server_names": [], "sites": {}, "extra": []}


def read_bw_sites(path=None):
    """Parst die Sites-Datei -> {server_names, sites{domain:{meta, settings[{key,value,comment}]}}, extra[]}.
    extra = Keys, die keiner Site zuzuordnen sind (bleiben unveraendert erhalten)."""
    path = path or BW_SITES_FILE
    state = empty_sites_state()
    if not path or not os.path.exists(path):
        return state
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    parsed = yaml.safe_load(text) or {}
    env = (((parsed.get("services") or {}).get(BW_SCHEDULER_SERVICE) or {}).get("environment")) or {}
    if isinstance(env, list):
        raise DomainError("Sites-Datei: environment muss ein Mapping sein, keine Liste")
    server_names = str(env.get("SERVER_NAME", "")).split()
    state["server_names"] = server_names
    for d in server_names:
        state["sites"][d] = {"meta": {}, "settings": []}

    # Zeilenweise fuer Kommentare/Meta; Werte kommen aus dem YAML-Parse (robust).
    pending_comments = []
    current_site = None
    in_env = False
    for line in text.splitlines():
        if line.strip() == "environment:":
            in_env = True
            continue
        if not in_env:
            continue
        m = _SITE_HDR_RE.match(line)
        if m:
            current_site = m.group(1)
            pending_comments = []
            continue
        m = _META_RE.match(line)
        if m and current_site in state["sites"]:
            try:
                state["sites"][current_site]["meta"] = json.loads(m.group(1))
            except ValueError:
                pass
            continue
        m = _COMMENT_RE.match(line)
        if m:
            pending_comments.append(m.group(1).rstrip())
            continue
        if not line.strip():
            pending_comments = []
            continue
        m = _ENV_LINE_RE.match(line)
        if not m:
            continue
        key = m.group(1).strip().strip('"').strip("'")
        comment = "\n".join(pending_comments).strip()
        pending_comments = []
        if key == "SERVER_NAME" or key not in env:
            continue
        value = _unescape("" if env[key] is None else str(env[key]))
        site = None
        for d in sorted(server_names, key=len, reverse=True):
            if key.startswith(d + "_"):
                site = d
                break
        if site:
            state["sites"][site]["settings"].append(
                {"key": key[len(site) + 1:], "value": value, "comment": comment})
        else:
            state["extra"].append({"key": key, "value": value, "comment": comment})
    return state


def render_bw_sites(state):
    lines = [SITES_HEADER.rstrip("\n"), "services:", f"  {BW_SCHEDULER_SERVICE}:", "    environment:"]
    lines.append(f"      SERVER_NAME: {_yaml_scalar(' '.join(state['server_names']))}")
    for d in state["server_names"]:
        site = state["sites"].get(d) or {"meta": {}, "settings": []}
        lines.append("")
        lines.append(f"      # ==== site: {d} ====")
        meta = {k: v for k, v in (site.get("meta") or {}).items() if v not in (None, "")}
        if meta:
            lines.append(f"      # @meta: {json.dumps(meta, ensure_ascii=True, sort_keys=True)}")
        for s in site["settings"]:
            for c in (s.get("comment") or "").splitlines():
                lines.append(f"      # {c}".rstrip())
            lines.append(f"      {d}_{s['key']}: {_yaml_scalar(s['value'])}")
    if state.get("extra"):
        lines.append("")
        lines.append("      # ==== ohne Site-Zuordnung (unveraendert uebernommen) ====")
        for s in state["extra"]:
            for c in (s.get("comment") or "").splitlines():
                lines.append(f"      # {c}".rstrip())
            lines.append(f"      {s['key']}: {_yaml_scalar(s['value'])}")
    return "\n".join(lines) + "\n"


def _backup_file(path, label):
    if not os.path.exists(path):
        return None
    bdir = os.path.join(os.path.dirname(path), "backups")
    os.makedirs(bdir, exist_ok=True)
    dst = os.path.join(bdir, f"{label}-{_ts_compact()}-{int(time.time() * 1000) % 1000:03d}")
    shutil.copy2(path, dst)
    olds = sorted(p for p in os.listdir(bdir) if p.startswith(label + "-"))
    for p in olds[:-BACKUP_KEEP]:
        try:
            os.remove(os.path.join(bdir, p))
        except OSError:
            pass
    return dst


def _write_in_place(path, content):
    """In place schreiben (gleiche Inode) - wichtig fuer Einzeldatei-Bind-Mounts."""
    mode = "r+" if os.path.exists(path) else "w"
    with open(path, mode, encoding="utf-8") as f:
        f.seek(0)
        f.write(content)
        f.truncate()
        f.flush()
        os.fsync(f.fileno())


def write_bw_sites(state):
    text = render_bw_sites(state)
    # Round-trip-Pruefung, bevor die echte Datei angefasst wird.
    tmp = BW_SITES_FILE + ".tmp-check"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    try:
        back = read_bw_sites(tmp)
    finally:
        os.remove(tmp)
    if back["server_names"] != state["server_names"] or any(
        [(s["key"], s["value"]) for s in back["sites"][d]["settings"]]
        != [(s["key"], s["value"]) for s in state["sites"][d]["settings"]]
        for d in state["server_names"]
    ):
        raise DomainError("Interner Fehler: Sites-Datei liesse sich nicht identisch zuruecklesen")
    backup = _backup_file(BW_SITES_FILE, "sites")
    _write_in_place(BW_SITES_FILE, text)
    return backup


COUNTRY_KEYS = ("WHITELIST_COUNTRY", "BLACKLIST_COUNTRY")


def _cc_list(vals):
    if isinstance(vals, str):
        vals = re.split(r"[\s,;]+", vals)
    out = []
    for v in vals or []:
        v = str(v).strip().upper()
        if v and v not in out:
            out.append(v)
    return out


def effective_countries(svc, site, via_bw):
    """Laenderregel, wie sie fuer Besucher gilt (bzw. gemeint ist)."""
    ar = (svc or {}).get("access_restrictions") or {}
    nb_a, nb_b = _cc_list(ar.get("allowed_countries")), _cc_list(ar.get("blocked_countries"))
    st = site_settings_dict(site) if site else {}
    bw_a, bw_b = _cc_list(st.get("WHITELIST_COUNTRY", "")), _cc_list(st.get("BLACKLIST_COUNTRY", ""))
    if via_bw and (bw_a or bw_b or not (nb_a or nb_b)):
        return {"allowed": bw_a, "blocked": bw_b, "enforced_by": "bunkerweb", "nb_allowed": nb_a, "nb_blocked": nb_b}
    # ueber BW, aber Regel (noch falsch) nur in NetBird -> als gemeinte Regel uebernehmen
    return {"allowed": nb_a, "blocked": nb_b, "enforced_by": "bunkerweb" if via_bw else "netbird",
            "nb_allowed": nb_a, "nb_blocked": nb_b}


def site_settings_dict(site):
    return {s["key"]: s["value"] for s in (site or {}).get("settings", [])}


def normalize_site_settings(domain, settings):
    """Gesperrte Keys erzwingen (vorne, feste Reihenfolge), Rest in Eingabereihenfolge."""
    out = []
    by_key = {}
    for s in settings:
        k = str(s.get("key", "")).strip()
        if not k:
            continue
        by_key[k] = {"key": k, "value": str(s.get("value", "")), "comment": str(s.get("comment", "") or "").strip()}
    for k, fn in LOCKED_KEYS.items():
        prev = by_key.pop(k, None)
        out.append({"key": k, "value": fn(domain), "comment": (prev or {}).get("comment", "")})
    for s in settings:
        k = str(s.get("key", "")).strip()
        if k in by_key:
            out.append(by_key.pop(k))
    return out


def preset_settings(domain, preset):
    p = PRESETS.get(preset) or PRESETS["webapp"]
    return normalize_site_settings(domain, [{"key": k, "value": v, "comment": c} for k, v, c in p["settings"]])


# --------------------------------------------------------------------------- #
# BunkerWeb anwenden (bw-scheduler neu erstellen) + Settings-Katalog
# --------------------------------------------------------------------------- #

_CATALOG_SCRIPT = r"""
import json, glob
out = {}
def add(settings, plugin):
    for k, v in (settings or {}).items():
        out[k] = {"help": v.get("help", ""), "default": v.get("default", ""), "regex": v.get("regex", ""),
                  "context": v.get("context", ""), "type": v.get("type", ""), "select": v.get("select"),
                  "multiple": v.get("multiple", ""), "plugin": plugin}
s = json.load(open("/usr/share/bunkerweb/settings.json"))
add(s, "general")
for p in sorted(glob.glob("/usr/share/bunkerweb/core/*/plugin.json") + glob.glob("/etc/bunkerweb/plugins/*/plugin.json") + glob.glob("/etc/bunkerweb/pro/plugins/*/plugin.json")):
    try:
        j = json.load(open(p)); add(j.get("settings"), j.get("name") or j.get("id"))
    except Exception:
        pass
print(json.dumps(out))
"""

_catalog_cache = {"at": 0, "data": None}


def bw_settings_catalog(docker_client):
    if _catalog_cache["data"] and time.time() - _catalog_cache["at"] < 3600:
        return _catalog_cache["data"]
    c = docker_client().containers.get(BW_SCHEDULER_CONTAINER)
    res = c.exec_run(["python3", "-c", _CATALOG_SCRIPT])
    if res.exit_code != 0:
        raise DomainError("BunkerWeb-Settings-Katalog nicht lesbar: " + res.output.decode(errors="replace")[-300:])
    data = json.loads(res.output.decode())
    data = {k: v for k, v in data.items() if v.get("context") == "multisite"}
    _catalog_cache.update(at=time.time(), data=data)
    return data


def _catalog_lookup(catalog, key):
    if key in catalog:
        return catalog[key]
    m = re.match(r"^(.*)_(\d+)$", key)  # mehrfach-Settings: REVERSE_PROXY_HOST_1
    if m and m.group(1) in catalog and catalog[m.group(1)].get("multiple"):
        return catalog[m.group(1)]
    return None


def validate_site_settings(settings, catalog):
    errors, warnings = [], []
    seen = set()
    for s in settings:
        k, v = s["key"], s["value"]
        if k in seen:
            errors.append(f"{k}: doppelt")
        seen.add(k)
        if not SETTING_KEY_RE.match(k):
            errors.append(f"{k}: ungueltiger Name")
            continue
        if "\n" in v or "\r" in v:
            errors.append(f"{k}: Zeilenumbruch im Wert nicht erlaubt")
        if k.startswith("CUSTOM_CONF_"):
            if not re.match(r"^CUSTOM_CONF_(HTTP|SERVER_HTTP|DEFAULT_SERVER_HTTP|MODSEC_CRS|MODSEC|STREAM|SERVER_STREAM|CRS_PLUGINS_BEFORE|CRS_PLUGINS_AFTER)_[A-Za-z0-9_-]+$", k):
                errors.append(f"{k}: CUSTOM_CONF_<TYP>_<name> erwartet (z.B. CUSTOM_CONF_MODSEC_fp-xyz)")
            continue
        if catalog is None:
            continue
        info = _catalog_lookup(catalog, k)
        if not info:
            errors.append(f"{k}: unbekanntes BunkerWeb-Setting (oder nicht pro Site setzbar)")
            continue
        rx = info.get("regex") or ""
        if rx and v != "":
            try:
                if not re.search(rx, v):
                    errors.append(f"{k}: Wert \"{v}\" passt nicht zum erlaubten Format")
            except re.error:
                pass
    return errors, warnings


def _scheduler_logs_since(docker_client, since_ts):
    c = docker_client().containers.get(BW_SCHEDULER_CONTAINER)
    return c.logs(stdout=True, stderr=True, since=int(since_ts)).decode(errors="replace")


def bw_apply(docker_client, joblog):
    """bw-scheduler mit der aktuellen Sites-Datei neu erstellen und auf den Reload warten."""
    if not os.path.exists(COMPOSE_BIN):
        raise DomainError(f"docker-compose nicht gefunden ({COMPOSE_BIN})")
    t0 = time.time() - 1
    cmd = [COMPOSE_BIN, "up", "-d", "--no-deps", "--force-recreate", BW_SCHEDULER_SERVICE]
    joblog(f"$ docker compose up -d --no-deps --force-recreate {BW_SCHEDULER_SERVICE}")
    p = subprocess.run(cmd, cwd=BW_COMPOSE_DIR, capture_output=True, text=True, timeout=180)
    out = (p.stdout + p.stderr).strip()
    for line in out.splitlines()[-8:]:
        joblog("  " + line)
    if p.returncode != 0:
        raise DomainError(f"docker compose fehlgeschlagen (Exit {p.returncode})")
    joblog("Warte auf Konfigurations-Reload von BunkerWeb ...")
    deadline = time.time() + BW_APPLY_TIMEOUT
    warned = set()
    while time.time() < deadline:
        time.sleep(3)
        try:
            logs = _scheduler_logs_since(docker_client, t0)
        except Exception as e:  # Container evtl. gerade im Neustart
            joblog(f"  (Logs noch nicht lesbar: {e})")
            continue
        for line in logs.splitlines():
            if ("is not valid" in line or "Ignoring variable" in line) and line not in warned:
                warned.add(line)
                joblog("  WARNUNG: " + line[-300:])
        if "Successfully reloaded" in logs:
            joblog("BunkerWeb hat die neue Konfiguration geladen.")
            return {"warnings": sorted(warned)}
        # Nur Fehler beim Erzeugen/Laden der Konfiguration sind fatal (nicht z.B.
        # ein fehlgeschlagener Blacklist-Download eines Jobs).
        bad = [ln for ln in logs.splitlines() if "❌" in ln and any(
            x in ln for x in ("SAVE_CONFIG", "GENERATOR", "eload", "onfig"))]
        if bad:
            for ln in bad[-5:]:
                joblog("  FEHLER: " + ln[-300:])
            raise DomainError("BunkerWeb meldet einen Fehler beim Laden der Konfiguration")
    raise DomainError(f"Kein erfolgreicher Reload innerhalb von {BW_APPLY_TIMEOUT}s")


# --------------------------------------------------------------------------- #
# Traefik
# --------------------------------------------------------------------------- #

def read_traefik_file():
    if not TRAEFIK_DYNAMIC_PATH or not os.path.exists(TRAEFIK_DYNAMIC_PATH):
        return {}
    with open(TRAEFIK_DYNAMIC_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def traefik_file_bw_routers(data=None):
    """{domain: router_name} fuer File-Router auf den BunkerWeb-Service."""
    data = read_traefik_file() if data is None else data
    out = {}
    for name, r in (((data.get("http") or {}).get("routers")) or {}).items():
        if not isinstance(r, dict) or r.get("service") != TRAEFIK_BW_SERVICE:
            continue
        m = HOST_RULE_RE.match(str(r.get("rule", "")))
        if m:
            out[m.group(1).lower()] = name
    return out


def router_name_for(domain):
    return "bw-" + re.sub(r"[^a-z0-9]+", "-", domain.lower()).strip("-")


def write_traefik_file(data):
    body = yaml.safe_dump(data, sort_keys=False, default_flow_style=False, allow_unicode=True)
    text = TRAEFIK_HEADER + "\n" + body
    yaml.safe_load(text)  # Syntax-Check
    bdir_label = "traefik-dynamic"
    backup = None
    if BW_COMPOSE_DIR:
        # Backups neben den BW-Backups (Traefik-Verzeichnis ist nur die Einzeldatei)
        bdir = os.path.join(BW_COMPOSE_DIR, "backups")
        os.makedirs(bdir, exist_ok=True)
        backup = os.path.join(bdir, f"{bdir_label}-{_ts_compact()}-{int(time.time() * 1000) % 1000:03d}")
        shutil.copy2(TRAEFIK_DYNAMIC_PATH, backup)
        olds = sorted(p for p in os.listdir(bdir) if p.startswith(bdir_label + "-"))
        for p in olds[:-BACKUP_KEEP]:
            try:
                os.remove(os.path.join(bdir, p))
            except OSError:
                pass
    _write_in_place(TRAEFIK_DYNAMIC_PATH, text)
    return backup


def traefik_set_bw_router(domain, enabled):
    data = read_traefik_file()
    http = data.setdefault("http", {})
    routers = http.setdefault("routers", {}) or {}
    http["routers"] = routers
    existing = traefik_file_bw_routers(data)
    if enabled:
        if domain in existing:
            return False
        routers[router_name_for(domain)] = {
            "rule": f"Host(`{domain}`)",
            "entryPoints": [TRAEFIK_ENTRYPOINT],
            "priority": 100,
            "service": TRAEFIK_BW_SERVICE,
            "tls": {"certResolver": TRAEFIK_CERT_RESOLVER},
        }
    else:
        if domain not in existing:
            return False
        routers.pop(existing[domain], None)
    if not routers:
        http.pop("routers", None)
    if not http:
        data.pop("http", None)
    write_traefik_file(data)
    return True


def traefik_label_routers(docker_client):
    """HTTP-Router aus Docker-Labels: [{name, hosts[], service, container}] (nur lesen)."""
    out = []
    try:
        containers = docker_client().containers.list()
    except Exception as e:
        log.warning("Docker-Labels nicht lesbar: %s", e)
        return out
    for c in containers:
        labels = c.labels or {}
        if labels.get("traefik.enable") != "true":
            continue
        routers = {}
        for k, v in labels.items():
            m = re.match(r"^traefik\.http\.routers\.([^.]+)\.(rule|service)$", k)
            if m:
                routers.setdefault(m.group(1), {})[m.group(2)] = v
        for name, r in routers.items():
            hosts = [h.lower() for h in HOSTS_IN_RULE_RE.findall(r.get("rule", ""))]
            svc = r.get("service") or ""
            out.append({
                "name": name, "hosts": hosts, "rule": r.get("rule", ""),
                "service": svc if "@" in svc else (svc + "@docker" if svc else ""),
                "container": c.name,
                "path_limited": "PathPrefix" in r.get("rule", "") or "Path(" in r.get("rule", ""),
            })
    return out


# --------------------------------------------------------------------------- #
# Pruefungen (TLS-Zertifikat / HTTP) ueber Traefik
# --------------------------------------------------------------------------- #

def check_cert(domain, timeout=6):
    if not PROBE_HOST:
        return {"ok": None, "error": "DOMAINS_PROBE_HOST nicht gesetzt"}
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((PROBE_HOST, PROBE_PORT), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=domain) as t:
                c = t.getpeercert()
        not_after = datetime.strptime(c["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        issuer = dict(x[0] for x in c.get("issuer", ())).get("organizationName", "")
        return {"ok": True, "not_after": not_after.isoformat(), "issuer": issuer,
                "days_left": int((not_after - datetime.now(timezone.utc)).total_seconds() // 86400)}
    except ssl.SSLCertVerificationError as e:
        return {"ok": False, "error": f"Zertifikat ungueltig: {e.verify_message}"}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


def check_http(domain, path="/", timeout=15):
    """Ein einzelner GET ueber Traefik (TLS mit Pruefung). -> {ok, status, location, error}"""
    if not PROBE_HOST:
        return {"ok": None, "error": "DOMAINS_PROBE_HOST nicht gesetzt"}
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((PROBE_HOST, PROBE_PORT), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=domain) as t:
                t.sendall((f"GET {path} HTTP/1.1\r\nHost: {domain}\r\n"
                           "User-Agent: netbird-proxy-dashboard-check/1.0\r\nAccept: */*\r\n"
                           "Connection: close\r\n\r\n").encode())
                buf = b""
                while b"\r\n\r\n" not in buf and len(buf) < 65536:
                    chunk = t.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
        head = buf.split(b"\r\n\r\n", 1)[0].decode(errors="replace").split("\r\n")
        status = int(head[0].split()[1])
        location = next((h.split(":", 1)[1].strip() for h in head[1:] if h.lower().startswith("location:")), None)
        server = next((h.split(":", 1)[1].strip() for h in head[1:] if h.lower().startswith("server:")), None)
        return {"ok": status < 500, "status": status, "location": location, "server": server}
    except ssl.SSLCertVerificationError as e:
        return {"ok": False, "error": f"Zertifikat ungueltig: {e.verify_message}"}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


def resolve_dns(domain):
    try:
        return sorted({ai[4][0] for ai in socket.getaddrinfo(domain, 443, proto=socket.IPPROTO_TCP)})
    except socket.gaierror:
        return []


_cert_cache = {}
_cert_lock = threading.Lock()


def cert_status_bulk(domains, max_age=600, force=False):
    now = time.time()
    todo = [d for d in domains if force or d not in _cert_cache or now - _cert_cache[d]["at"] > max_age]
    if todo:
        with ThreadPoolExecutor(max_workers=8) as ex:
            for d, res in zip(todo, ex.map(check_cert, todo)):
                with _cert_lock:
                    _cert_cache[d] = {"at": now, "res": res}
    return {d: dict(_cert_cache[d]["res"], checked_at=_cert_cache[d]["at"]) for d in domains if d in _cert_cache}


# --------------------------------------------------------------------------- #
# NetBird
# --------------------------------------------------------------------------- #

class NetBird:
    def __init__(self, base, token):
        self.base = base
        self.token = token

    def _req(self, method, path, **kw):
        r = requests.request(method, f"{self.base}{path}", timeout=30, headers={
            "Accept": "application/json", "Content-Type": "application/json",
            "Authorization": f"Token {self.token}"}, **kw)
        if r.status_code >= 400:
            try:
                msg = r.json().get("message") or r.text
            except ValueError:
                msg = r.text
            raise DomainError(f"NetBird-API {method} {path}: HTTP {r.status_code} {msg[:300]}")
        return r.json() if r.content else None

    def services(self):
        return self._req("GET", "/api/reverse-proxies/services") or []

    def service(self, sid):
        return self._req("GET", f"/api/reverse-proxies/services/{sid}")

    def create(self, body):
        return self._req("POST", "/api/reverse-proxies/services", json=body)

    def update(self, sid, body):
        return self._req("PUT", f"/api/reverse-proxies/services/{sid}", json=body)

    def delete(self, sid):
        return self._req("DELETE", f"/api/reverse-proxies/services/{sid}")

    def proxy_domains(self):
        return self._req("GET", "/api/reverse-proxies/domains") or []

    def groups(self):
        return [{"id": g["id"], "name": g["name"]} for g in (self._req("GET", "/api/groups") or [])]

    def peers(self):
        return [{"id": p["id"], "name": p.get("name"), "ip": p.get("ip"), "connected": p.get("connected")}
                for p in (self._req("GET", "/api/peers") or [])]

    def resources(self):
        out = []
        for n in self._req("GET", "/api/networks") or []:
            for r in self._req("GET", f"/api/networks/{n['id']}/resources") or []:
                out.append({"id": r["id"], "name": r.get("name"), "type": r.get("type"),
                            "address": r.get("address"), "network": n.get("name"),
                            "enabled": r.get("enabled", True)})
        return out


REQUEST_FIELDS = ["name", "domain", "mode", "listen_port", "targets", "enabled", "pass_host_header",
                  "rewrite_redirects", "auth", "access_restrictions", "private", "access_groups"]


def service_to_request(svc):
    body = {k: copy.deepcopy(svc[k]) for k in REQUEST_FIELDS if k in svc and svc[k] is not None}
    # Secrets kommen nie zurueck (leer) -> NetBird uebernimmt beim PUT die bestehenden.
    return body


def build_service_request(spec, existing=None):
    """Formular-Spec -> ServiceRequest. Bestehende Felder (weitere Targets, Header-Auth, ...) bleiben."""
    body = service_to_request(existing) if existing else {
        "name": spec["domain"], "domain": spec["domain"], "mode": "http", "enabled": True,
        "pass_host_header": True, "rewrite_redirects": False, "targets": [],
        "auth": {}, "access_restrictions": {},
    }
    nb = spec.get("nb") or {}
    if "enabled" in nb:
        body["enabled"] = bool(nb["enabled"])
    for k in ("pass_host_header", "rewrite_redirects"):
        if k in nb:
            body[k] = bool(nb[k])
    t = nb.get("target")
    if t:
        new_t = copy.deepcopy(body["targets"][0]) if body.get("targets") else {
            "enabled": True, "access_action": "inherit", "options": {}}
        new_t.update({
            "target_type": t["target_type"], "target_id": t["target_id"],
            "host": t["host"], "port": int(t.get("port") or 0),
            "protocol": t.get("protocol") or "http",
        })
        opts = dict(new_t.get("options") or {})
        if t.get("skip_tls_verify"):
            opts["skip_tls_verify"] = True
        else:
            opts.pop("skip_tls_verify", None)
        new_t["options"] = opts
        if body.get("targets"):
            body["targets"][0] = new_t
        else:
            body["targets"] = [new_t]
    a = nb.get("auth")
    if a is not None:
        auth = body.setdefault("auth", {}) or {}
        body["auth"] = auth
        auth["bearer_auth"] = {"enabled": bool(a.get("sso_enabled")),
                               "distribution_groups": list(a.get("sso_groups") or []) or None}
        auth["password_auth"] = {"enabled": bool(a.get("password_enabled")), "password": a.get("password") or ""}
        auth["pin_auth"] = {"enabled": bool(a.get("pin_enabled")), "pin": a.get("pin") or ""}
    acc = nb.get("access")
    if acc is not None:
        ar = dict(body.get("access_restrictions") or {})
        for k in ("allowed_countries", "blocked_countries", "allowed_cidrs", "blocked_cidrs"):
            if k in acc:
                vals = [v.strip().upper() if "countries" in k else v.strip() for v in acc[k] if v and v.strip()]
                if vals:
                    ar[k] = vals
                else:
                    ar.pop(k, None)
        if acc.get("crowdsec_mode"):
            ar["crowdsec_mode"] = acc["crowdsec_mode"]
        body["access_restrictions"] = ar
    return body


def summarize_service(svc, groups_by_id=None):
    groups_by_id = groups_by_id or {}
    t = (svc.get("targets") or [{}])[0]
    auth = svc.get("auth") or {}
    ar = svc.get("access_restrictions") or {}
    bearer = auth.get("bearer_auth") or {}
    return {
        "id": svc.get("id"),
        "name": svc.get("name"),
        "enabled": svc.get("enabled"),
        "status": (svc.get("meta") or {}).get("status"),
        "certificate_issued_at": (svc.get("meta") or {}).get("certificate_issued_at"),
        "mode": svc.get("mode"),
        "target": {
            "target_type": t.get("target_type"), "target_id": t.get("target_id"),
            "host": t.get("host"), "port": t.get("port"), "protocol": t.get("protocol"),
            "skip_tls_verify": bool((t.get("options") or {}).get("skip_tls_verify")),
            "path": t.get("path"),
        },
        "targets_count": len(svc.get("targets") or []),
        "pass_host_header": svc.get("pass_host_header"),
        "rewrite_redirects": svc.get("rewrite_redirects"),
        "auth": {
            "sso_enabled": bool(bearer.get("enabled")),
            "sso_groups": bearer.get("distribution_groups") or [],
            "sso_group_names": [groups_by_id.get(g, g) for g in (bearer.get("distribution_groups") or [])],
            "password_enabled": bool((auth.get("password_auth") or {}).get("enabled")),
            "pin_enabled": bool((auth.get("pin_auth") or {}).get("enabled")),
            "header_auths": len(auth.get("header_auths") or []),
        },
        "access": {
            "allowed_countries": ar.get("allowed_countries") or [],
            "blocked_countries": ar.get("blocked_countries") or [],
            "allowed_cidrs": ar.get("allowed_cidrs") or [],
            "blocked_cidrs": ar.get("blocked_cidrs") or [],
            "crowdsec_mode": ar.get("crowdsec_mode") or "off",
        },
    }


# --------------------------------------------------------------------------- #
# Blueprint / Orchestrierung
# --------------------------------------------------------------------------- #

def register(app, get_conn, nb_base, nb_token, docker_client, backup_sync_lookup=None):
    bp = Blueprint("domains", __name__)
    nb = NetBird(nb_base, nb_token)
    configured = bool(BW_COMPOSE_DIR and BW_SITES_FILE and TRAEFIK_DYNAMIC_PATH and nb_base and nb_token)
    job_lock = threading.Lock()
    lookups_cache = {"at": 0, "data": None}

    conn = get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS domain_jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            action TEXT NOT NULL,
            created_at TEXT NOT NULL,
            finished_at TEXT,
            status TEXT NOT NULL,
            summary TEXT,
            plan TEXT,
            log TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_domain_jobs_created ON domain_jobs(created_at)")
    # Nach Neustart haengengebliebene Jobs abschliessen
    conn.execute("UPDATE domain_jobs SET status='error', summary='Abgebrochen (Dashboard-Neustart)', "
                 "finished_at=? WHERE status='running'", (_now_iso(),))
    conn.commit()
    conn.close()

    def _lookups(force=False):
        if not force and lookups_cache["data"] and time.time() - lookups_cache["at"] < 300:
            return lookups_cache["data"]
        data = {"groups": nb.groups(), "peers": nb.peers(), "resources": nb.resources(),
                "proxy_domains": [d for d in nb.proxy_domains() if d.get("validated")]}
        lookups_cache.update(at=time.time(), data=data)
        return data

    def _traffic_stats():
        """Pro Host: Requests/Fehler der letzten 24h + stuendliche Verteilung (aus den NetBird-Events)."""
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).strftime("%Y-%m-%dT%H")
        c = get_conn()
        rows = c.execute("""
            SELECT host, substr(timestamp, 1, 13) AS h, COUNT(*) AS n,
                   SUM(CASE WHEN status_code >= 500 THEN 1 ELSE 0 END) AS e5,
                   SUM(CASE WHEN status_code IN (401, 403, 429) THEN 1 ELSE 0 END) AS den,
                   MAX(timestamp) AS last
            FROM proxy_events WHERE timestamp >= ? GROUP BY host, h
        """, (cutoff,)).fetchall()
        bw_rows = []
        try:
            bw_rows = c.execute("""
                SELECT host, COUNT(*) AS n FROM bunkerweb_requests
                WHERE state = 'blocked' AND timestamp >= ? GROUP BY host
            """, (cutoff,)).fetchall()
        except Exception:
            pass
        c.close()
        now_h = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
        hours = [(now_h - timedelta(hours=i)).strftime("%Y-%m-%dT%H") for i in range(23, -1, -1)]
        idx = {h: i for i, h in enumerate(hours)}
        out = {}
        for r in rows:
            host = (r["host"] or "").lower()
            s = out.setdefault(host, {"requests": 0, "errors_5xx": 0, "denied": 0, "last": None,
                                      "hourly": [0] * 24, "bw_blocked": 0})
            s["requests"] += r["n"]
            s["errors_5xx"] += r["e5"] or 0
            s["denied"] += r["den"] or 0
            s["last"] = max(s["last"] or "", r["last"] or "") or None
            if r["h"] in idx:
                s["hourly"][idx[r["h"]]] += r["n"]
        for r in bw_rows:
            host = (r["host"] or "").lower()
            s = out.setdefault(host, {"requests": 0, "errors_5xx": 0, "denied": 0, "last": None,
                                      "hourly": [0] * 24, "bw_blocked": 0})
            s["bw_blocked"] = r["n"]
        return out

    def _bw_summary(domain, site):
        st = site_settings_dict(site)
        if st.get("USE_MODSECURITY", "yes") == "no":
            waf = "Off"
        else:
            waf = st.get("MODSECURITY_SEC_RULE_ENGINE", "On") or "On"
        return {
            "configured": True,
            "preset": (site.get("meta") or {}).get("preset"),
            "note": (site.get("meta") or {}).get("note", ""),
            "waf": waf,
            "methods": st.get("ALLOWED_METHODS", "GET|POST|HEAD (Default)"),
            "rate": st.get("LIMIT_REQ_RATE", "2r/s (Default)"),
            "whitelist": st.get("WHITELIST_IP", ""),
            "app_headers": all(st.get(k, None) == "" for k in APP_HEADER_KEYS),
            "settings": site.get("settings", []),
        }

    def collect_overview():
        errors = []
        try:
            services = nb.services()
        except Exception as e:
            services = []
            errors.append(f"NetBird: {e}")
        try:
            groups_by_id = {g["id"]: g["name"] for g in _lookups()["groups"]}
        except Exception as e:
            groups_by_id = {}
            errors.append(f"NetBird-Gruppen: {e}")
        try:
            sites = read_bw_sites()
        except Exception as e:
            sites = empty_sites_state()
            errors.append(f"BunkerWeb-Sites-Datei: {e}")
        try:
            file_routers = traefik_file_bw_routers()
        except Exception as e:
            file_routers = {}
            errors.append(f"Traefik-Datei: {e}")
        label_routers = traefik_label_routers(docker_client)
        traffic = _traffic_stats()
        backup = backup_sync_lookup() if backup_sync_lookup else {}

        label_bw = {}
        infra = {}
        for r in label_routers:
            for h in r["hosts"]:
                if r["service"] == TRAEFIK_BW_SERVICE:
                    label_bw[h] = r["name"]
                else:
                    infra.setdefault(h, []).append(r)

        nb_by_domain = {}
        for s in services:
            nb_by_domain.setdefault((s.get("domain") or "").lower(), s)
        domains = set(nb_by_domain) | set(sites["sites"]) | set(file_routers) | set(label_bw)
        items = []
        for d in sorted(domains, key=lambda x: (x.split(".")[-2:], x)):
            svc = nb_by_domain.get(d)
            site = sites["sites"].get(d)
            router_src = "file" if d in file_routers else ("label" if d in label_bw else None)
            route = "bunkerweb" if router_src else ("traefik" if d in infra and not svc else "passthrough")
            issues = []
            if router_src and not site:
                issues.append({"level": "error", "text": "Traefik-Router auf BunkerWeb, aber keine BunkerWeb-Site -> Anfragen scheitern"})
            if site and not router_src:
                issues.append({"level": "warn", "text": "BunkerWeb-Site konfiguriert, aber kein Traefik-Router -> Verkehr laeuft direkt (BunkerWeb inaktiv)"})
            if site and not svc:
                issues.append({"level": "error", "text": "BunkerWeb-Site ohne NetBird-Service -> netbird-proxy kennt die Domain nicht"})
            if svc and svc.get("enabled") is False:
                issues.append({"level": "warn", "text": "NetBird-Service deaktiviert"})
            if svc and (svc.get("meta") or {}).get("status") not in (None, "active"):
                issues.append({"level": "warn", "text": f"NetBird-Status: {(svc.get('meta') or {}).get('status')}"})
            if router_src == "label":
                issues.append({"level": "info", "text": "Traefik-Router als Docker-Label (im Dashboard nur lesbar)"})
            countries = effective_countries(svc, site, route == "bunkerweb")
            if route == "bunkerweb" and countries["nb_allowed"]:
                issues.append({"level": "error", "text":
                               "NetBird-Laenderliste \"nur erlauben\" ("
                               + " ".join(countries["nb_allowed"]) + ") sperrt hinter BunkerWeb ALLE Besucher "
                               "(NetBird sieht nur die BunkerWeb-IP). Einmal speichern verschiebt sie nach BunkerWeb."})
            elif route == "bunkerweb" and countries["nb_blocked"]:
                issues.append({"level": "warn", "text":
                               "NetBird-Laendersperre wirkt hinter BunkerWeb nicht. Einmal speichern verschiebt sie nach BunkerWeb."})
            items.append({
                "domain": d,
                "route": route,
                "traefik": {"router_source": router_src,
                            "router": file_routers.get(d) or label_bw.get(d),
                            "infra": [{"name": r["name"], "container": r["container"], "rule": r["rule"],
                                       "path_limited": r["path_limited"]} for r in infra.get(d, [])]},
                "nb": summarize_service(svc, groups_by_id) if svc else None,
                "bw": _bw_summary(d, site) if site else None,
                "traffic": traffic.get(d),
                "backup_sync": backup.get(d),
                "countries": countries,
                "issues": issues,
            })
        # Reine Traefik-Infrastruktur (z.B. netbird.cercatrova.me), die nicht schon oben steht
        for h, rs in infra.items():
            if h in domains:
                continue
            items.append({
                "domain": h, "route": "traefik",
                "traefik": {"router_source": "label", "router": rs[0]["name"],
                            "infra": [{"name": r["name"], "container": r["container"], "rule": r["rule"],
                                       "path_limited": r["path_limited"]} for r in rs]},
                "nb": None, "bw": None, "traffic": traffic.get(h), "backup_sync": None, "issues": [],
            })
        return {"items": items, "errors": errors, "generated_at": _now_iso(),
                "configured": configured, "probe_configured": bool(PROBE_HOST)}

    # ---------------- Planung ----------------

    def _validate_spec(spec, is_new):
        d = str(spec.get("domain", "")).strip().lower()
        if not DOMAIN_RE.match(d):
            raise DomainError("Ungueltiger Domainname")
        spec["domain"] = d
        nbs = spec.get("nb") or {}
        t = nbs.get("target")
        if is_new and not t:
            raise DomainError("Ziel (Backend) fehlt")
        if t:
            if t.get("target_type") not in ("host", "subnet", "peer", "domain"):
                raise DomainError("Ungueltiger Zieltyp")
            if not t.get("target_id"):
                raise DomainError("Ziel-Ressource/Peer fehlt")
            host = str(t.get("host") or "").strip()
            if not host:
                raise DomainError("Ziel-Host/IP fehlt")
            t["host"] = host
            try:
                port = int(t.get("port") or 0)
            except (TypeError, ValueError):
                raise DomainError("Ungueltiger Port")
            if not 0 <= port <= 65535:
                raise DomainError("Ungueltiger Port")
            if t.get("protocol") not in ("http", "https"):
                raise DomainError("Protokoll muss http oder https sein")
        acc = nbs.get("access") or {}
        for k in ("allowed_countries", "blocked_countries"):
            for c in acc.get(k) or []:
                if not re.match(r"^[A-Za-z]{2}$", c.strip()):
                    raise DomainError(f"Laendercode ungueltig: {c}")
        for k in ("allowed_cidrs", "blocked_cidrs"):
            for c in acc.get(k) or []:
                try:
                    ipaddress.ip_network(c.strip(), strict=False)
                except ValueError:
                    raise DomainError(f"CIDR ungueltig: {c}")
        if acc.get("crowdsec_mode") and acc["crowdsec_mode"] not in ("off", "observe", "enforce"):
            raise DomainError("Ungueltiger CrowdSec-Modus")
        a = nbs.get("auth") or {}
        if a.get("pin_enabled") and a.get("pin") and not re.match(r"^\d{4,12}$", str(a["pin"])):
            raise DomainError("PIN: 4-12 Ziffern")
        return d

    def make_plan(spec):
        """Vergleicht Wunsch-Zustand mit Ist-Zustand -> Schritte + Diffs (noch nichts ausfuehren)."""
        action = spec.get("action", "save")
        if action not in ("save", "create", "delete"):
            raise DomainError("Unbekannte Aktion")
        is_new = action == "create"
        domain = _validate_spec(spec, is_new)

        services = nb.services()
        svc = next((s for s in services if (s.get("domain") or "").lower() == domain), None)
        sites = read_bw_sites()
        site = sites["sites"].get(domain)
        file_routers = traefik_file_bw_routers()
        label_bw = {h for r in traefik_label_routers(docker_client) if r["service"] == TRAEFIK_BW_SERVICE for h in r["hosts"]}

        if is_new and (svc or site or domain in file_routers):
            raise DomainError("Domain existiert bereits - bitte bearbeiten statt neu anlegen")
        if not is_new and not (svc or site or domain in file_routers):
            raise DomainError("Domain nicht gefunden")
        if domain in label_bw:
            raise DomainError("Router dieser Domain ist ein Docker-Label (bunkerweb-Compose) - zuerst in die Traefik-Datei verschieben")

        steps, warnings = [], []
        plan = {"domain": domain, "action": action, "steps": steps, "warnings": warnings,
                "nb_diff": [], "bw_diff": [], "dns": None}

        if action == "delete":
            if domain in file_routers:
                steps.append({"kind": "traefik_off", "system": "Traefik",
                              "text": f"Router {file_routers[domain]} entfernen (Domain verlaesst BunkerWeb sofort)"})
            if site:
                steps.append({"kind": "bw_remove", "system": "BunkerWeb",
                              "text": "Site aus BunkerWeb entfernen und bw-scheduler neu laden"})
            if svc:
                steps.append({"kind": "nb_delete", "system": "NetBird",
                              "text": f"NetBird-Service {svc['id']} loeschen (Domain danach nicht mehr erreichbar)",
                              "service_id": svc["id"]})
            warnings.append("Loeschen ist endgueltig. Ein NetBird-Service kann nur neu angelegt werden "
                            "(Passwort/PIN muessen dann neu gesetzt werden).")
            return plan

        # ---- Laenderregeln: wirken nur dort, wo die echte Client-IP sichtbar ist.
        # Direkt (Passthrough) -> netbird-proxy. Ueber BunkerWeb sieht netbird-proxy nur
        # 172.30.0.20 (kein Land): eine NetBird-Allowlist wuerde dann ALLE sperren, eine
        # Blocklist nichts. Deshalb setzt das Dashboard sie je nach Weg in NetBird ODER
        # BunkerWeb (WHITELIST_COUNTRY / BLACKLIST_COUNTRY).
        bw = spec.get("bw")
        has_router = domain in file_routers
        currently_bw = bool(has_router and site)
        final_bw = bool(bw.get("enabled")) if bw is not None else currently_bw
        cur = effective_countries(svc, site, currently_bw)
        nb_acc_spec = ((spec.get("nb") or {}).get("access")) or {}
        desired_allowed = _cc_list(nb_acc_spec["allowed_countries"]) if "allowed_countries" in nb_acc_spec else cur["allowed"]
        desired_blocked = _cc_list(nb_acc_spec["blocked_countries"]) if "blocked_countries" in nb_acc_spec else cur["blocked"]
        plan["countries"] = {"allowed": desired_allowed, "blocked": desired_blocked,
                             "enforced_by": "bunkerweb" if final_bw else "netbird"}

        # ---- NetBird
        nb_steps = []
        new_body = None
        if spec.get("nb") is not None or svc:
            nb_spec = copy.deepcopy(spec.get("nb") or {})
            acc = dict(nb_spec.get("access") or {})
            acc["allowed_countries"] = [] if final_bw else desired_allowed
            acc["blocked_countries"] = [] if final_bw else desired_blocked
            nb_spec["access"] = acc
            if svc or spec.get("nb") is not None:
                new_body = build_service_request({"domain": domain, "nb": nb_spec}, svc)
        if new_body is not None and svc:
            old_body = service_to_request(svc)
            diff = _dict_diff(old_body, new_body)
            plan["nb_diff"] = diff
            if diff:
                nb_steps.append({"kind": "nb_update", "system": "NetBird",
                                 "text": f"NetBird-Service aktualisieren ({len(diff)} Aenderung(en))",
                                 "service_id": svc["id"]})
        elif new_body is not None:
            plan["nb_diff"] = _dict_diff({}, new_body)
            nb_steps.append({"kind": "nb_create", "system": "NetBird",
                             "text": "NetBird-Service anlegen (Backend-Verbindung, Zertifikat fuer Passthrough)"})
            pdoms = [x["domain"] for x in nb.proxy_domains() if x.get("validated")]
            if not any(domain == p or domain.endswith("." + p) for p in pdoms):
                raise DomainError("Domain gehoert zu keiner in NetBird validierten Basis-Domain "
                                  f"({', '.join(pdoms)}). Zuerst in NetBird unter Reverse Proxy -> Domains hinzufuegen.")
            plan["dns"] = {"domain": resolve_dns(domain), "reference": resolve_dns(_reference_domain(services))}
            if plan["dns"]["domain"] and plan["dns"]["reference"] and not set(plan["dns"]["domain"]) & set(plan["dns"]["reference"]):
                warnings.append("DNS der Domain zeigt nicht auf dieselbe IP wie die anderen Domains - "
                                "Zertifikat und Erreichbarkeit schlagen fehl, bis DNS stimmt.")
            elif not plan["dns"]["domain"]:
                warnings.append("Domain ist (noch) nicht im DNS aufloesbar - Zertifikat wird erst nach DNS-Eintrag ausgestellt.")
        if spec.get("nb") is not None:
            pw = ((spec.get("nb") or {}).get("auth") or {})
            if pw.get("password_enabled") and not pw.get("password") and not (
                    svc and ((svc.get("auth") or {}).get("password_auth") or {}).get("enabled")):
                raise DomainError("Passwort-Schutz aktiviert, aber kein Passwort gesetzt")
            if pw.get("pin_enabled") and not pw.get("pin") and not (
                    svc and ((svc.get("auth") or {}).get("pin_auth") or {}).get("enabled")):
                raise DomainError("PIN-Schutz aktiviert, aber keine PIN gesetzt")

        # ---- BunkerWeb
        bw_steps = []
        new_site = None
        if final_bw:
            settings = (bw or {}).get("settings")
            if settings is None:
                settings = site["settings"] if site else preset_settings(domain, (bw or {}).get("preset") or "webapp")
            settings = [dict(x) for x in settings if x.get("key") not in COUNTRY_KEYS]
            for key, vals in (("WHITELIST_COUNTRY", desired_allowed), ("BLACKLIST_COUNTRY", desired_blocked)):
                if vals:
                    old_c = next((x.get("comment", "") for x in (site or {}).get("settings", []) if x["key"] == key), "")
                    settings.append({"key": key, "value": " ".join(vals),
                                     "comment": old_c or "Laenderregel aus dem Dashboard (wirkt hier statt in NetBird)"})
            settings = normalize_site_settings(domain, settings)
            try:
                catalog = bw_settings_catalog(docker_client)
            except Exception as e:
                catalog = None
                warnings.append(f"BunkerWeb-Settings konnten nicht validiert werden: {e}")
            errs, _ = validate_site_settings(settings, catalog)
            if errs:
                raise DomainError("BunkerWeb-Settings: " + "; ".join(errs))
            bwm = bw or {}
            meta = {"preset": (bwm.get("preset") or (site or {}).get("meta", {}).get("preset") or ""),
                    "note": str(bwm.get("note", (site or {}).get("meta", {}).get("note", "")) or "")[:500]}
            new_site = {"meta": meta, "settings": settings}
            old_pairs = {x["key"]: x["value"] for x in (site or {}).get("settings", [])}
            new_pairs = {x["key"]: x["value"] for x in settings}
            plan["bw_diff"] = _flat_diff(old_pairs, new_pairs)
            old_comments = {x["key"]: x.get("comment", "") for x in (site or {}).get("settings", [])}
            comment_changed = any(old_comments.get(x["key"], "") != x.get("comment", "") for x in settings)
            meta_changed = (site or {}).get("meta", {}) != {k: v for k, v in meta.items() if v}
            if not site:
                bw_steps.append({"kind": "bw_write", "system": "BunkerWeb",
                                 "text": f"Site anlegen ({len(settings)} Settings) und bw-scheduler neu laden"})
            elif plan["bw_diff"]:
                bw_steps.append({"kind": "bw_write", "system": "BunkerWeb",
                                 "text": f"Site-Settings aendern ({len(plan['bw_diff'])} Aenderung(en)) und bw-scheduler neu laden"})
            elif comment_changed or meta_changed:
                bw_steps.append({"kind": "bw_write_noreload", "system": "BunkerWeb",
                                 "text": "Nur Notiz/Kommentare aktualisieren (kein Reload noetig)"})
        elif bw is not None and site:
            bw_steps.append({"kind": "bw_remove", "system": "BunkerWeb",
                             "text": "Site aus BunkerWeb entfernen und bw-scheduler neu laden"})
            plan["bw_diff"] = _flat_diff(site_settings_dict(site), {})

        # ---- Reihenfolge: nie ein Fenster, in dem die Laenderregel fehlt.
        create = [x for x in nb_steps if x["kind"] == "nb_create"]
        upd = [x for x in nb_steps if x["kind"] == "nb_update"]
        if final_bw and not has_router:
            # auf BunkerWeb: Site (inkl. Laender) -> Router -> Zertifikat -> erst dann
            # NetBird-Laender entfernen (bis dahin hoechstens kurz zu streng, nie offen)
            steps += create + bw_steps
            steps.append({"kind": "traefik_on", "system": "Traefik",
                          "text": f"Router {router_name_for(domain)} anlegen: Domain laeuft ab jetzt ueber BunkerWeb"})
            steps.append({"kind": "wait_cert", "system": "Pruefung",
                          "text": "Warten auf Let's-Encrypt-Zertifikat von Traefik (TLS-Challenge)"})
            steps += upd
            warnings.append("Beim Wechsel auf BunkerWeb stellt Traefik ein eigenes Zertifikat aus: "
                            "ca. 10-60 s sehen Besucher eine Zertifikatswarnung. Klappt es nicht, "
                            "wird der Router automatisch wieder entfernt.")
            if desired_allowed or desired_blocked:
                warnings.append("Laenderregel wandert von NetBird nach BunkerWeb (sie wird erst in NetBird "
                                "entfernt, wenn der Weg ueber BunkerWeb steht).")
        elif not final_bw and has_router:
            # zurueck auf direkt: zuerst NetBird-Laender setzen, dann Router weg
            steps += upd + create
            steps.append({"kind": "traefik_off", "system": "Traefik",
                          "text": f"Router {file_routers[domain]} entfernen: Domain laeuft wieder direkt ueber netbird-proxy"})
            steps += bw_steps
            if desired_allowed or desired_blocked:
                warnings.append("Laenderregel wandert von BunkerWeb zurueck nach NetBird. Zwischen dem NetBird-Update "
                                "und dem Entfernen des Routers (wenige Sekunden) werden alle Besucher abgewiesen.")
        else:
            steps += nb_steps + bw_steps
            if is_new and not final_bw:
                steps.append({"kind": "wait_cert", "system": "Pruefung",
                              "text": "Warten auf Zertifikat von netbird-proxy"})
        if steps and any(x["kind"] not in ("bw_write_noreload",) for x in steps):
            steps.append({"kind": "http_check", "system": "Pruefung", "text": "Testaufruf https://" + domain + "/"})
        plan["_new_body"] = new_body
        plan["_new_site"] = new_site
        plan["_svc"] = svc
        return plan

    def _reference_domain(services):
        for s in services:
            if s.get("enabled") and (s.get("meta") or {}).get("status") == "active":
                return s["domain"]
        return ""

    def public_plan(plan):
        return {k: v for k, v in plan.items() if not k.startswith("_")}

    # ---------------- Ausfuehrung ----------------

    def _job_update(job_id, **fields):
        c = get_conn()
        sets = ", ".join(f"{k} = ?" for k in fields)
        c.execute(f"UPDATE domain_jobs SET {sets} WHERE id = ?", (*fields.values(), job_id))
        c.commit()
        c.close()

    def run_job(job_id, plan):
        lines = []
        last_flush = [0.0]

        def joblog(msg):
            stamp = datetime.now().strftime("%H:%M:%S")
            lines.append(f"[{stamp}] {msg}")
            log.info("domain-job %s: %s", job_id, msg)
            if time.time() - last_flush[0] > 0.5:
                _job_update(job_id, log="\n".join(lines))
                last_flush[0] = time.time()

        domain = plan["domain"]
        undo = []  # (Beschreibung, fn)
        status, summary = "ok", "Erfolgreich"
        try:
            pre = None
            route_change = any(s["kind"] in ("traefik_on", "traefik_off") for s in plan["steps"])
            if plan["action"] != "delete" and plan["action"] != "create":
                pre = check_http(domain)
                joblog(f"Vorher-Test: {_fmt_http(pre)}")
            for i, step in enumerate(plan["steps"], 1):
                joblog(f"Schritt {i}/{len(plan['steps'])} [{step['system']}] {step['text']}")
                kind = step["kind"]
                if kind == "nb_create":
                    created = nb.create(plan["_new_body"])
                    sid = created["id"]
                    joblog(f"  NetBird-Service angelegt: {sid}")
                    undo.append(("NetBird-Service wieder loeschen", lambda sid=sid: nb.delete(sid)))
                elif kind == "nb_update":
                    old = service_to_request(plan["_svc"])
                    nb.update(step["service_id"], plan["_new_body"])
                    joblog("  NetBird-Service aktualisiert")
                    undo.append(("NetBird-Service zuruecksetzen",
                                 lambda sid=step["service_id"], old=old: nb.update(sid, old)))
                elif kind == "nb_delete":
                    nb.delete(step["service_id"])
                    joblog("  NetBird-Service geloescht")
                elif kind in ("bw_write", "bw_write_noreload", "bw_remove"):
                    sites = read_bw_sites()
                    prev = copy.deepcopy(sites)
                    if kind == "bw_remove":
                        sites["server_names"] = [d for d in sites["server_names"] if d != domain]
                        sites["sites"].pop(domain, None)
                    else:
                        if domain not in sites["server_names"]:
                            sites["server_names"].append(domain)
                        sites["sites"][domain] = plan["_new_site"]
                    backup = write_bw_sites(sites)
                    joblog(f"  Sites-Datei geschrieben (Backup: {os.path.basename(backup) if backup else '-'})")

                    def _restore(prev=prev, reload=(kind != "bw_write_noreload")):
                        write_bw_sites(prev)
                        if reload:
                            bw_apply(docker_client, joblog)
                    undo.append(("BunkerWeb-Sites-Datei zuruecksetzen", _restore))
                    if kind != "bw_write_noreload":
                        res = bw_apply(docker_client, joblog)
                        if res["warnings"]:
                            raise DomainError("BunkerWeb hat Settings verworfen (siehe Warnungen)")
                elif kind == "traefik_on":
                    traefik_set_bw_router(domain, True)
                    joblog(f"  Router {router_name_for(domain)} aktiv (Traefik laedt die Datei live)")
                    undo.append(("Traefik-Router wieder entfernen", lambda: traefik_set_bw_router(domain, False)))
                elif kind == "traefik_off":
                    old_data = read_traefik_file()
                    traefik_set_bw_router(domain, False)
                    joblog("  Router entfernt")
                    undo.append(("Traefik-Router wiederherstellen", lambda old=old_data: write_traefik_file(old)))
                elif kind == "wait_cert":
                    time.sleep(3)
                    deadline = time.time() + CERT_WAIT_SECONDS
                    res = None
                    while time.time() < deadline:
                        res = check_cert(domain)
                        if res.get("ok"):
                            break
                        time.sleep(5)
                    if not res or not res.get("ok"):
                        msg = (res or {}).get("error", "unbekannt")
                        if plan["action"] == "create" and not any(s["kind"] == "traefik_on" for s in plan["steps"]):
                            joblog(f"  WARNUNG: noch kein gueltiges Zertifikat ({msg}) - wird oft nachgeholt, sobald DNS stimmt")
                            status, summary = "warn", "Angelegt, aber Zertifikat noch nicht gueltig"
                            continue
                        raise DomainError(f"Kein gueltiges Zertifikat nach {CERT_WAIT_SECONDS}s: {msg}")
                    joblog(f"  Zertifikat gueltig ({res['issuer']}, {res['days_left']} Tage)")
                    _cert_cache[domain] = {"at": time.time(), "res": res}
                elif kind == "http_check":
                    time.sleep(2)
                    res = check_http(domain)
                    joblog(f"  Ergebnis: {_fmt_http(res)}")
                    if plan["action"] == "delete":
                        continue
                    bad_now = not res.get("ok")
                    was_ok = pre is None or pre.get("ok")
                    if bad_now and was_ok and pre is not None:
                        raise DomainError("Testaufruf fehlgeschlagen, vorher funktionierte die Domain")
                    # Wegwechsel: ein neues 401/403 heisst fast immer "jetzt fuer alle gesperrt"
                    # (z.B. Laenderregel am falschen Ort) -> nicht als Erfolg werten.
                    if (route_change and pre and pre.get("status") and res.get("status") in (401, 403)
                            and pre["status"] not in (401, 403)):
                        raise DomainError(f"Testaufruf liefert jetzt HTTP {res['status']}, vorher {pre['status']} "
                                          "- Domain waere vermutlich fuer alle gesperrt")
                    if bad_now:
                        status, summary = "warn", f"Ausgefuehrt, Testaufruf aber nicht OK ({_fmt_http(res)})"
            _cert_cache.pop(domain, None)
        except Exception as e:
            log.exception("domain-job %s fehlgeschlagen", job_id)
            joblog(f"FEHLER: {e}")
            status, summary = "error", str(e)
            if undo:
                joblog("Rollback der bereits ausgefuehrten Schritte ...")
                for desc, fn in reversed(undo):
                    try:
                        joblog(f"  Rollback: {desc}")
                        fn()
                    except Exception as ue:
                        joblog(f"  Rollback-FEHLER ({desc}): {ue} - bitte manuell pruefen!")
                        summary += " | Rollback unvollstaendig"
                status = "rolled_back" if "unvollstaendig" not in summary else "error"
        finally:
            joblog(f"Fertig: {summary}")
            _job_update(job_id, status=status, summary=summary, finished_at=_now_iso(), log="\n".join(lines))
            lookups_cache["at"] = 0
            job_lock.release()

    def _fmt_http(res):
        if res is None:
            return "-"
        if res.get("status"):
            s = f"HTTP {res['status']}"
            if res.get("location"):
                s += f" -> {res['location']}"
            if res.get("server"):
                s += f" (Server: {res['server']})"
            return s
        return res.get("error") or "-"

    # ---------------- Routen ----------------

    @bp.route("/domains")
    def domains_page():
        return render_template("domains.html")

    @bp.route("/api/domains")
    def api_domains():
        return jsonify(collect_overview())

    @bp.route("/api/domains/certs")
    def api_domain_certs():
        names = [d for d in request.args.get("domains", "").split(",") if DOMAIN_RE.match(d)]
        force = request.args.get("force") == "1"
        return jsonify(cert_status_bulk(names[:100], force=force))

    @bp.route("/api/domains/lookups")
    def api_domain_lookups():
        try:
            data = dict(_lookups(force=request.args.get("force") == "1"))
        except Exception as e:
            return jsonify(error=str(e)), 502
        data["presets"] = {k: {"label": v["label"], "description": v["description"]} for k, v in PRESETS.items()}
        data["locked_keys"] = list(LOCKED_KEYS)
        data["app_header_keys"] = APP_HEADER_KEYS
        data["country_keys"] = list(COUNTRY_KEYS)
        return jsonify(data)

    @bp.route("/api/domains/bw-catalog")
    def api_bw_catalog():
        try:
            return jsonify(bw_settings_catalog(docker_client))
        except Exception as e:
            return jsonify(error=str(e)), 502

    @bp.route("/api/domains/preset/<preset>")
    def api_preset(preset):
        domain = request.args.get("domain", "example.org").lower()
        if preset not in PRESETS:
            return jsonify(error="unbekannt"), 404
        return jsonify(settings=preset_settings(domain, preset))

    @bp.route("/api/domains/check/<domain>", methods=["POST"])
    def api_domain_check(domain):
        domain = domain.lower()
        if not DOMAIN_RE.match(domain):
            return jsonify(error="ungueltig"), 400
        cert = check_cert(domain)
        _cert_cache[domain] = {"at": time.time(), "res": cert}
        return jsonify(cert=cert, http=check_http(domain), dns=resolve_dns(domain))

    @bp.route("/api/domains/plan", methods=["POST"])
    def api_domain_plan():
        if not configured:
            return jsonify(error="Domain-Verwaltung nicht konfiguriert (BW_COMPOSE_DIR / TRAEFIK_DYNAMIC_PATH)"), 503
        try:
            plan = make_plan(request.get_json(force=True) or {})
        except DomainError as e:
            return jsonify(error=str(e)), 400
        except Exception as e:
            log.exception("plan")
            return jsonify(error=f"{type(e).__name__}: {e}"), 500
        p = public_plan(plan)
        p["plan_hash"] = _plan_hash(p)
        return jsonify(p)

    @bp.route("/api/domains/apply", methods=["POST"])
    def api_domain_apply():
        if not configured:
            return jsonify(error="Domain-Verwaltung nicht konfiguriert"), 503
        spec = request.get_json(force=True) or {}
        expected_hash = spec.pop("plan_hash", None)
        confirm = spec.pop("confirm_domain", None)
        try:
            plan = make_plan(spec)
        except DomainError as e:
            return jsonify(error=str(e)), 400
        pub = public_plan(plan)
        if expected_hash != _plan_hash(pub):
            return jsonify(error="Der Zustand hat sich seit der Vorschau geaendert - bitte Vorschau neu laden."), 409
        if plan["action"] == "delete" and confirm != plan["domain"]:
            return jsonify(error="Zum Loeschen den Domainnamen exakt eingeben"), 400
        if not plan["steps"]:
            return jsonify(error="Keine Aenderungen"), 400
        if not job_lock.acquire(blocking=False):
            return jsonify(error="Es laeuft bereits eine Aenderung - bitte warten"), 409
        try:
            c = get_conn()
            cur = c.execute(
                "INSERT INTO domain_jobs (domain, action, created_at, status, plan, log) VALUES (?,?,?,?,?,?)",
                (plan["domain"], plan["action"], _now_iso(), "running", json.dumps(pub), ""))
            job_id = cur.lastrowid
            c.commit()
            c.close()
            threading.Thread(target=run_job, args=(job_id, plan), daemon=True).start()
        except Exception:
            job_lock.release()
            raise
        return jsonify(job_id=job_id)

    @bp.route("/api/domains/jobs")
    def api_domain_jobs():
        c = get_conn()
        rows = c.execute("SELECT id, domain, action, created_at, finished_at, status, summary "
                         "FROM domain_jobs ORDER BY id DESC LIMIT 30").fetchall()
        c.close()
        return jsonify([dict(r) for r in rows])

    @bp.route("/api/domains/jobs/<int:job_id>")
    def api_domain_job(job_id):
        c = get_conn()
        r = c.execute("SELECT * FROM domain_jobs WHERE id = ?", (job_id,)).fetchone()
        c.close()
        if not r:
            return jsonify(error="nicht gefunden"), 404
        d = dict(r)
        d["plan"] = json.loads(d["plan"] or "{}")
        return jsonify(d)

    app.register_blueprint(bp)
    return {"configured": configured}


def _plan_hash(pub):
    data = {k: v for k, v in pub.items() if k not in ("dns", "plan_hash")}
    return hashlib.sha256(json.dumps(data, sort_keys=True, default=str).encode()).hexdigest()[:16]


def _mask(path, v):
    if path.endswith(("password", "pin")) and v:
        return "********"
    return v


def _dict_diff(old, new, prefix=""):
    out = []
    keys = list(dict.fromkeys(list(old.keys()) + list(new.keys()))) if isinstance(old, dict) and isinstance(new, dict) else []
    if not keys and old != new:
        return [{"key": prefix or "(wert)", "old": _mask(prefix, old), "new": _mask(prefix, new)}]
    for k in keys:
        p = f"{prefix}.{k}" if prefix else k
        o, n = old.get(k), new.get(k)
        if isinstance(o, dict) and isinstance(n, dict):
            out.extend(_dict_diff(o, n, p))
        elif isinstance(o, list) and isinstance(n, list) and o and n and all(isinstance(x, dict) for x in o + n):
            for i in range(max(len(o), len(n))):
                out.extend(_dict_diff(o[i] if i < len(o) else {}, n[i] if i < len(n) else {}, f"{p}[{i}]"))
        elif (o in (None, [], {}, "")) and (n in (None, [], {}, "")):
            continue
        elif o != n:
            out.append({"key": p, "old": _mask(p, o), "new": _mask(p, n)})
    return out


def _flat_diff(old, new):
    out = []
    for k in list(dict.fromkeys(list(old) + list(new))):
        if k not in new:
            out.append({"key": k, "old": old[k], "new": None})
        elif k not in old:
            out.append({"key": k, "old": None, "new": new[k]})
        elif old[k] != new[k]:
            out.append({"key": k, "old": old[k], "new": new[k]})
    return out
