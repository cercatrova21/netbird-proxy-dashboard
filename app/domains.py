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


BW_INSTANCE_CONTAINER = os.environ.get("BW_INSTANCE_CONTAINER", "bunkerweb")
LIVE_MARKER = "Neue BunkerWeb-Konfiguration ist aktiv"


def _bw_health_ok(docker_client):
    """Interner Health-Endpunkt der BunkerWeb-Instanz: msg 'ok' (bereit) oder 'reloading'."""
    try:
        c = docker_client().containers.get(BW_INSTANCE_CONTAINER)
        r = c.exec_run(["curl", "-s", "-m", "3", "-H", "Host: bwapi", "http://127.0.0.1:5000/health"])
        return r.exit_code == 0 and json.loads(r.output.decode() or "{}").get("msg") == "ok"
    except Exception:
        return False


def _bw_scan_logs(docker_client, st, joblog):
    """Scheduler-Logs seit Start auswerten -> (logs, fatal_lines)."""
    logs = _scheduler_logs_since(docker_client, st["t0"])
    for line in logs.splitlines():
        if ("is not valid" in line or "Ignoring variable" in line) and line not in st["warned"]:
            st["warned"].add(line)
            joblog("  WARNUNG: " + line[-300:])
    # Nur Fehler beim Erzeugen/Laden der Konfiguration sind fatal (nicht z.B. ein
    # fehlgeschlagener Blacklist-Download eines Jobs).
    bad = [ln for ln in logs.splitlines() if "❌" in ln and any(
        x in ln for x in ("SAVE_CONFIG", "GENERATOR", "eload", "onfig"))]
    if bad:
        for ln in bad[-5:]:
            joblog("  FEHLER: " + ln[-300:])
        raise DomainError("BunkerWeb meldet einen Fehler beim Laden der Konfiguration")
    return logs


def bw_apply_start(docker_client, joblog):
    """bw-scheduler neu erstellen und warten, bis BunkerWeb mit der NEUEN Konfiguration
    bedient (nach dem ersten Reload, ca. halbe Zeit). BunkerWeb laedt nach dem Start
    des Schedulers ein zweites Mal mit derselben Konfiguration neu - darauf wartet
    bw_apply_finish(), am Ende des Jobs."""
    if not os.path.exists(COMPOSE_BIN):
        raise DomainError(f"docker-compose nicht gefunden ({COMPOSE_BIN})")
    st = {"t0": time.time() - 1, "warned": set(), "complete": False}
    cmd = [COMPOSE_BIN, "up", "-d", "--no-deps", "--force-recreate", BW_SCHEDULER_SERVICE]
    joblog(f"$ docker compose up -d --no-deps --force-recreate {BW_SCHEDULER_SERVICE}")
    p = subprocess.run(cmd, cwd=BW_COMPOSE_DIR, capture_output=True, text=True, timeout=180)
    out = (p.stdout + p.stderr).strip()
    for line in out.splitlines()[-8:]:
        joblog("  " + line)
    if p.returncode != 0:
        raise DomainError(f"docker compose fehlgeschlagen (Exit {p.returncode})")
    joblog("Warte, bis BunkerWeb die neue Konfiguration geladen hat ...")
    deadline = time.time() + BW_APPLY_TIMEOUT
    ok_since = None
    while time.time() < deadline:
        time.sleep(3)
        try:
            logs = _bw_scan_logs(docker_client, st, joblog)
        except DomainError:
            raise
        except Exception as e:  # Container evtl. gerade im Neustart
            joblog(f"  (Logs noch nicht lesbar: {e})")
            continue
        if "Successfully reloaded" in logs:
            st["complete"] = True
            joblog(f"{LIVE_MARKER} (Reload abgeschlossen).")
            return st
        if "bunkerweb:5000/reload" in logs:
            # Reload ist angestossen: bereit, sobald der Health-Endpunkt zweimal
            # hintereinander 'ok' meldet (nicht mehr 'reloading').
            if _bw_health_ok(docker_client):
                if ok_since and time.time() - ok_since >= 3:
                    joblog(f"{LIVE_MARKER}. Ein zweiter, gleichwertiger Reload laeuft im Hintergrund weiter.")
                    return st
                ok_since = ok_since or time.time()
            else:
                ok_since = None
    raise DomainError(f"Neue Konfiguration nicht innerhalb von {BW_APPLY_TIMEOUT}s aktiv")


def bw_apply_finish(docker_client, joblog, st):
    """Auf den Abschluss des zweiten Reloads warten (nur Absicherung; die Konfiguration
    ist zu diesem Zeitpunkt schon aktiv)."""
    if st.get("complete"):
        return {"warnings": sorted(st["warned"])}
    joblog("Warte auf Abschluss des zweiten BunkerWeb-Reloads ...")
    deadline = st["t0"] + BW_APPLY_TIMEOUT + 240
    while time.time() < deadline:
        try:
            logs = _bw_scan_logs(docker_client, st, joblog)
        except DomainError:
            raise
        except Exception:
            logs = ""
        if "Successfully reloaded" in logs:
            st["complete"] = True
            joblog("BunkerWeb-Reload abgeschlossen.")
            return {"warnings": sorted(st["warned"])}
        time.sleep(3)
    raise DomainError("Zweiter BunkerWeb-Reload nicht abgeschlossen")


def bw_apply(docker_client, joblog):
    """Komplett: neu erstellen, aktiv, Abschluss abwarten (fuer Rollbacks)."""
    st = bw_apply_start(docker_client, joblog)
    return bw_apply_finish(docker_client, joblog, st)


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


def traefik_set_bw_routers(enable=(), disable=()):
    """Mehrere BunkerWeb-Router in EINEM Schreibvorgang setzen/entfernen."""
    data = read_traefik_file()
    http = data.setdefault("http", {})
    routers = http.get("routers") or {}
    http["routers"] = routers
    existing = traefik_file_bw_routers(data)
    changed = False
    for domain in enable:
        if domain not in existing:
            routers[router_name_for(domain)] = {
                "rule": f"Host(`{domain}`)", "entryPoints": [TRAEFIK_ENTRYPOINT], "priority": 100,
                "service": TRAEFIK_BW_SERVICE, "tls": {"certResolver": TRAEFIK_CERT_RESOLVER},
            }
            changed = True
    for domain in disable:
        if domain in existing:
            routers.pop(existing[domain], None)
            changed = True
    if not routers:
        http.pop("routers", None)
    if not http:
        data.pop("http", None)
    if changed:
        write_traefik_file(data)
    return changed


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
        try:
            cp = get_conn()
            pending_set = {r[0] for r in cp.execute("SELECT domain FROM domain_pending").fetchall()}
            cp.close()
        except Exception:
            pending_set = set()
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
                "pending": d in pending_set,
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
        bw_state = None
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
                        bw_state = bw_apply_start(docker_client, joblog)
                        if bw_state["warned"]:
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
            if bw_state is not None:
                res = bw_apply_finish(docker_client, joblog, bw_state)
                if res["warnings"]:
                    raise DomainError("BunkerWeb hat Settings verworfen (siehe Warnungen)")
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
            if status in ("ok", "warn"):
                try:
                    c = get_conn()
                    c.execute("DELETE FROM domain_pending WHERE domain = ?", (domain,))
                    c.commit()
                    c.close()
                except Exception:
                    pass
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


    # ---------------- Sammel-Aenderung (viele Domains, ein BunkerWeb-Reload) ----------------

    BULK_KINDS = {"bw_write", "bw_write_noreload", "bw_remove", "traefik_on", "traefik_off",
                  "wait_cert", "nb_update", "http_check"}

    def make_bulk_plan(specs):
        if not specs or len(specs) > 60:
            raise DomainError("1-60 Domains erwartet")
        plans, seen = [], set()
        for sp in specs:
            sp = copy.deepcopy(sp)
            sp["action"] = "save"
            pl = make_plan(sp)
            if pl["domain"] in seen:
                raise DomainError(f"{pl['domain']} doppelt")
            seen.add(pl["domain"])
            bad = {x["kind"] for x in pl["steps"]} - BULK_KINDS
            if bad:
                raise DomainError(f"{pl['domain']}: in der Sammel-Aenderung nicht moeglich ({', '.join(sorted(bad))}) - einzeln ausfuehren")
            if pl["steps"]:
                plans.append(pl)
        if not plans:
            raise DomainError("Keine Aenderungen")
        K = lambda p: {x["kind"] for x in p["steps"]}
        n_off = sum(1 for p in plans if "traefik_off" in K(p))
        n_bw = sum(1 for p in plans if K(p) & {"bw_write", "bw_remove"})
        n_bwn = sum(1 for p in plans if K(p) & {"bw_write", "bw_write_noreload", "bw_remove"})
        n_rt = sum(1 for p in plans if "traefik_on" in K(p))
        n_nb = sum(1 for p in plans if "nb_update" in K(p) and "traefik_off" not in K(p))
        steps = []
        if n_off:
            steps.append({"kind": "bulk_off", "system": "Traefik",
                          "text": f"{n_off} Domain(s) zurueck auf den direkten Weg (Laender zurueck nach NetBird, dann Router entfernen)"})
        if n_bwn:
            steps.append({"kind": "bulk_bw", "system": "BunkerWeb",
                          "text": (f"{n_bwn} Site(s) in einem Schreibvorgang aendern, bw-scheduler EINMAL neu laden"
                                   if n_bw else f"{n_bwn} Site(s): nur Notizen/Kommentare (kein Reload)")})
        if n_rt:
            steps.append({"kind": "bulk_traefik", "system": "Traefik",
                          "text": f"{n_rt} Router in einem Schreibvorgang anlegen (Domains wechseln auf BunkerWeb)"})
            steps.append({"kind": "bulk_cert", "system": "Pruefung",
                          "text": f"Zertifikate fuer {n_rt} Domain(s) parallel abwarten"})
        if n_nb:
            steps.append({"kind": "bulk_nb", "system": "NetBird", "text": f"{n_nb} NetBird-Service(s) aktualisieren"})
        steps.append({"kind": "bulk_http", "system": "Pruefung", "text": f"Testaufruf aller {len(plans)} Domains"})
        warnings = sorted({w for p in plans for w in p["warnings"]})
        if n_bw:
            warnings.append("Ein BunkerWeb-Reload fuer alle Aenderungen zusammen: bestehende WebSocket-Verbindungen "
                            "aller BunkerWeb-Domains brechen dabei einmal ab und verbinden sich neu.")
        if len(plans) > 1:
            warnings.append("Scheitert eine Domain, wird nur sie zurueckgerollt.")
        pub = {"domain": plans[0]["domain"] if len(plans) == 1 else f"{len(plans)} Domains",
               "action": "bulk", "steps": steps, "warnings": warnings,
               "domains": [{"domain": p["domain"], "steps": [x["text"] for x in p["steps"]],
                            "countries": p.get("countries"), "nb_diff": p["nb_diff"], "bw_diff": p["bw_diff"]}
                           for p in plans],
               "nb_diff": [], "bw_diff": [], "dns": None}
        return pub, plans

    def run_bulk_job(job_id, pub, plans, pending=False):
        lines = []
        last_flush = [0.0]

        def joblog(msg):
            lines.append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
            log.info("domain-job %s: %s", job_id, msg)
            if time.time() - last_flush[0] > 0.5:
                _job_update(job_id, log="\n".join(lines))
                last_flush[0] = time.time()

        by = {p["domain"]: p for p in plans}
        kinds = {d: {x["kind"] for x in p["steps"]} for d, p in by.items()}
        failed = {}          # domain -> Grund
        nb_done = {}         # domain -> alter ServiceRequest (fuer Rollback)
        routers_added, routers_removed = [], []
        total = len(pub["steps"])
        status, summary = "ok", ""
        sites_before = None
        bw_state = None
        warn_domains = []

        def step(kind):
            idx = next(i for i, x in enumerate(pub["steps"], 1) if x["kind"] == kind)
            joblog(f"Schritt {idx}/{total} [{pub['steps'][idx-1]['system']}] {pub['steps'][idx-1]['text']}")

        def rollback_domain(d, reason):
            if d in failed:
                return
            failed[d] = reason
            joblog(f"  {d}: FEHLER - {reason} -> wird zurueckgerollt")
            if d in routers_added:
                try:
                    traefik_set_bw_routers(disable=[d])
                    routers_added.remove(d)
                    joblog("    Router entfernt (wieder direkt ueber netbird-proxy)")
                except Exception as e:
                    joblog(f"    Rollback-FEHLER Router: {e}")
            if d in nb_done:
                try:
                    nb.update(by[d]["_svc"]["id"], nb_done.pop(d))
                    joblog("    NetBird-Service zurueckgesetzt")
                except Exception as e:
                    joblog(f"    Rollback-FEHLER NetBird: {e}")

        def nb_apply(d):
            old = service_to_request(by[d]["_svc"])
            nb.update(by[d]["_svc"]["id"], by[d]["_new_body"])
            nb_done[d] = old
            joblog(f"  {d}: NetBird-Service aktualisiert")

        try:
            with ThreadPoolExecutor(max_workers=8) as ex:
                pre = dict(zip(by, ex.map(check_http, by)))
            joblog("Vorher-Tests: " + ", ".join(f"{d}={_fmt_http(r).split(' ->')[0]}" for d, r in pre.items()))

            # 0) Zurueck auf direkt: erst NetBird-Laender setzen, dann Router weg (vor dem BW-Reload)
            off = [d for d in by if "traefik_off" in kinds[d]]
            if off:
                step("bulk_off")
                for d in off:
                    if "nb_update" in kinds[d]:
                        try:
                            nb_apply(d)
                        except Exception as e:
                            rollback_domain(d, f"NetBird-Update: {e}")
                rm = [d for d in off if d not in failed]
                if rm:
                    traefik_set_bw_routers(disable=rm)
                    routers_removed.extend(rm)
                    joblog(f"  Router entfernt: {', '.join(rm)}")

            # 1) BunkerWeb: alle Sites in einem Schreibvorgang, ein Reload
            if any(x["kind"] == "bulk_bw" for x in pub["steps"]):
                step("bulk_bw")
                sites = read_bw_sites()
                sites_before = copy.deepcopy(sites)
                need_reload = False
                for d, p in by.items():
                    if kinds[d] & {"bw_write", "bw_write_noreload"}:
                        if d not in sites["server_names"]:
                            sites["server_names"].append(d)
                        sites["sites"][d] = p["_new_site"]
                        need_reload |= "bw_write" in kinds[d]
                    elif "bw_remove" in kinds[d] and d not in failed:
                        sites["server_names"] = [x for x in sites["server_names"] if x != d]
                        sites["sites"].pop(d, None)
                        need_reload = True
                backup = write_bw_sites(sites)
                joblog(f"  Sites-Datei geschrieben (Backup: {os.path.basename(backup) if backup else '-'})")
                if need_reload:
                    try:
                        bw_state = bw_apply_start(docker_client, joblog)
                        if bw_state["warned"]:
                            raise DomainError("BunkerWeb hat Settings verworfen (siehe Warnungen)")
                    except Exception:
                        joblog("  BunkerWeb-Reload fehlgeschlagen -> alte Sites-Datei wiederherstellen")
                        write_bw_sites(sites_before)
                        sites_before = None
                        bw_apply(docker_client, joblog)
                        if routers_removed:
                            traefik_set_bw_routers(enable=routers_removed)
                            joblog("  Entfernte Router wiederhergestellt")
                            routers_removed.clear()
                        raise

            # 2) Traefik: alle neuen Router auf einmal
            todo_rt = [d for d in by if "traefik_on" in kinds[d]]
            if todo_rt:
                step("bulk_traefik")
                traefik_set_bw_routers(enable=todo_rt)
                routers_added.extend(todo_rt)
                joblog(f"  {len(todo_rt)} Router aktiv: {', '.join(todo_rt)}")

                # 3) Zertifikate parallel
                step("bulk_cert")
                time.sleep(3)
                deadline = time.time() + CERT_WAIT_SECONDS
                pending_c = set(todo_rt)
                while pending_c and time.time() < deadline:
                    with ThreadPoolExecutor(max_workers=8) as ex:
                        res = dict(zip(pending_c, ex.map(check_cert, list(pending_c))))
                    for d, r in res.items():
                        if r.get("ok"):
                            pending_c.discard(d)
                            _cert_cache[d] = {"at": time.time(), "res": r}
                            joblog(f"  {d}: Zertifikat gueltig ({r['issuer']}, {r['days_left']} Tage)")
                    if pending_c:
                        time.sleep(5)
                for d in sorted(pending_c):
                    rollback_domain(d, f"kein gueltiges Zertifikat nach {CERT_WAIT_SECONDS}s ({check_cert(d).get('error')})")

            # 4) NetBird (z.B. Laender entfernen, wenn der Weg ueber BunkerWeb steht)
            todo_nb = [d for d in by if "nb_update" in kinds[d] and "traefik_off" not in kinds[d] and d not in failed]
            if todo_nb:
                step("bulk_nb")
                for d in todo_nb:
                    try:
                        nb_apply(d)
                    except Exception as e:
                        rollback_domain(d, f"NetBird-Update: {e}")

            # 5) Testaufrufe
            step("bulk_http")
            time.sleep(2)
            ok_domains = [d for d in by if d not in failed]
            with ThreadPoolExecutor(max_workers=8) as ex:
                post = dict(zip(ok_domains, ex.map(check_http, ok_domains)))
            for d in ok_domains:
                r, pr = post[d], pre.get(d) or {}
                joblog(f"  {d}: vorher {_fmt_http(pr).split(' ->')[0]} / jetzt {_fmt_http(r)[:120]}")
                route_change = bool(kinds[d] & {"traefik_on", "traefik_off"})
                revertible = "traefik_off" not in kinds[d]   # Rueckweg auf direkt nicht zurueckrollen
                if not r.get("ok") and pr.get("ok") and revertible:
                    rollback_domain(d, "Testaufruf fehlgeschlagen, vorher funktionierte die Domain")
                elif (revertible and route_change and pr.get("status") and r.get("status") in (401, 403)
                      and pr["status"] not in (401, 403)):
                    rollback_domain(d, f"jetzt HTTP {r['status']}, vorher {pr['status']} - vermutlich fuer alle gesperrt")
                elif not r.get("ok"):
                    warn_domains.append(d)

            # 6) Zweiten BunkerWeb-Reload abschliessen
            if bw_state is not None:
                res = bw_apply_finish(docker_client, joblog, bw_state)
                if res["warnings"]:
                    raise DomainError("BunkerWeb hat Settings verworfen (siehe Warnungen)")

            # 7) Sites der zurueckgerollten Domains zuruecksetzen (zweiter Reload nur bei Fehlern)
            bw_failed = [d for d in failed if kinds[d] & {"bw_write", "bw_write_noreload"}]
            if bw_failed and sites_before is not None:
                joblog(f"BunkerWeb-Sites von {', '.join(bw_failed)} zuruecksetzen ...")
                sites = read_bw_sites()
                for d in bw_failed:
                    if d in sites_before["sites"]:
                        sites["sites"][d] = sites_before["sites"][d]
                    else:
                        sites["server_names"] = [x for x in sites["server_names"] if x != d]
                        sites["sites"].pop(d, None)
                write_bw_sites(sites)
                bw_apply(docker_client, joblog)

            done = [d for d in by if d not in failed]
            if failed:
                status = "warn" if done else "error"
                summary = (f"{len(done)} von {len(by)} umgesetzt; zurueckgerollt: "
                           + ", ".join(f"{d} ({r})" for d, r in failed.items()))
            else:
                summary = f"Alle {len(by)} Aenderung(en) umgesetzt" if len(by) > 1 else "Erfolgreich"
            if warn_domains:
                status = "warn" if status == "ok" else status
                summary += "; Testaufruf nicht OK: " + ", ".join(warn_domains)
            if pending and done:
                c = get_conn()
                c.executemany("DELETE FROM domain_pending WHERE domain = ?", [(d,) for d in done])
                c.commit()
                c.close()
        except Exception as e:
            log.exception("bulk-job %s", job_id)
            joblog(f"FEHLER: {e}")
            for d in list(routers_added):
                rollback_domain(d, "Abbruch")
            for d in list(nb_done):
                rollback_domain(d, "Abbruch")
            if sites_before is not None and read_bw_sites() != sites_before:
                try:
                    joblog("BunkerWeb-Sites-Datei auf den Stand vor dem Job zuruecksetzen ...")
                    write_bw_sites(sites_before)
                    bw_apply(docker_client, joblog)
                except Exception as re_:
                    joblog(f"Rollback-FEHLER BunkerWeb: {re_} - bitte manuell pruefen!")
            if routers_removed:
                try:
                    traefik_set_bw_routers(enable=routers_removed)
                    joblog("Entfernte Router wiederhergestellt")
                except Exception as re_:
                    joblog(f"Rollback-FEHLER Traefik: {re_}")
            status, summary = "error", f"Abgebrochen: {e}"
        finally:
            for d in failed:
                _cert_cache.pop(d, None)
            joblog(f"Fertig: {summary}")
            _job_update(job_id, status=status, summary=summary, finished_at=_now_iso(), log="\n".join(lines))
            lookups_cache["at"] = 0
            job_lock.release()

    # ---------------- Sammlung offener Aenderungen ----------------

    c0 = get_conn()
    c0.execute("""
        CREATE TABLE IF NOT EXISTS domain_pending (
            domain TEXT PRIMARY KEY,
            spec TEXT NOT NULL,
            summary TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)
    c0.commit()
    c0.close()

    def pending_specs():
        c = get_conn()
        rows = c.execute("SELECT * FROM domain_pending ORDER BY created_at").fetchall()
        c.close()
        return rows

    def start_bulk_job(pub, plans, pending):
        if not job_lock.acquire(blocking=False):
            return None
        try:
            c = get_conn()
            cur = c.execute(
                "INSERT INTO domain_jobs (domain, action, created_at, status, plan, log) VALUES (?,?,?,?,?,?)",
                (pub["domain"], "bulk", _now_iso(), "running", json.dumps(pub), ""))
            job_id = cur.lastrowid
            c.commit()
            c.close()
            threading.Thread(target=run_bulk_job, args=(job_id, pub, plans, pending), daemon=True).start()
            return job_id
        except Exception:
            job_lock.release()
            raise

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

    @bp.route("/api/domains/bulk/plan", methods=["POST"])
    def api_domain_bulk_plan():
        if not configured:
            return jsonify(error="Domain-Verwaltung nicht konfiguriert"), 503
        try:
            pub, _ = make_bulk_plan((request.get_json(force=True) or {}).get("items") or [])
        except DomainError as e:
            return jsonify(error=str(e)), 400
        pub["plan_hash"] = _plan_hash(pub)
        return jsonify(pub)

    @bp.route("/api/domains/bulk/apply", methods=["POST"])
    def api_domain_bulk_apply():
        if not configured:
            return jsonify(error="Domain-Verwaltung nicht konfiguriert"), 503
        body = request.get_json(force=True) or {}
        try:
            pub, plans = make_bulk_plan(body.get("items") or [])
        except DomainError as e:
            return jsonify(error=str(e)), 400
        if body.get("plan_hash") != _plan_hash(pub):
            return jsonify(error="Der Zustand hat sich seit der Vorschau geaendert - bitte Vorschau neu laden."), 409
        job_id = start_bulk_job(pub, plans, pending=False)
        if job_id is None:
            return jsonify(error="Es laeuft bereits eine Aenderung - bitte warten"), 409
        return jsonify(job_id=job_id)

    def _has_secret(spec):
        a = ((spec.get("nb") or {}).get("auth") or {})
        return bool(a.get("password") or a.get("pin"))

    @bp.route("/api/domains/pending")
    def api_pending_list():
        out = []
        for r in pending_specs():
            out.append({"domain": r["domain"], "spec": json.loads(r["spec"]),
                        "summary": json.loads(r["summary"] or "[]"),
                        "created_at": r["created_at"], "updated_at": r["updated_at"]})
        return jsonify(out)

    @bp.route("/api/domains/pending/<domain>", methods=["PUT"])
    def api_pending_put(domain):
        spec = request.get_json(force=True) or {}
        spec["domain"] = domain.lower()
        spec["action"] = "save"
        if _has_secret(spec):
            return jsonify(error="Passwort/PIN werden nicht zwischengespeichert - diese Aenderung bitte sofort anwenden"), 400
        try:
            plan = make_plan(copy.deepcopy(spec))
        except DomainError as e:
            return jsonify(error=str(e)), 400
        bad = {x["kind"] for x in plan["steps"]} - BULK_KINDS
        if bad:
            return jsonify(error="Diese Aenderung kann nicht gesammelt werden - bitte sofort anwenden"), 400
        c = get_conn()
        if not plan["steps"]:
            c.execute("DELETE FROM domain_pending WHERE domain = ?", (plan["domain"],))
            c.commit()
            c.close()
            return jsonify(removed=True, message="Keine Aenderung gegenueber dem aktuellen Stand")
        now = _now_iso()
        c.execute("""INSERT INTO domain_pending (domain, spec, summary, created_at, updated_at) VALUES (?,?,?,?,?)
                     ON CONFLICT(domain) DO UPDATE SET spec=excluded.spec, summary=excluded.summary,
                     updated_at=excluded.updated_at""",
                  (plan["domain"], json.dumps(spec), json.dumps([x["text"] for x in plan["steps"]]), now, now))
        c.commit()
        c.close()
        return jsonify(ok=True, steps=[x["text"] for x in plan["steps"]])

    @bp.route("/api/domains/pending/<domain>", methods=["DELETE"])
    def api_pending_delete(domain):
        c = get_conn()
        c.execute("DELETE FROM domain_pending WHERE domain = ?", (domain.lower(),))
        c.commit()
        c.close()
        return jsonify(ok=True)

    @bp.route("/api/domains/pending", methods=["DELETE"])
    def api_pending_clear():
        c = get_conn()
        c.execute("DELETE FROM domain_pending")
        c.commit()
        c.close()
        return jsonify(ok=True)

    @bp.route("/api/domains/pending/plan", methods=["POST"])
    def api_pending_plan():
        specs = [json.loads(r["spec"]) for r in pending_specs()]
        try:
            pub, _ = make_bulk_plan(specs)
        except DomainError as e:
            return jsonify(error=str(e)), 400
        pub["plan_hash"] = _plan_hash(pub)
        return jsonify(pub)

    @bp.route("/api/domains/pending/apply", methods=["POST"])
    def api_pending_apply():
        if not configured:
            return jsonify(error="Domain-Verwaltung nicht konfiguriert"), 503
        body = request.get_json(force=True) or {}
        specs = [json.loads(r["spec"]) for r in pending_specs()]
        try:
            pub, plans = make_bulk_plan(specs)
        except DomainError as e:
            return jsonify(error=str(e)), 400
        if body.get("plan_hash") != _plan_hash(pub):
            return jsonify(error="Der Zustand hat sich seit der Vorschau geaendert - bitte Vorschau neu laden."), 409
        job_id = start_bulk_job(pub, plans, pending=True)
        if job_id is None:
            return jsonify(error="Es laeuft bereits eine Aenderung - bitte warten"), 409
        return jsonify(job_id=job_id)

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
