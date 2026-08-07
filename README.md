# NetBird Proxy Dashboard

A small, self-hosted analytics dashboard for [NetBird](https://netbird.io)'s
reverse-proxy access events. It polls your self-hosted NetBird Management
API for proxy events, stores them in a local SQLite database, and serves a
single-page dashboard with traffic breakdowns, geo maps, latency stats,
anomaly detection and full cross-filtering.

It's a single Flask app + a background poller thread, no external database,
no build step for the frontend - one Docker container.

![status](https://img.shields.io/badge/status-personal%20project-blue)
![license](https://img.shields.io/badge/license-MIT-green)

## Features

- **Live ingestion** - polls `{NB_API_BASE}/api/events/proxy` on an interval,
  paginated, resumable (keeps its sync position in SQLite so a restart
  doesn't re-fetch everything).
- **KPIs** - total requests, unique source IPs, denied requests, top country,
  total traffic, for the selected time range.
- **World map** - requests by country, with the currently filtered
  country highlighted as a ring so the filter stays visible on the map.
- **Charts** - requests over time, status code distribution, top
  countries/hosts/paths/cities/source IPs/users, auth methods used, deny
  reasons, traffic (upload/download) per host.
- **Latency** - p50/p95/average per the selected range, an hourly latency
  timeseries, and a "slowest requests" table.
- **Anomaly detection** - flags countries seen for the first time in the
  selected window, and source IPs with an unusually high number of denies.
  Shown as a small badge that expands into details, not a page-pushing banner.
- **Cross-filtering** - click any chart segment, map region, or table cell to
  filter every other panel by it, Grafana-style. Active filters show as
  removable chips.
- **Poller health** - a small status indicator shows how far behind the
  poller's last sync is.
- **Data retention** - optionally auto-deletes events older than N days.
- **CrowdSec integration (optional)** - mirrors your CrowdSec LAPI's
  alerts/bans locally (longer history than CrowdSec's own ~7 days), shows
  currently-active blocks with scenario/country/ASN, lets you unban an IP with
  one click, and includes a whitelist manager for the bundled detection
  scenarios. See [CrowdSec integration](#crowdsec-integration-optional) below.
- **No separate auth layer** - designed to be bound to a private/VPN-only
  interface (e.g. a NetBird mesh IP) instead of shipping its own login. See
  [Security](#security) below before exposing it any other way.

## How it works

```
NetBird Management API  --(poll every 30s)-->  SQLite (local file)  <--  Flask app  -->  Dashboard (browser)
```

A background thread polls `GET {NB_API_BASE}/api/events/proxy` with your
API token, paginating through new events since the last sync point, and
writes them into a local SQLite database. The Flask app serves a single
HTML page (`app/templates/dashboard.html`) plus a small JSON API
(`/api/stats`, `/api/events`, `/api/poller-status`) that the page polls
every 30 seconds. All aggregation (top countries, latency percentiles,
etc.) happens in the Flask process, not in the browser.

## Prerequisites

- Docker and Docker Compose (v2, i.e. `docker compose ...`).
- A self-hosted NetBird Management server with the reverse-proxy / access
  events feature enabled, reachable from wherever this container runs.
- A NetBird **Personal Access Token** or **Service User token** with read
  access to Events (NetBird Dashboard -> Settings -> Service Users, or your
  own account -> Personal Access Tokens).
- Some network interface this container can bind to that isn't the public
  internet - typically the host's NetBird/WireGuard IP. This is how access
  control is handled instead of a login screen (see [Security](#security)).

## Quick start

1. **Clone the repo**

   ```bash
   git clone https://github.com/cercatrova21/netbird-proxy-dashboard.git
   cd netbird-proxy-dashboard
   ```

2. **Create your `.env`**

   ```bash
   cp .env.example .env
   ```

   Then edit `.env` and set at least:
   - `NB_API_BASE` - your NetBird management domain, e.g. `https://netbird.example.com`
   - `NB_API_TOKEN` - your Personal Access Token / Service User token
   - `DASHBOARD_BIND_IP` - the IP to bind the dashboard to (see [Security](#security))

   All other variables have sensible defaults - see the
   [Configuration](#configuration) table below.

3. **Build and start**

   ```bash
   docker compose up -d --build
   ```

   On first start, the poller will back-fill `INITIAL_BACKFILL_DAYS` days of
   history (default 7) before the dashboard shows a full picture - this can
   take a few minutes depending on how much history there is.

4. **Open the dashboard**

   ```
   http://<DASHBOARD_BIND_IP>:<DASHBOARD_PORT>
   ```

   (defaults to port `8098`). If you bound it to a NetBird IP, you'll need to
   be connected to that NetBird network yourself to reach it.

5. **Check it's syncing**

   ```bash
   curl http://<DASHBOARD_BIND_IP>:8098/api/poller-status
   ```

   `lag_seconds` tells you how far behind the last successful sync is; it
   should stay close to `POLL_INTERVAL_SECONDS`. The same info is shown as a
   small status dot in the dashboard header.

## Configuration

All configuration is via environment variables (see `.env.example`).

| Variable | Default | Description |
|---|---|---|
| `NB_API_BASE` | *(required)* | Base URL of your NetBird Management API, no trailing slash. |
| `NB_API_TOKEN` | *(required)* | Personal Access Token / Service User token with read access to Events. |
| `DASHBOARD_BIND_IP` | *(required)* | Host IP the dashboard port is published on. Use a private/VPN interface, not `0.0.0.0`. |
| `DASHBOARD_PORT` | `8098` | Host port the dashboard is published on. |
| `POLL_INTERVAL_SECONDS` | `30` | How often the poller checks for new events. |
| `INITIAL_BACKFILL_DAYS` | `7` | How many days of history to fetch on first start. |
| `RETENTION_DAYS` | `0` | Delete events older than N days (`0` = keep forever). Runs at most once/hour. |
| `ANOMALY_DENY_THRESHOLD` | `10` | Denies from one source IP within the selected range before it's flagged as an anomaly. |
| `STATS_CACHE_SECONDS` | `20` | How long a `/api/stats` response is cached per unique range+filter combination. |
| `TZ` | `Europe/Zurich` | Container timezone (affects log timestamps). |
| `DB_PATH` | `/data/proxy_events.db` | SQLite file path inside the container. Only relevant if you change the volume mount. |
| `PORT` | `8098` | Port Flask listens on inside the container. Only relevant if you change the Dockerfile/compose port mapping. |
| `CROWDSEC_API_URL` | *(empty)* | Base URL of your CrowdSec LAPI, e.g. `http://192.168.1.10:8080`. Leave empty to disable the CrowdSec feature entirely. |
| `CROWDSEC_MACHINE_ID` | *(empty)* | Machine account username for read access to the LAPI (see [CrowdSec integration](#crowdsec-integration-optional)). |
| `CROWDSEC_MACHINE_PASSWORD` | *(empty)* | Machine account password for the above. |
| `WHITELIST_HOST_FILE_PATH` | *(empty)* | Host path to the CrowdSec whitelist YAML file the dashboard should manage. Leave empty to hide the whitelist widget. |
| `WHITELIST_CONTAINER_NAME` | `netbird-logparser` | Name of the CrowdSec container to restart when you click "Apply" after editing the whitelist. |
| `ASN_ENRICHMENT_ENABLED` | `false` | Enrich every request with its source IP's AS number/org (adds a "Top ASNs" chart + `asn` filter). Downloads the free, unauthenticated GeoLite2-ASN database CrowdSec's own hub also uses - opt-in since it's the only feature here that fetches something from the internet on its own. |
| `ASN_MMDB_URL` | CrowdSec's public mirror | Override if you'd rather point at your own MaxMind-licensed mirror. |

## CrowdSec integration (optional)

If you protect your NetBird reverse-proxy with [CrowdSec](https://www.crowdsec.net/),
this dashboard can read its LAPI to show currently-active blocks (grouped by
IP, with scenario/country/ASN and a one-click unban), a longer-than-7-days
history, and a widget to manage a whitelist file without SSHing in. All of
this is entirely optional - leave the `CROWDSEC_*` variables empty and the
dashboard runs exactly as before.

**If you already run CrowdSec** protecting your NetBird proxy, you just need
to point the dashboard at it:

1. Create a read-only machine account on your CrowdSec LAPI:
   ```bash
   docker compose exec crowdsec cscli machines add netbird-proxy-dashboard --auto
   ```
2. Set `CROWDSEC_API_URL`, `CROWDSEC_MACHINE_ID` and `CROWDSEC_MACHINE_PASSWORD`
   in `.env` to that machine's URL/username/password.
3. Optionally set `WHITELIST_HOST_FILE_PATH` to the whitelist YAML file your
   CrowdSec setup already uses, and `WHITELIST_CONTAINER_NAME` to the
   container that needs restarting for it to take effect.

**If you don't have CrowdSec set up yet** for your NetBird proxy, the
[`crowdsec/`](crowdsec/) folder in this repo has the exact detection scenarios
this project was built around - custom parsers/scenarios that turn 401s, 404s
and known exploit-path probes on your proxy into CrowdSec bans, plus a
docker-compose excerpt to wire it all up. See [`crowdsec/README.md`](crowdsec/README.md)
for the full setup guide.

## Security

This dashboard **does not have its own login**. Access control is meant to
be handled at the network layer: bind it to an interface only reachable over
a private network or VPN mesh (e.g. your NetBird WireGuard IP), not to
`0.0.0.0` or a public IP. `docker-compose.yml` is set up this way by default
via `DASHBOARD_BIND_IP`.

If you want to expose it more broadly, put a reverse proxy with its own
authentication (basic auth, OIDC, whatever you already use) in front of it -
don't just bind it to `0.0.0.0`.

Also note: the app runs Flask's built-in development server (see the
`WARNING: This is a development server` line in the logs). That's fine for a
personal/small-team dashboard behind a private network, but if you expose
this more broadly or expect real concurrent load, put a proper WSGI server
(gunicorn, waitress, ...) in front of it.

If you enable the CrowdSec whitelist widget (`WHITELIST_HOST_FILE_PATH` set),
`docker-compose.yml` also mounts `/var/run/docker.sock` into this container so
the "Apply" button can restart your log-parser container. Docker socket
access is effectively root-equivalent on the host - only enable it if you're
comfortable with that tradeoff, and definitely keep the dashboard off any
network reachable by anyone you don't trust with that.

## API reference

The frontend consumes these; they're plain JSON and can be queried directly
(e.g. for your own scripts/alerts):

- `GET /api/stats?range=24h|7d|30d|all&<filters>` - aggregated stats for the
  dashboard (KPIs, top-N breakdowns, latency, anomalies, ...).
- `GET /api/events?range=...&<filters>&search=...&limit=200` - raw event rows,
  newest first (max `limit` is 500).
- `GET /api/poller-status` - poller sync lag, total event count, retention setting.
- `GET /healthz` - basic liveness check.

Supported filters (as query params) on both `/api/stats` and `/api/events`:
`host`, `country`, `ip`, `path`, `city`, `user_id`, `status` (`allowed`/`denied`),
`bucket` (`2xx`/`3xx`/`4xx`/`5xx`/`n/a`), `reason`.

If CrowdSec is configured (see [above](#crowdsec-integration-optional)):

- `GET /api/crowdsec/current` - currently-active blocks, one row per IP.
- `GET /api/crowdsec/history?range=...&search=...&limit=200` - full ban
  history, including expired ones.
- `DELETE /api/crowdsec/ban/<ip>` - unban an IP (deletes its active decisions
  on the LAPI).
- `GET /api/crowdsec/whitelist` - current whitelist file contents.
- `POST /api/crowdsec/whitelist/entries` `{"value": "1.2.3.4"}` - add an
  IP/CIDR to the whitelist file.
- `DELETE /api/crowdsec/whitelist/entries?value=1.2.3.4` - remove an entry.
- `POST /api/crowdsec/whitelist/apply` - restart `WHITELIST_CONTAINER_NAME` so
  the edited whitelist file is actually loaded.

## Data retention & storage

Events are stored in a local SQLite file (`./data/proxy_events.db` by
default via the Compose volume mount). There's no external database to run.
Set `RETENTION_DAYS` if you don't want the file to grow unbounded - it's a
straightforward `DELETE ... WHERE timestamp < cutoff`, not a rolling
archive, so make sure it's larger than any time range you actually want to
look back over.

## Local development (without Docker)

```bash
cd app
pip install -r requirements.txt
export NB_API_BASE=https://netbird.example.com
export NB_API_TOKEN=nbp_xxx
export DB_PATH=./proxy_events.db
python app.py
```

Then open `http://localhost:8098`.

## Contributing

Issues and PRs are welcome. This started as a personal homelab tool, so
expect some rough edges - if something's confusing or broken, please open
an issue.

## License

[MIT](LICENSE)
