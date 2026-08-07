# CrowdSec setup for the NetBird proxy

This folder is the exact detection layer this project runs in production: a
dedicated, LAPI-less [CrowdSec](https://www.crowdsec.net/) instance that tails
the NetBird reverse-proxy's logs (plus this dashboard's own denied-request
log) and turns scan/brute-force patterns into bans on your main CrowdSec LAPI.
Wire it up once, and both the [dashboard](../README.md#crowdsec-integration-optional)
and your proxy's own CrowdSec bouncer benefit from it.

## Architecture

```
netbird-proxy (401/404 etc.)  ---\
                                   >--  netbird-logparser  --(decisions)-->  crowdsec (main LAPI)  -->  bouncer on netbird-proxy
netbird-proxy-dashboard (denied)-/
```

- **`crowdsec`** - your main CrowdSec Local API. This is what actually enforces
  bans, via whatever bouncer you run in front of your NetBird proxy. Setting
  this up (collections, the bouncer registration) is standard CrowdSec/NetBird
  territory and not specific to this repo - see the
  [CrowdSec docs](https://docs.crowdsec.net/) and NetBird's reverse-proxy docs.
- **`netbird-logparser`** - a second CrowdSec container, started with
  `DISABLE_LOCAL_API=true`, whose only job is to parse logs through the custom
  parsers/scenarios in this folder and forward decisions to the main LAPI
  above as a machine ("agent") account. Keeping it separate means the noisy,
  proxy-specific parsing doesn't clutter your main CrowdSec config.

## Why a second CrowdSec instance instead of just adding scenarios to the main one

The NetBird reverse-proxy's own stdout only logs actual backend connection
errors (502s) - it never logs blocked/401/404/denied requests, so out of the
box CrowdSec has no visibility into scan/brute-force traffic at all. This
dashboard's `log_security_event()` (see `app/app.py`) fixes that by emitting a
structured `security_event ...` line to its own container's stdout for every
denied request, and the parsers here (`netbird-proxy-access-denied.yaml`)
pick that up. Splitting this into its own CrowdSec instance keeps that
docker-log acquisition (which needs `docker.sock` access) isolated from your
main LAPI's config.

## What's in here

| File | Purpose |
|---|---|
| `netbird-logparser/acquis.yaml` | Tails the `netbird-proxy` container (backend errors) and the `netbird-proxy-dashboard` container (denied requests) via Docker log acquisition. |
| `parsers/s01-parse/netbird-proxy-errors.yaml` | Parses the proxy's own `proxy error: ...` stdout lines (real backend failures, e.g. 502s). |
| `parsers/s01-parse/netbird-proxy-access-denied.yaml` | Parses this dashboard's `security_event ...` lines (401/404/405/etc., across all hosted domains). |
| `scenarios/netbird-proxy-auth-bruteforce.yaml` | 5 auth failures from one IP within 60s -> 15 min ban. |
| `scenarios/netbird-proxy-access-flood.yaml` | 40 denied/not-found requests from one IP within 60s -> 10 min ban. Catches systematic scanning across all hosted domains. |
| `scenarios/netbird-proxy-error-flood.yaml` | 15 real backend errors from one IP within 30s -> 5 min ban. |
| `scenarios/netbird-proxy-sensitive-path.yaml` | Immediate ban (10 min) on the first request to a known exploit/config/webshell path (`.env`, `.git/`, `wp-admin`, `.php`, `phpmyadmin`, etc.) on any hosted domain. |
| `postoverflows/s01-whitelist/netbird-proxy-whitelist.yaml` | Exempts loopback + private ranges from all of the above. Add your own trusted public IPs here - this is also the file the dashboard's whitelist widget edits. |

Tune the numbers (`capacity`, `leakspeed`, `blackhole`) in the scenario files
to match your own traffic; the values above are just what worked well in
practice.

## Setup

1. **Merge [`docker-compose.example.yml`](docker-compose.example.yml)** into
   wherever your NetBird stack's compose file lives, adjusting the network
   name and `LOCAL_API_URL` to match your setup. Copy this whole `crowdsec/`
   folder next to that compose file so the relative volume paths resolve.

2. **Create the agent machine account** on your main LAPI and put the
   generated password into `NETBIRD_LOGPARSER_AGENT_PASSWORD` (env var or
   `.env` next to that compose file):
   ```bash
   docker compose exec crowdsec cscli machines add netbird-proxy-parser --auto
   ```

3. **Start it**:
   ```bash
   docker compose up -d netbird-logparser
   docker compose exec netbird-logparser cscli parsers list
   docker compose exec netbird-logparser cscli scenarios list
   ```
   You should see the `netbird-proxy/*` parsers and scenarios listed as
   installed (they're mounted directly, not installed via `cscli`, so they
   won't show a hub status - that's expected).

4. **Verify decisions reach the main LAPI**:
   ```bash
   docker compose exec crowdsec cscli decisions list
   ```

5. **Reloading after a config change**: CrowdSec only reads parser/scenario/
   postoverflow config at startup - there's no hot reload. After editing
   anything in this folder (including the whitelist file, if not using the
   dashboard's "Apply" button), restart the container:
   ```bash
   docker compose restart netbird-logparser
   ```

6. **Wire up the dashboard** (optional): see
   [the main README](../README.md#crowdsec-integration-optional) - point it at
   your main LAPI with a read-only machine account, and optionally at this
   folder's whitelist file for the whitelist widget.

## Security note

`netbird-logparser` needs read access to `/var/run/docker.sock` to tail
container logs, and the dashboard needs the same if you use the whitelist
"Apply" button (it restarts this container). Docker socket access is
effectively root-equivalent on the host - understand that tradeoff before
enabling it, same as noted in the [main README's Security section](../README.md#security).
