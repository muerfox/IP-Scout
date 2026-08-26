# IP Scout

Infrastructure/IP intelligence platform focused on HTTP 503 requests from
monitored Nginx servers: extract client IPs, enrich them with WHOIS and
geolocation, classify them against Iranian CIDR ranges, and provide a
dashboard/API to investigate and export the results.

> **Continuously discover, enrich, analyze, and export IP addresses
> generating HTTP 503 requests from monitored Nginx servers, with special
> focus on identifying Iranian IPs through CIDR intelligence and historical
> WHOIS/geolocation data.**

## Stack

Python 3.13, Django 5.2, Django REST Framework, PostgreSQL (`inet`/`cidr`
types), Redis, Celery + Celery Beat, Gunicorn, Nginx, Django templates +
HTMX, Leaflet.js, Chart.js, the Linux `whois` binary.

## Status: Phase 5 — WHOIS service, parser, and 7-day cache

Phases 1-5 are implemented: foundation, server/SSH management + log
discovery, the incremental Nginx log reader/parser and 503 `RequestEvent`
pipeline, the complete `IPAddress` intelligence schema + Celery IP queue,
and now real WHOIS execution feeding that schema. Geolocation and Iran
CIDR classification are not implemented yet - the columns for them exist
and are honestly empty. See [Roadmap](#roadmap) below.

Nothing in the UI or API returns fabricated data — dashboard cards that
depend on unbuilt apps show "pending", and unbuilt nav entries are
disabled rather than linking to pages that don't exist.

Phase 5, concretely:

- `apps.whois.WhoisService` — the Linux `whois` binary run via
  `subprocess.run([binary, ip], ...)`, never `shell=True`, the address
  validated with `ipaddress.ip_address()` before it's ever passed to the
  binary (spec sections 15, 43). Prefers `settings.WHOIS_BINARY` but
  falls back to a `PATH` lookup if that path doesn't exist. Distinguishes
  retryable failures (timeout, couldn't spawn the process) from
  non-retryable ones (invalid input, empty response) so the task layer
  knows what's worth retrying.
- `apps.whois.parsers` — registry-agnostic: every `key: value` line is
  parsed into `{key: [values]}` with no assumption about which keys are
  present (WHOIS formats vary enormously between ARIN/RIPE/APNIC/
  LACNIC/AFRINIC and national registries), then a small alias table
  extracts the canonical fields spec section 16 names (inetnum, netname,
  country, organization, descr, origin, route, mnt_by, abuse_email)
  across those registries' different naming conventions.
- `apps.whois.WhoisRecord` — one row per completed lookup that actually
  returned a response, raw text preserved verbatim alongside the parsed
  data (spec: "raw WHOIS data is valuable for future parser
  improvements"). A failed attempt has no response worth keeping, so it's
  recorded on `IPAddress.whois_status`/`whois_error` instead.
- `perform_whois_lookup` (queue `whois`) applies the 7-day freshness
  cache (`WHOIS_CACHE_DAYS`) via `whois_next_check_at`, retries
  transient failures with exponential backoff (max 3, spec section 18),
  and is guarded by `redis_lock("whois:<address>")` so only one lookup
  per IP ever runs at a time (section 36). `apps.ips.tasks.process_new_ip`
  now actually dispatches this - the Phase 4 TODO is resolved.
- **Force WHOIS** button on the IP Addresses list (spec sections 45-46):
  bypasses the freshness gate but still respects the lock, and is
  audit-logged. The WHOIS column live-polls via HTMX.

Prior phases, briefly: server/SSH management with encrypted credentials
and Nginx log discovery (Phase 2); an incremental log reader that never
re-downloads a whole file and a configurable Nginx log parser feeding
503-only `RequestEvent` rows (Phase 3); the full `IPAddress` schema and
the `ip:process:<address>`-locked Celery queue that dispatches
intelligence work for genuinely new IPs (Phase 4). See each phase's
commit message for the full detail.

## Project layout

```
config/            settings (base/development/production/test), urls, celery, wsgi/asgi
apps/
  common/          TimeStampedModel, EncryptedTextField, redis_lock, request-IP helper
  users/           custom User model, login/logout, audit log
  dashboard/       nav tree, dashboard views
  servers/         Server model, SSHService (test/discover/poll_log), CRUD views
  logs/            LogSource model, NginxLogParser, NginxLogReader, poll Celery tasks
  ips/             IPAddress (full schema), IPIntelligenceService, process_new_ip queue, IP list
  whois/           WhoisService (subprocess), WhoisParser, WhoisRecord, perform_whois_lookup
  geo/             geolocation abstraction               (Phase 8)
  incidents/       503 RequestEvent + rollups            (rollups: Phase 8)
  iran/            Iran CIDR database + matching         (Phase 6)
  api/             DRF router, JWT auth endpoints
templates/         base layout + per-app templates
static/            CSS (NOC black/white/gray theme)
docker/            nginx.conf for the reverse-proxy service
```

## Local development (without Docker)

Requires a local PostgreSQL and Redis instance, and the `whois` binary
for the Celery worker that runs `perform_whois_lookup` (`apt install
whois` on Debian/Ubuntu; the Docker image already includes it - see
`Dockerfile`).

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements/development.txt
cp .env.example .env   # edit DATABASE_URL / REDIS_URL / SECRET_KEY etc.

python manage.py migrate
python manage.py createsuperuser
python manage.py runserver
```

In separate shells, so "Test Connection" / "Rescan Logs" actually run:

```bash
celery -A config worker -Q logs,ips,whois,iran,maintenance -l info
celery -A config beat -l info --scheduler django_celery_beat.schedulers:DatabaseScheduler
```

## Local development (Docker)

```bash
cp .env.example .env
docker compose up -d
docker compose exec web python manage.py createsuperuser
```

- App: http://localhost:8000 (direct) or http://localhost:8080 (via the nginx service)
- `web` runs migrate + `runserver` for dev convenience; production uses Gunicorn (see `Dockerfile` / `docker-compose.prod.yml` you provide for your environment).

## Testing

```bash
pytest
# or
python manage.py test
```

`config/settings/test.py` still targets PostgreSQL — the `inet`/`cidr`
network field types used from Phase 4 onward are PostgreSQL-specific and
are not portable to SQLite, so tests run against the same engine as
production.

## Configuration

All configuration is via environment variables — see `.env.example` for
the full list (database, Redis, WHOIS binary/timeout/cache days, retention
periods, Iran CIDR source, SSH credential encryption key, JWT lifetimes).
Nothing is hard-coded; nothing is read from `os.environ` outside
`config/env.py` and `config/settings/*.py`.

## Roadmap

Built incrementally per the project spec (section 62):

1. **Foundation** — Django/Postgres/Redis/Celery/DRF wiring, auth, base UI, Docker Compose.
2. **Server/SSH management, Nginx log/file discovery**.
3. **Incremental Nginx log reader, 503 parser, `RequestEvent`**.
4. **Full `IPAddress` intelligence fields + Celery IP-intelligence queue + Redis locks**.
5. **WHOIS service/parser/cache (7-day freshness)** (this repo).
6. Iran CIDR database, matching, history, monthly validation - `apps.common.fields.CIDRField` is already in place for `CountryNetwork.cidr`.
7. IP detail page, 503 intelligence, timeline, exports.
8. Dashboard charts, world map, filters.
9. Retention/purge, worker monitoring, audit log surfacing, production deployment docs.

## Production deployment

Two supported paths:

- **Docker Compose** — build with `requirements/production.txt`, run
  `gunicorn config.wsgi:application` behind the `nginx` service, `celery
  worker` and `celery beat` as separate long-running services.
- **Traditional Linux (systemd)** — Gunicorn + systemd unit, Nginx as
  reverse proxy, PostgreSQL and Redis as system services, Celery
  worker/beat as systemd units. Full unit-file documentation lands in
  Phase 9 alongside retention/purge and worker monitoring.

Set `DJANGO_SETTINGS_MODULE=config.settings.production`. That module
refuses to start with a default `SECRET_KEY`, an empty `ALLOWED_HOSTS`, or
a missing `SSH_CREDENTIAL_ENCRYPTION_KEY`.
