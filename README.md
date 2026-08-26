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

## Status: Phase 6 — Iran CIDR database, matching, history, monthly validation

Phases 1-6 are implemented: foundation; server/SSH management + log
discovery; the incremental Nginx log reader/parser and 503 `RequestEvent`
pipeline; the complete `IPAddress` schema + Celery IP queue; real WHOIS
execution; and now real Iran CIDR matching feeding `IPAddress.is_iran`.
Geolocation is not implemented yet. See [Roadmap](#roadmap) below.

Nothing in the UI or API returns fabricated data — dashboard cards that
depend on unbuilt apps show "pending", and unbuilt nav entries are
disabled rather than linking to pages that don't exist. **No specific
Iran IP ranges are bundled with this project** - this environment has no
network access and no way to verify a dataset's accuracy, and guessing
at CIDR blocks from memory for a feature whose entire purpose is
classifying real IPs as Iranian would be exactly the kind of fake data
the project rules warn against. `CountryNetwork` starts empty; an
operator adds real, trusted ranges via **Iran → CIDRs** or `/admin`.

Phase 6, concretely:

- `apps.common.fields.CIDRField` now has a `contains_ip` lookup
  registered on it: `CountryNetwork.objects.filter(cidr__contains_ip=ip)`
  compiles to PostgreSQL's native `cidr >>= %s::inet` containment
  operator (verified against a real query - see the commit) - spec
  section 21 explicitly forbids a Python `ip.startswith(...)` check, and
  this doesn't do one.
- `apps.iran.CountryNetwork` / `IPCountryHistory` — the spec section
  20/22 schema exactly. `classify()` only opens/closes a history row on
  an actual transition (became Iranian, stopped being Iranian, or its
  matched CIDR changed) - "Which Iranian IPs are no longer Iranian?" is
  a direct query (`valid_until__isnull=False`), not a derived guess.
- `apps.iran.providers.IranCIDRProvider` — the pluggable source
  interface spec section 23 asks for, selected via `IRAN_CIDR_SOURCE`
  (never hard-coded into matching/validation logic). The default
  `static` provider treats `CountryNetwork` rows themselves as the
  source of truth (no external fetch); a deployment with a trusted feed
  implements a provider against it and points the setting there.
- `IranCIDRService.classify(ip)` — most-specific-prefix match wins,
  `ip:iran_match_cidr` and `is_iran` persisted, history updated only on
  change. `IranCIDRValidationService.run()` is the full monthly workflow
  (fetch → upsert → disable removed entries → re-evaluate every
  currently-Iranian IP, skipped entirely when nothing actually changed).
- Celery: `classify_ip` (queue `iran`, `redis_lock("iran:<address>")`)
  is now dispatched by `process_new_ip` for every new IP - the last
  Phase 4 TODO is resolved. `run_monthly_iran_validation` is seeded as a
  django-celery-beat `PeriodicTask` (1st of each month).
- UI: **Iran → CIDRs** (add/enable/disable), **Iran → Changes** (the
  history table), **Iran → Iranian IPs** (the IP list filtered
  `is_iran=true`), and a **Recalculate Iran** button per IP - spec
  section 45's manual action, audit-logged like Force WHOIS.

Prior phases, briefly: server/SSH management with encrypted credentials
and Nginx log discovery (Phase 2); an incremental log reader that never
re-downloads a whole file and a configurable Nginx log parser feeding
503-only `RequestEvent` rows (Phase 3); the full `IPAddress` schema and
the Celery IP queue (Phase 4); real WHOIS execution with a 7-day cache
(Phase 5). See each phase's commit message for the full detail.

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
  iran/            CountryNetwork, IPCountryHistory, IranCIDRProvider, matching, monthly validation
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
5. **WHOIS service/parser/cache (7-day freshness)**.
6. **Iran CIDR database, matching, history, monthly validation** (this repo).
7. IP detail page, 503 intelligence, timeline, exports - Iran IP export filters/downloads specifically land here per spec section 24.
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
