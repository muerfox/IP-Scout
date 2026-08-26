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

## Status: Phase 7 — IP detail page, 503 intelligence, timeline, exports

Phases 1-7 are implemented: foundation; server/SSH management + log
discovery; the incremental Nginx log reader/parser and 503 `RequestEvent`
pipeline; the complete `IPAddress` schema + Celery IP queue; real WHOIS
execution; real Iran CIDR matching; and now the investigation surfaces
that tie it all together - an IP detail page, 503-focused dashboards, and
Iran IP exports. Geolocation and the world map are not implemented yet.
See [Roadmap](#roadmap) below.

Nothing in the UI or API returns fabricated data — dashboard cards that
depend on unbuilt apps show "pending", and unbuilt nav entries are
disabled rather than linking to pages that don't exist. **No specific
Iran IP ranges are bundled with this project** - this environment has no
network access and no way to verify a dataset's accuracy, and guessing
at CIDR blocks from memory for a feature whose entire purpose is
classifying real IPs as Iranian would be exactly the kind of fake data
the project rules warn against. `CountryNetwork` starts empty; an
operator adds real, trusted ranges via **Iran → CIDRs** or `/admin`.

Phase 7, concretely:

- **IP detail page** (`ips:detail`, spec sections 30-31) - every
  `IPAddress` field, recent WHOIS lookups, Iran classification history,
  and a filterable (server/host) paginated 503 timeline with aggregate
  stats. Force WHOIS / Recalculate Iran now redirect here instead of
  the list.
- **503 → Iran** (`incidents:overview`, spec section 25) - the four
  stat cards (503 Requests, Unique 503 IPs, Iranian IPs, Iranian IP %)
  plus a top-10 table, with a full sortable/filterable **IPs** table
  (`incidents:ip-table`) behind "View full table" - IP, Country, ASN,
  Organization, CIDR, 503 Count, First/Last Seen, WHOIS Last Checked,
  Iran Status, exactly the section 25 column list. A global
  chronological **Timeline** (`incidents:timeline`) rounds out the
  section's three nav entries.
- **Iran IP export** (`iran:export`, spec section 24) -
  `apps.common.fields.GenericIPAddressField` gains an `is_contained_by`
  lookup (PostgreSQL's `<<=` operator, the inverse of Phase 6's
  `contains_ip`) powering the CIDR filter; `IPExportService` combines it
  with period/server/503-only/Iran-status filters exactly as spec lists
  them. A live preview textarea with **Copy**, plus **Download
  TXT** (one IP per line, verified), **CSV**, and **JSON** - all sharing
  the same filtered queryset, audit-logged.

Prior phases, briefly: server/SSH management with encrypted credentials
and Nginx log discovery (Phase 2); an incremental log reader that never
re-downloads a whole file and a configurable Nginx log parser feeding
503-only `RequestEvent` rows (Phase 3); the full `IPAddress` schema and
the Celery IP queue (Phase 4); real WHOIS execution with a 7-day cache
(Phase 5); real Iran CIDR matching, history, and monthly validation
(Phase 6). See each phase's commit message for the full detail.

## Project layout

```
config/            settings (base/development/production/test), urls, celery, wsgi/asgi
apps/
  common/          TimeStampedModel, EncryptedTextField, redis_lock, request-IP helper
  users/           custom User model, login/logout, audit log
  dashboard/       nav tree, dashboard views
  servers/         Server model, SSHService (test/discover/poll_log), CRUD views
  logs/            LogSource model, NginxLogParser, NginxLogReader, poll Celery tasks
  ips/             IPAddress (full schema), IPIntelligenceService, process_new_ip queue, IP list + detail
  whois/           WhoisService (subprocess), WhoisParser, WhoisRecord, perform_whois_lookup
  geo/             geolocation abstraction               (Phase 8)
  incidents/       RequestEvent, 503 Overview/IPs/Timeline views      (rollups: Phase 8)
  iran/            CountryNetwork, IPCountryHistory, IranCIDRProvider, matching, monthly validation, export
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
6. **Iran CIDR database, matching, history, monthly validation**.
7. **IP detail page, 503 intelligence, timeline, exports** (this repo).
8. Dashboard charts, world map, filters - GeoIP (`IPAddress.latitude`/`longitude`/`country_*`) is the remaining unpopulated piece of the schema.
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
