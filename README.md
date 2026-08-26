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

## Status: Phase 8 — dashboard charts, world map, filters

Phases 1-8 are implemented: the full ingestion → intelligence pipeline
(server discovery, log reading, IP/WHOIS/Iran/Geo enrichment), the
investigation surfaces (IP detail, 503 intelligence, exports), and now
the visual layer - Chart.js dashboards and an interactive Leaflet world
map, both backed by real aggregation, both empty of data until you feed
the pipeline real log sources. See [Roadmap](#roadmap) below.

Nothing in the UI or API returns fabricated data — unbuilt nav entries
are disabled rather than linking to pages that don't exist. **No
geolocation dataset or Iran CIDR data ships with this project** - this
sandbox has no network access and no way to verify such data, and
inventing it for security/geo-classification features would be exactly
the kind of fake data the project rules warn against. `GEOIP_PROVIDER`
defaults to `null` (no coordinates populated, so the map starts empty);
`CountryNetwork` starts empty too (see Phase 6). Both are real,
pluggable, and ready for a deployment that adds a trusted data source.

Phase 8, concretely:

- **`apps.geo`** - the `GeoIPProvider` interface spec section 19 asks
  for. `MaxMindGeoIPProvider` is real, correct code against the standard
  `geoip2` library (lazy-imported, so it's not a hard dependency until
  configured) reading a local GeoLite2-City `.mmdb` file
  (`GEOIP_DATABASE_PATH`); `NullGeoIPProvider` is the honest default.
  `enrich_ip` (queue `ips`) is now dispatched by `process_new_ip` for
  every new IP - the very last Phase 4 TODO is resolved, so all three
  intelligence sources (WHOIS, Iran, Geo) fire together.
- **Dashboard charts** (spec section 27) - `DashboardAnalyticsService`
  computes all seven series (503s and unique IPs over time with
  adaptive DB-side bucketing, countries, Iran/Other/Unknown split, top
  Iranian IPs, top Iranian CIDRs, top countries) for a period (1h/6h/
  24h/7d/30d/custom) via `/api/v1/dashboard/`; Chart.js renders them
  client-side in the project's black/white/gray palette (red reserved
  for Iran/503-specific series, everything else grayscale).
- **World map** (spec sections 28-29) - `MapAggregationService` never
  sends one marker per IP: below zoom 8 it returns grid-rounded cluster
  points (count only), at or above it individual IPs with full popup
  detail (country, ASN, org, 503 count, last seen, Iran status, a "View
  IP" link) via `/api/v1/map/`. Status filter (All/503/Iran/Non-Iran/
  Unknown, default `503` per spec's emphasis) plus the same time
  periods as the dashboard. Leaflet renders it on a clean, minimal light
  basemap; red markers are Iranian, green are everything else.
- `/api/v1/dashboard/` and `/api/v1/map/` are real DRF endpoints (spec
  section 39) - the first two pieces of the full REST API, which is
  otherwise still a gap; see [Roadmap](#roadmap).

Prior phases, briefly: server/SSH management with encrypted credentials
and Nginx log discovery (Phase 2); an incremental log reader and
configurable parser feeding 503-only `RequestEvent` rows (Phase 3); the
full `IPAddress` schema and Celery IP queue (Phase 4); real WHOIS
execution with a 7-day cache (Phase 5); real Iran CIDR matching, history,
and monthly validation (Phase 6); the IP detail page, 503 intelligence
dashboards, and Iran IP export (Phase 7). See each phase's commit
message for the full detail.

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
  geo/             GeoIPProvider (null/maxmind), GeoIPService, enrich_ip
  incidents/       RequestEvent, 503 Overview/IPs/Timeline views      (rollups: still open)
  iran/            CountryNetwork, IPCountryHistory, IranCIDRProvider, matching, monthly validation, export
  api/             JWT auth, /dashboard/ + /map/ endpoints  (full REST API: still open, see Roadmap)
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
7. **IP detail page, 503 intelligence, timeline, exports**.
8. **Dashboard charts, world map, filters** (this repo) - including `apps.geo`'s GeoIP provider abstraction, since the map needs coordinates.
9. Retention/purge, worker monitoring, audit log surfacing, production deployment docs.
10. *(tracked gap, not in the original 9-phase roadmap)* The full REST API from spec section 39 - ViewSets/serializers for servers, log sources, IPs, 503 events, Iran CIDRs/exports, workers, with filtering/search/ordering/pagination. Only `/api/v1/auth/`, `/api/v1/dashboard/`, and `/api/v1/map/` exist today; everything else in this repo is web-UI-only.

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
