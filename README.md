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

## Status: Phase 3 — incremental log reader, parser, RequestEvent

Phases 1-3 are implemented: foundation, server/SSH management + log
discovery, and now the incremental Nginx log reader/parser and 503
`RequestEvent` pipeline. WHOIS, geolocation and Iran CIDR classification
are not implemented yet. See [Roadmap](#roadmap) below.

Nothing in the UI or API returns fabricated data — dashboard cards that
depend on unbuilt apps show "pending", and unbuilt nav entries are
disabled rather than linking to pages that don't exist.

Phase 3, concretely:

- `apps.ips.IPAddress` — deliberately minimal for now: `address` (unique),
  `version`, `first_seen_at`/`last_seen_at`. WHOIS/geo/Iran fields are
  added onto this same table in Phases 4-6 (additive migrations, not a
  rebuild). `IPIntelligenceService.record_sightings_bulk()` dedupes a
  whole batch of sightings in a handful of queries and never regresses
  `last_seen_at` under concurrent readers (a conditional `UPDATE ...
  WHERE last_seen_at < %s`, not check-then-write).
- `apps.incidents.RequestEvent` — one row per parsed **503** line only
  (spec: "the main purpose is 503"); other status codes are parsed just
  enough to be filtered out, never persisted.
- `SSHService.poll_log()` (spec section 9/43's `read_log`/`stat_log`
  merged into one composite operation, since the reader always needs
  both): stats the file via a fixed `stat -c '%i %s %Y'` (the SFTP
  protocol itself doesn't expose inode numbers), detects rotation by
  inode change, and range-reads only the new bytes via SFTP `seek()` -
  never re-downloads a whole file. The **first** poll of a newly-enabled
  log source skips straight to the current end-of-file rather than
  backfilling potentially huge historical content.
- `apps.logs.parsers.NginxLogParser` — compiles an nginx `log_format`
  string (with `$variables`) into a regex at runtime. `LogSource.format`
  can be a built-in preset (`combined`, `combined_host`,
  `combined_timed`) or any raw `log_format` string - genuinely
  configurable, not a fixed enum.
- `apps.logs.services.NginxLogReader` — orchestrates one poll: only
  advances `byte_offset` past complete (`\n`-terminated) lines, so a
  line nginx is still writing is safely re-read combined with what gets
  appended next poll. Malformed lines are counted and skipped, not
  fatal.
- Celery: `poll_log_source` (queue `logs`, `apps.logs.tasks`) is guarded
  by `redis_lock("logreader:<server_id>:<log_source_id>")`;
  `poll_all_log_sources` fans it out to every enabled log source and is
  seeded as a django-celery-beat `PeriodicTask` (every 30s, editable at
  `/admin/django_celery_beat/periodictask/`) by a data migration.

## Project layout

```
config/            settings (base/development/production/test), urls, celery, wsgi/asgi
apps/
  common/          TimeStampedModel, EncryptedTextField, redis_lock, request-IP helper
  users/           custom User model, login/logout, audit log
  dashboard/       nav tree, dashboard views
  servers/         Server model, SSHService (test/discover/poll_log), CRUD views
  logs/            LogSource model, NginxLogParser, NginxLogReader, poll Celery tasks
  ips/             IPAddress (identity/dedup only - WHOIS/geo/Iran land in Phase 4-6)
  whois/           whois execution/cache/parsing        (Phase 5)
  geo/             geolocation abstraction               (Phase 8)
  incidents/       503 RequestEvent + rollups            (rollups: Phase 8)
  iran/            Iran CIDR database + matching         (Phase 6)
  api/             DRF router, JWT auth endpoints
templates/         base layout + per-app templates
static/            CSS (NOC black/white/gray theme)
docker/            nginx.conf for the reverse-proxy service
```

## Local development (without Docker)

Requires a local PostgreSQL and Redis instance.

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
3. **Incremental Nginx log reader, 503 parser, `RequestEvent`** (this repo).
4. Full `IPAddress` intelligence fields + Celery IP-intelligence queue + Redis locks (identity/dedup already lands in Phase 3).
5. WHOIS service/parser/cache (7-day freshness).
6. Iran CIDR database, matching, history, monthly validation.
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
