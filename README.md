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

## Status: Phase 2 — server/SSH management + log discovery

Phase 1 (foundation) and Phase 2 (servers + SSH + log discovery) are
implemented. The incremental log reader/parser, IP intelligence, WHOIS and
Iran CIDR pipeline are not implemented yet. See [Roadmap](#roadmap) below.

Nothing in the UI or API returns fabricated data — dashboard cards that
depend on unbuilt apps show "pending", and unbuilt nav entries are
disabled rather than linking to pages that don't exist.

Phase 2, concretely:

- `Server` model (SSH connection details; the private key/password is
  encrypted at rest via `apps.common.fields.EncryptedTextField`, a Fernet
  field keyed by `SSH_CREDENTIAL_ENCRYPTION_KEY`).
- `apps.servers.services.SSHService` — a small, fixed set of operations
  (`test_connection`, `discover_logs`, `stat_log`) over paramiko. No
  arbitrary-command execution; log discovery uses SFTP `listdir_attr`
  rather than shell globbing.
- "Test Connection" and "Rescan Logs" enqueue Celery tasks
  (`apps.servers.tasks`) on the `maintenance` queue, guarded by a
  Redis-backed lock (`apps.common.locks.redis_lock`) so a slow SSH op
  can't be triggered twice concurrently for the same server.
- Discovery upserts `LogSource` rows (new ones start disabled — an
  operator opts a file into monitoring from the server detail page or the
  cross-server Log Sources list).
- Every mutating action (add/edit/delete/enable/disable a server, toggle
  a log source, test connection, discover logs) writes an
  `apps.users.AuditLogEntry`.

## Project layout

```
config/            settings (base/development/production/test), urls, celery, wsgi/asgi
apps/
  common/          TimeStampedModel, EncryptedTextField, redis_lock, request-IP helper
  users/           custom User model, login/logout, audit log
  dashboard/       nav tree, dashboard views
  servers/         Server model, SSHService, CRUD + test-connection/discovery views
  logs/            LogSource model, cross-server list + enable toggle
  ips/             IPAddress intelligence record        (Phase 4)
  whois/           whois execution/cache/parsing        (Phase 5)
  geo/             geolocation abstraction               (Phase 8)
  incidents/       503 RequestEvent + rollups            (Phase 3/8)
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
2. **Server/SSH management, Nginx log/file discovery** (this repo).
3. Incremental Nginx log reader, 503 parser, `RequestEvent`.
4. `IPAddress` dedup + Celery IP queue + Redis locks.
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
