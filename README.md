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

## Status: Phase 9 — retention/purge, worker monitoring, audit log, deployment docs

All nine phases of the original roadmap are now implemented: the full
ingestion → intelligence pipeline, the investigation surfaces, the visual
layer, and now the operational surfaces - retention/purge, worker
monitoring, an in-app audit log, and production deployment docs. One
tracked gap remains beyond the original roadmap: the full REST API (see
[Roadmap](#roadmap)).

Nothing in the UI or API returns fabricated data — unbuilt nav entries
are disabled rather than linking to pages that don't exist. **No
geolocation dataset or Iran CIDR data ships with this project** - this
sandbox has no network access and no way to verify such data, and
inventing it for security/geo-classification features would be exactly
the kind of fake data the project rules warn against. `GEOIP_PROVIDER`
defaults to `null`; `CountryNetwork` starts empty (see Phases 6/8). Both
are real, pluggable, and ready for a deployment that adds a trusted
source - see Settings → GeoIP / Iran CIDR Sources for current status.

Phase 9, concretely:

- **Retention/purge** (spec section 38) - per-model purge tasks
  (`RequestEvent`, `WhoisRecord`, and `IPAddress` on its exact compound
  eligibility rule) orchestrated by `apps.ips.tasks.purge_old_data`,
  scheduled daily via Celery Beat. The subtle part: `IPCountryHistory`'s
  FK to `IPAddress` is `CASCADE`, so an IP purge would silently destroy
  "keep indefinitely" Iran classification history if not excluded - the
  eligibility query excludes any IP with *any* history row (open or
  closed), not just currently-Iranian ones, closing that gap explicitly
  (see the test for this exact scenario).
- **Worker monitoring** (spec section 34) - a real **Workers** page,
  combining live Redis queue depth (`LLEN`, no worker needs to be up to
  see it) with `django-celery-results` (`CELERY_TASK_TRACK_STARTED=True`)
  for genuine Running/Failed/Completed/Last-execution history, grouped
  into the five named queues. This added a new real dependency rather
  than faking historical data Celery doesn't retain on its own.
- **Audit log surfacing** (spec section 44) - `AuditLogEntry` has existed
  since Phase 1 with every mutating action already writing to it, but
  only `/admin` could read it; **Settings → Audit Log** is its first
  in-app view (filterable by action/result). Not one of spec section
  61's literal five Settings items, but the roadmap's own Phase 9
  description names "audit log surfacing" explicitly.
- **Settings pages** (WHOIS, Retention, GeoIP, Iran CIDR Sources, Users)
  - read-only displays of the current effective configuration, not
  editable forms: spec section 51 makes environment variables the single
  source of truth, so a "Save" button here would either do nothing or
  require a second, competing configuration path. Retention gets a real
  **Run Purge Now** action (dispatches the same Celery task the daily
  schedule uses); Users redirects to `/admin` (already the real
  user-management UI, not worth duplicating).
- **Production deployment docs** - `deploy/systemd/*.service` (Gunicorn,
  a WHOIS-only Celery worker with its own concurrency limit per spec
  section 35, a worker for everything else, Celery Beat) and
  `deploy/nginx/ipscout.conf` for the traditional (non-Docker) path,
  plus a concrete step-by-step README walkthrough - resolving the "lands
  in Phase 9" deferral from the Phase 1 README.

Prior phases, briefly: server/SSH management with encrypted credentials
and Nginx log discovery (Phase 2); an incremental log reader and
configurable parser feeding 503-only `RequestEvent` rows (Phase 3); the
full `IPAddress` schema and Celery IP queue (Phase 4); real WHOIS
execution with a 7-day cache (Phase 5); real Iran CIDR matching, history,
and monthly validation (Phase 6); the IP detail page, 503 intelligence
dashboards, and Iran IP export (Phase 7); Chart.js dashboards and the
Leaflet world map, plus GeoIP (Phase 8). See each phase's commit message
for the full detail.

## Project layout

```
config/            settings (base/development/production/test), urls, celery, wsgi/asgi
apps/
  common/          TimeStampedModel, EncryptedTextField, redis_lock, request-IP helper
  users/           custom User model, login/logout, audit log + its view
  dashboard/       nav tree, dashboard/map/workers/settings views, chart+map+worker services
  servers/         Server model, SSHService (test/discover/poll_log), CRUD views
  logs/            LogSource model, NginxLogParser, NginxLogReader, poll Celery tasks
  ips/             IPAddress (full schema), IPIntelligenceService, process_new_ip + purge tasks, IP list + detail
  whois/           WhoisService (subprocess), WhoisParser, WhoisRecord, perform_whois_lookup, purge task
  geo/             GeoIPProvider (null/maxmind), GeoIPService, enrich_ip
  incidents/       RequestEvent, 503 Overview/IPs/Timeline views, purge task    (rollups: still open)
  iran/            CountryNetwork, IPCountryHistory, IranCIDRProvider, matching, monthly validation, export
  api/             JWT auth, /dashboard/ + /map/ endpoints  (full REST API: still open, see Roadmap)
templates/         base layout + per-app templates
static/            CSS (NOC black/white/gray theme), dashboard/map JS
docker/            nginx.conf for the Docker Compose reverse-proxy service
deploy/            systemd units + nginx config for the traditional (non-Docker) path
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
8. **Dashboard charts, world map, filters** - including `apps.geo`'s GeoIP provider abstraction, since the map needs coordinates.
9. **Retention/purge, worker monitoring, audit log surfacing, production deployment docs** (this repo). All nine phases of the original roadmap are now complete.
10. *(tracked gap, not in the original 9-phase roadmap)* The full REST API from spec section 39 - ViewSets/serializers for servers, log sources, IPs, 503 events, Iran CIDRs/exports, workers, with filtering/search/ordering/pagination. Only `/api/v1/auth/`, `/api/v1/dashboard/`, and `/api/v1/map/` exist today; everything else in this repo is web-UI-only.

## Production deployment

Two supported paths. Either way, set
`DJANGO_SETTINGS_MODULE=config.settings.production` — that module
refuses to start with a default `SECRET_KEY`, an empty `ALLOWED_HOSTS`, or
a missing `SSH_CREDENTIAL_ENCRYPTION_KEY`.

### Docker Compose

Build with `requirements/production.txt`, run `gunicorn
config.wsgi:application` behind the `nginx` service, `celery worker` and
`celery beat` as separate long-running services (see `docker-compose.yml`
- swap the dev `command:` overrides for the `Dockerfile`'s default CMD,
and split the worker service into one per queue the same way the
systemd path below does if you need WHOIS's concurrency capped
independently of the rest).

### Traditional Linux (Ubuntu/Debian, systemd)

```bash
# 1. System packages
sudo apt update
sudo apt install -y python3-venv python3-pip postgresql redis-server nginx whois

# 2. App user + code
sudo useradd --system --create-home --shell /bin/bash ipscout
sudo -u ipscout git clone <your-fork-url> /opt/ipscout
cd /opt/ipscout
sudo -u ipscout python3 -m venv .venv
sudo -u ipscout .venv/bin/pip install -r requirements/production.txt

# 3. Database
sudo -u postgres createuser ipscout
sudo -u postgres createdb ipscout -O ipscout
sudo -u postgres psql -c "ALTER USER ipscout WITH PASSWORD 'change-me';"

# 4. Configuration
sudo -u ipscout cp .env.example .env
sudo -u ipscout $EDITOR .env   # DJANGO_SETTINGS_MODULE=config.settings.production,
                                # a real DJANGO_SECRET_KEY, ALLOWED_HOSTS, DATABASE_URL,
                                # SSH_CREDENTIAL_ENCRYPTION_KEY (see the comment in .env.example)

# 5. Migrate + static files
cd /opt/ipscout
sudo -u ipscout .venv/bin/python manage.py migrate
sudo -u ipscout .venv/bin/python manage.py collectstatic --noinput
sudo -u ipscout .venv/bin/python manage.py createsuperuser

# 6. systemd services (Gunicorn, two Celery workers, Celery Beat)
sudo cp deploy/systemd/*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ipscout-gunicorn ipscout-celery-worker ipscout-celery-worker-whois ipscout-celery-beat

# 7. Nginx
sudo cp deploy/nginx/ipscout.conf /etc/nginx/sites-available/ipscout
sudo ln -s /etc/nginx/sites-available/ipscout /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

`deploy/systemd/` has four units:

- `ipscout-gunicorn.service` — the app server, bound to `127.0.0.1:8000`.
- `ipscout-celery-worker.service` — everything except WHOIS
  (`logs,ips,iran,maintenance`).
- `ipscout-celery-worker-whois.service` — WHOIS only, on its own
  concurrency limit (spec section 35: never let WHOIS run unbounded).
- `ipscout-celery-beat.service` — the scheduler, using
  `django_celery_beat`'s `DatabaseScheduler` so periodic tasks (log
  polling, monthly Iran validation, daily retention purge) are editable
  from `/admin/django_celery_beat/periodictask/` without a restart.

Check status/logs the normal systemd way: `systemctl status
ipscout-gunicorn`, `journalctl -u ipscout-celery-worker -f`. For TLS,
add a certificate (e.g. via `certbot --nginx`) - `config.settings.production`
already sets `SECURE_SSL_REDIRECT` and `SECURE_PROXY_SSL_HEADER` expecting
to sit behind exactly this kind of proxy.
