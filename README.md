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

## Status: Phase 10 — full REST API + global search, verified end-to-end

All nine phases of the original roadmap are implemented, plus the
tracked gap from Phase 9: the full REST API (spec section 39), its
example queries (section 40), and global search (section 41) - the last
three pieces of the spec with no code behind them at all.

Every phase up to this point had only ever been checked with
`manage.py check` and a DB-free test subset - real PostgreSQL/Redis/
whois were never available. This build now has: `migrate` run for
real against PostgreSQL 15 (all migrations across all ten phases,
including the custom `inet`/`cidr` fields and their lookups, applied
cleanly); the full test suite (292 tests) run for real, not skipped;
and a live `runserver` smoke test - session login, JWT issuance, an
authenticated API call, and a rendered dashboard page - all against
that same real Postgres/Redis. Three real bugs only reachable this way
were found and fixed:

- `IranExportAPIView`'s `?format=txt|csv` (spec section 40) 404'd
  before `get()` ever ran, because DRF's default content negotiation
  treats `?format=` as its own renderer-selection query param and had
  no `txt`/`csv` renderer registered - only `?format=json` worked by
  accident. Fixed by overriding `perform_content_negotiation` to skip
  DRF's renderer selection entirely, since this view only ever returns
  a raw `HttpResponse` it builds itself.
- `AuditLogMiddleware` set the per-request `contextvars.ContextVar`
  used to attribute audit log entries to the acting user, but never
  reset it. Django's synchronous request handling reuses the same OS
  thread (and `Context`) across requests, so on a real multi-request
  process the value leaked into whatever ran next on that thread -
  visible once the test suite ran against a real threaded DB backend
  instead of being skipped. Fixed with a `contextvars.Token` returned
  from `set_context()` and reset in a `finally` block.
- A worker-monitoring test asserted Redis-unreachable behavior by
  relying on the sandbox simply having no Redis at all - true until
  now. Fixed to point at a definitely-closed port via
  `override_settings` instead, so the test is deterministic regardless
  of what's actually running.

With real infrastructure available, the four remaining disabled nav
placeholders (Logs → Readers, IP Intelligence → Countries/ASNs/WHOIS)
were closed out too - the last gaps between the nav tree and actual
pages:

- **Countries** / **ASNs** (`apps/ips`): directory pages grouping all
  known IPs by GeoIP country / WHOIS ASN, each row linking into the
  existing filtered IP list (`?q=<code>` / `?asn=<n>`, both already
  supported by `ip_list`). Deliberately not scoped to a time window -
  see `DashboardAnalyticsService` for the period-scoped, 503-incident
  country chart this doesn't duplicate. ASNs group by `asn` alone
  (`Max("organization")` for display), not `(asn, organization)`,
  since the same ASN's organization string can vary slightly across
  individual WHOIS responses.
- **Readers** (`apps/logs`): the raw incremental-read state
  (inode/byte_offset/last_error) "Log Sources" only ever summarized
  into a status dot, plus a "Poll now" button - previously the only
  way to trigger a reader was to wait for Celery Beat's schedule.
- **WHOIS** (`apps/whois`, previously had no `views.py`/`urls.py` at
  all): a browsable, filter-by-IP archive of every `WhoisRecord`, and
  a detail page finally showing a lookup's actual raw response and
  parsed fields - nowhere in the UI displayed `raw_response` before
  this, even on the IP detail page's "Recent WHOIS Lookups" table.

13 new tests; 305/305 passing against the same real Postgres/Redis,
plus a live `runserver` check that all four new pages return 200.

The async pipeline itself was then verified for real too: a real
`celery worker` (all five named queues) and a real `celery beat`
(`django_celery_beat`'s `DatabaseScheduler`) against the same real
Redis broker - not `CELERY_TASK_ALWAYS_EAGER`, which is all any test
in this repo exercises. Dispatched `process_new_ip` from a separate
process; the worker picked it up over the broker, chained into real
`perform_whois_lookup` / `classify_ip` / `enrich_ip` tasks, and the
WHOIS lookup hit RIPE's actual WHOIS service and got back (and
correctly parsed) a real registration record - with `asn` correctly
left unset, since that particular real response had no `origin:`
field to parse. Also let beat run long enough to fire "Poll enabled
log sources" (every 30s) on its own schedule and confirmed the worker
executed it. No bugs found this round - unlike the migration/test-suite
verification and the nav-placeholder pass before it, this one held up
end-to-end on the first try.

Proving real network access was available (the WHOIS lookup above)
prompted going back to fix something that access had actually been
blocking: **Iran CIDR classification, the application's namesake
feature, now has a real, working data source.**
`apps.iran.providers.RipeNccDelegatedStatsProvider`
(`IRAN_CIDR_SOURCE=ripencc`) fetches and parses RIPE NCC's own
delegated-extended stats file - the registry's primary allocation
record, freely published, no API key or account required - and
extracts every IPv4/IPv6 block currently allocated or assigned to Iran.
Run for real against the live file: **2,529 CIDR blocks fetched and
persisted**, and a real address inside one of them
(`2.57.3.1`, matched against `2.57.3.0/24`) correctly classified
`is_iran=True` by the unmodified, already-existing classification code.
`IRAN_CIDR_SOURCE` still defaults to `static` (an empty
`CountryNetwork` table, populated only if an operator adds rows) rather
than switching every deployment onto a new external network dependency
by default - that's a deliberate choice a deployment should make, not
something to change silently. Fixed a real bug surfaced while building
this: `IranCIDRValidationService.run()`'s disable-stale-entries pass
was scoped to `source="manual"` unconditionally, so a second provider's
entries would never be disabled when the upstream feed stopped
reporting them; it's now scoped to `provider.SOURCE`, and each provider
declares its own (`static` -> `"manual"`, `ripencc` -> `"ripencc"`), so
two providers' data can coexist in `CountryNetwork` without one's
validation pass touching the other's rows. 11 new tests (offline,
fixture-based parsing coverage - the live RIPE fetch above was a manual
verification, not something the test suite depends on network for).

The same pattern applied one more time, to GeoIP: MaxMind's own
GeoLite2-City needs a licensed account, so `MaxMindGeoIPProvider`
(unmodified - no new code needed) was verified for real against
**DB-IP's City Lite database instead** (download.db-ip.com/free/, CC BY
4.0, no signup) - DB-IP builds it in the same MaxMind DB binary format
specifically for compatibility with the standard `geoip2` library this
provider already uses. Downloaded the real ~130MB file and ran a real
lookup through the unmodified app code
(`GeoIPService.enrich()` against real Postgres): `2.57.3.1` -> Tehran,
Iran, `35.7239/51.4329` - correctly persisted onto the IP row. Surfaced
one now-stale test in the process: `MaxMindGeoIPProviderTests` asserted
an "import fails, package genuinely isn't installed" path by relying on
`geoip2` being absent from the sandbox - no longer true once installing
it to run this verification (and never true in a real deployment,
since `requirements/base.txt` already declares it). Fixed with
`patch.dict(sys.modules, {"geoip2.database": None})` so the test forces
the failure deterministically instead of depending on ambient
environment state - same category of fix as the Redis-unreachable test
two commits back.

**Then the last remaining mocked-only surface got the same treatment:
SSH itself.** Every prior phase's SSH-connectivity tests used a mocked
`paramiko.SSHClient` - `apps.servers.services.SSHService` had never
actually opened a real SSH connection. Ran a real, rootless `sshd`
(this sandbox's `openssh-server` package, no root needed - a generated
host key, a generated client keypair, `UsePAM no`, an unprivileged
port) and pointed a real `Server` row at it. Result: the entire
ingestion pipeline, unmocked end to end, in one pass -

1. `SSHService.test_connection()` - real paramiko connection, real
   `uname -s` / `command -v nginx` exec over the wire.
2. `discover_server_logs` - real SFTP directory listing found a real
   log file.
3. `poll_log_source`, called twice - the first call correctly
   baselined to end-of-file without backfilling the file's existing
   content (`known_inode=None`'s documented behavior, not a bug);
   after appending new lines and polling again, a real `stat` over SSH
   plus a real SFTP range-read pulled back exactly the new bytes.
4. `NginxLogParser` correctly parsed real combined-format lines and
   kept only the 503s, discarding a 200 in the same batch.
5. `IPIntelligenceService.record_sightings_bulk()` correctly dispatched
   `process_new_ip` only for the genuinely new IP in the batch, not one
   already known from an earlier manual test - confirmed by reading its
   own docstring's claimed behavior, not assumed.
6. That real Celery task chain (drained by a real worker against the
   real Redis broker) produced a **real WHOIS lookup** for the new IP
   (`185.231.114.5` -> ASN 197946, "Amnpardaz Soft Corporation") and
   **real Iran CIDR classification** against the RIPE data from two
   commits ago (`is_iran=True`, matched `185.231.114.0/24`).

No bugs found, no code changes needed - every piece already worked
correctly together. This closes the loop: as of this pass, every major
subsystem (Postgres/migrations, the full test suite, Celery worker +
beat against a real broker, WHOIS, Iran CIDR classification, GeoIP,
and now SSH/SFTP log ingestion) has been exercised against something
real, not a mock, at least once.

Nothing in the UI or API returns fabricated data — every nav entry now
has a real page behind it, and no result is invented when a source
(GeoIP, WHOIS, Iran CIDR) has nothing to say. `GEOIP_PROVIDER` defaults
to `null` and `IRAN_CIDR_SOURCE` defaults to `static` (both start
empty) - not because real data is unreachable (both now have a
verified-working real source, see above and Settings → GeoIP / Iran
CIDR Sources), but because embedding a large, independently-updated
external dataset - or pointing a scheduled task at an external network
dependency - by default is a deployment's decision, not something to
default silently.

Phase 10, concretely:

- **Read-only DRF ViewSets** for `Server` (no `ssh_private_key` in any
  response, ever - a dedicated test asserts this explicitly), `LogSource`,
  `IPAddress`, `RequestEvent` (registered at `/api/v1/503/`),
  `CountryNetwork`, plus `/api/v1/iran/ips/` - every path spec section 39
  names, verified to match by inspecting the router's actual generated
  URL patterns. Filtering/searching/ordering come from the
  `DjangoFilterBackend`/`SearchFilter`/`OrderingFilter` wired globally
  since Phase 1; `?country=IR`, `?is_iran=true`, `?days=7` (section 40's
  literal examples) are handled explicitly since the query param names
  don't match the underlying field names 1:1.
- Read-only **on purpose**: mutating a server (touches encrypted SSH
  credentials), toggling a log source, or forcing WHOIS/Iran
  recalculation stay web-UI-only actions - audit-logged, CSRF-protected
  forms - rather than opening a second, parallel JSON surface for the
  same security-sensitive operations.
- **`/api/v1/iran/export/`** and **`/api/v1/workers/`** reuse the exact
  same `IPExportService`/`WorkerMonitoringService` code the web pages use
  - no duplicated logic. The export endpoint is a real `APIView` rather
  than a bare reuse of the web view function, specifically so it goes
  through JWT authentication (a plain `@login_required` view only
  recognizes a session cookie).
- **Global search** (spec section 41): a topbar search box on every page,
  `resolve_search()` routes a query to the right destination - a known
  IP's detail page, an unknown IP's (empty) address search, a CIDR's
  contained-IP list (via the same `is_contained_by` lookup the Iran
  export uses), an ASN's IP list, an exact server name/hostname match's
  server page, or a free-text search across address/organization/
  network/country. Never creates a record for something not seen before.

Prior phases, briefly: retention/purge, worker monitoring, an in-app
audit log, and production deployment docs (Phase 9); Chart.js dashboards,
the Leaflet world map, and GeoIP (Phase 8); the IP detail page, 503
intelligence dashboards, and Iran IP export (Phase 7); real Iran CIDR
matching, history, and monthly validation (Phase 6); real WHOIS execution
with a 7-day cache (Phase 5); the full `IPAddress` schema and Celery IP
queue (Phase 4); an incremental log reader and configurable parser
feeding 503-only `RequestEvent` rows (Phase 3); server/SSH management
with encrypted credentials and Nginx log discovery (Phase 2). See each
phase's commit message for the full detail.

## Project layout

```
config/            settings (base/development/production/test), urls, celery, wsgi/asgi
apps/
  common/          TimeStampedModel, EncryptedTextField, redis_lock, request-IP helper
  users/           custom User model, login/logout, audit log + its view
  dashboard/       nav tree, dashboard/map/workers/settings/search views, chart+map+worker+search services
  servers/         Server model, SSHService (test/discover/poll_log), CRUD views
  logs/            LogSource model, NginxLogParser, NginxLogReader, poll Celery tasks
  ips/             IPAddress (full schema), IPIntelligenceService, process_new_ip + purge tasks, IP list + detail
  whois/           WhoisService (subprocess), WhoisParser, WhoisRecord, perform_whois_lookup, purge task, browsable list/detail views
  geo/             GeoIPProvider (null/maxmind), GeoIPService, enrich_ip
  incidents/       RequestEvent, 503 Overview/IPs/Timeline views, purge task    (rollups: still open)
  iran/            CountryNetwork, IPCountryHistory, IranCIDRProvider, matching, monthly validation, export
  api/             JWT auth + full read-only REST API (servers/logs/ips/503/iran/export/workers)
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
9. **Retention/purge, worker monitoring, audit log surfacing, production deployment docs**. All nine phases of the original roadmap are complete.
10. **Full REST API (spec section 39-40) + global search (section 41)** (this repo) - the tracked gap from Phase 9, now closed. *(Not in the original 9-phase roadmap, but explicitly asked for in the spec.)*

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
