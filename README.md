# Nautobot Upgrade Readiness Assessment Job

A version-agnostic Nautobot Job that inspects a running Nautobot instance and
produces a structured JSON report for upgrade planning. The same file runs on
Nautobot **1.x, 2.x, and 3.x** — feature detection is dynamic, so checks that
don't apply to the running version emit `null`/`skipped` rather than error.

The JSON output is designed to be consumed by the companion web app in
[networktocode-llc/nautobot-upgrade-assessment-server](https://github.com/networktocode-llc/nautobot-upgrade-assessment-server),
which produces an interactive, PDF/Word-exportable report from it.

---

## What it reports

| Area | Details |
|------|---------|
| Environment | Nautobot, Python, Django, database engine & version, queue backend (Celery vs RQ) |
| Settings hygiene | Removed/deprecated settings still present, `STRICT_FILTERING`, pre-1.5 Celery queue pinning, debug mode, auth backends |
| Compatibility matrix | Runtime Python / Django / DB versions vs the target's requirements, with `ok` / `runtime_too_old` / `runtime_too_new` / `db_too_old` / `mismatch` verdicts per axis |
| Installed apps | Runtime introspection (models, views, API, filtersets, nav) + per-app source-code scan using pylint-nautobot catalogs; Python code, HTML templates, JS/CSS, and HTML-embedded-in-Python all scanned for deprecated patterns |
| Bootstrap 3 → 5 migration | Per-app scan for the classes, `data-bs-*` attributes, grid changes (`col-xs-*`, `col-*-offset-*`, push/pull), Nautobot-specific class renames (`nb-*`), and jQuery usage covered by the upstream [Bootstrap v3→v5 guide](https://docs.nautobot.com/projects/core/en/stable/development/apps/migration/from-v2/upgrading-from-bootstrap-v3-to-v5/). Each finding carries its Bootstrap-5/Nautobot replacement hint |
| App compatibility | `Requires-Dist` constraints from each app's metadata vs the chosen target version (reports `blocks_upgrade_to_v2`, `blocks_upgrade_to_v3`, `blocks_target_version`) |
| Jobs | Registered jobs with per-job code-complexity analysis; scheduled-jobs detail (interval, enabled, last-run) |
| Job approval readiness | Jobs and ScheduledJobs still using the `approval_required` flag (removed in 3.0 / 3.1 in favor of the ApprovalWorkflow model) |
| Task-queue migration (2.4) | ScheduledJobs on the legacy `queue` CharField vs the new `job_queue` FK; Jobs still declaring `task_queues` |
| Data-model inventory | Object counts for DCIM, IPAM, Extras, Tenancy, Circuits, Virtualization — including `DeviceRedundancyGroup` (1.5+) and `InterfaceRedundancyGroup` (1.6+) |
| IPAM Namespace migration (1.x → 2.x) | VRFs with `enforce_unique`, prefixes and IPs that would collapse into the default Global namespace, duplicate-prefix / duplicate-IP candidates that will land in the Cleanup namespace, and — on 2.x+ — the realized per-namespace distribution |
| Field-state deltas | Row counts where legacy single-FK fields still carry data: `Prefix.location` / `VLAN.location` (2.2+ became M2M), `Device.cluster` (3.0 became M2M) |
| UI Component Framework impact (2.4) | Third-party `TemplateExtension` subclasses whose target model's detail view migrated to the new framework |
| Integrations | SSoT adapters, webhooks, git repositories (with credential-style classification: inline creds vs SecretsGroup), secrets groups |
| API consumers (inbound) | Tokens, recent API-driven changes by user, external auth backends, **writes against removed-in-target models** (strong signal of callers still using deprecated endpoints) |
| Feature audits | Dynamic groups, saved views, permission constraints, GraphQL queries (with per-query deprecated-token hit counts) |
| Deprecated API URLs | Webhook `payload_url`s, ConfigContext JSON, ExportTemplate bodies, and Job source scanned for pre-2.0 REST paths (`/api/dcim/sites/`, etc.) |
| Content-type feature usage | CustomField / Relationship / Status / Tag / Webhook / CustomLink / ExportTemplate / ComputedField / JobHook / JobButton / Note rows whose `content_types` M2M or `content_type` FK points at a model removed in 2.0 |
| Read-traffic signals | Opportunistic detection via the in-process `django-prometheus` registry (aggregated across workers when `PROMETHEUS_MULTIPROC_DIR` is set); emits a drop-in middleware snippet for full read-attribution when the registry isn't useful |
| Migrations | Applied per-app counts and any pending migrations |
| Retention | ObjectChange / JobResult / JobLogEntry / admin-log row counts (pre-upgrade pruning candidates) |
| Pre-migrate audit | Captured output from Nautobot's `pre_migrate`, `audit_dynamic_groups`, and `audit_graphql_queries` management commands (when available on the running version) |

### Data safety

The output contains **no device credentials, passwords, custom-field values, or
user-generated content**. Only schema shape, object counts, import paths, class
names, and deprecated-pattern evidence are collected. See the module docstring
in [jobs/nautobot_upgrade_readiness.py](jobs/nautobot_upgrade_readiness.py) for
the full data-handling rationale.

---

## Requirements

- Nautobot 1.3+, 2.x, or 3.x (verified patterns for 1.5 through 3.1)
- Read-only access to the Nautobot database (the Job is marked `read_only = True`)
- A user with permission to run Jobs and view Job Results

No extra Python dependencies beyond Nautobot itself. Optional but nice-to-have:

- **`django-prometheus`** (or the `nautobot_capacity_metrics` app) — enables the
  "Read-traffic signals" section. If absent, the Job emits a ready-to-install
  middleware snippet in the output instead.
- **`PROMETHEUS_MULTIPROC_DIR`** configured and shared between uWSGI + Celery —
  lets the Prometheus probe see aggregated counts across all Nautobot workers
  instead of only its own process.

---

## Deploying the Job

Pick one of the three standard ways Nautobot loads custom Jobs.

### Option A — Git repository (recommended)

This repo is already laid out for Nautobot's Git Repository sync — the Job
lives at `jobs/nautobot_upgrade_readiness.py`, which is exactly where Nautobot
expects to find it.

1. In Nautobot: **Extensibility → Git Repositories → Add**, point it at this
   repository (or your fork), enable the **jobs** provided content type, and
   **Sync**.
2. Nautobot auto-discovers the Job after sync — no service restart required.

### Option B — `JOBS_ROOT`

1. On your Nautobot host, identify the value of `JOBS_ROOT` in
   `nautobot_config.py` (default: `$NAUTOBOT_ROOT/jobs`).
2. Copy the file:
   ```bash
   cp jobs/nautobot_upgrade_readiness.py $JOBS_ROOT/
   chown nautobot:nautobot $JOBS_ROOT/nautobot_upgrade_readiness.py
   ```
3. Restart the Nautobot web and worker services so they pick up the new file:
   ```bash
   sudo systemctl restart nautobot nautobot-worker
   # or, for docker-compose based installs:
   docker compose restart nautobot nautobot-worker
   ```

### Option C — Container-based Nautobot

If your Nautobot runs in a container and you own the image, bake the file in:

```dockerfile
COPY jobs/nautobot_upgrade_readiness.py /opt/nautobot/jobs/
```

Or bind-mount it from the host in your compose file:

```yaml
services:
  nautobot:
    volumes:
      - ./jobs/nautobot_upgrade_readiness.py:/opt/nautobot/jobs/nautobot_upgrade_readiness.py:ro
```

Then `docker compose restart nautobot nautobot-worker`.

---

## Enabling and running the Job

After deploy, enable and run the Job once:

1. **Jobs → Jobs** — find **Upgrade Readiness Assessment**.
2. Click **Edit Job** and set **Enabled = true** (first-time deploys only).
3. Click **Run Job Now**.
4. On the Job form, pick a **Target Nautobot Version** from the dropdown.
   Supported targets: `2.3`, `2.4`, `3.0`, `3.1` (default: `3.1`). The chosen
   target drives the compatibility-matrix check and the `blocks_target_version`
   flag on each installed app. Add more targets by editing
   `TARGET_VERSION_REQUIREMENTS` at the top of the Job file.
5. Submit. The Job typically finishes in under a minute on a medium-sized
   install; large installs with many plugins may take a few minutes.

### Retrieving the JSON output

On the **Job Result** page, the structured JSON is attached as a file artifact
named something like `assessment_job_output.json`. Click **Download**.

**A note on Nautobot 1.x output shape.** Nautobot 1.x stringifies whatever
`run()` returns, so on 1.x the file looks like:

```json
{"output": "{\"assessment_metadata\": {...}}"}
```

The Job pre-serializes to compact JSON on 1.x (no embedded newlines) so
`json.loads(data["output"])` gives you a clean object. On 2.x+ the
`JobResult.result` field stores the dict natively, with no outer wrapping.

**The companion webapp unwraps either shape transparently on upload**, so
in normal use you don't need to clean the file first.

You can also fetch it via the REST API:

```bash
curl -sSf \
    -H "Authorization: Token $NAUTOBOT_TOKEN" \
    "https://nautobot.example.com/api/extras/job-results/$RESULT_ID/" \
    | jq -r '.data' > assessment_job_output.json
```

---

## Companion report app

The JSON output is consumed by the companion web app in
[networktocode-llc/nautobot-upgrade-assessment-server](https://github.com/networktocode-llc/nautobot-upgrade-assessment-server),
which renders it as an interactive report with PDF/Word export. See that
repository's README for setup and usage.

---

## Troubleshooting

| Symptom | Likely cause |
|---------|--------------|
| Job not visible under **Jobs → Jobs** | `nautobot` and `nautobot-worker` processes weren't restarted; or file permissions block import. Check Nautobot logs for `JobError`. |
| Job runs but output is mostly `null` / `skipped` | Expected on older Nautobot versions — the Job reports what is available and marks the rest as not present. `null` for a model means "doesn't exist on this version"; `0` means "exists but empty". |
| Target-version dropdown missing a version | Add the version to `TARGET_VERSION_REQUIREMENTS` near the top of the Job file; the dropdown rebuilds from that dict. |
| "Permission denied" reading app source | The Nautobot worker user must be able to read the Python files of installed apps in its `site-packages`. |
| `read_traffic_signals.prometheus_counters.legacy_view_hits` always empty | The Job's Celery worker has its own per-process Prometheus registry. Set `PROMETHEUS_MULTIPROC_DIR` (see the `prometheus_client` docs) and share it between uWSGI and Celery workers — then the probe aggregates across all processes. |
| `pre_migrate_report` says `not_available` | The `pre_migrate` / `audit_dynamic_groups` / `audit_graphql_queries` management commands were added in Nautobot 2.x. On 1.x they simply don't exist — this is expected. |
| Output on 1.x has `\n`-escaped content | Nautobot 1.x wraps the Job's string return in `{"output": "..."}`. The webapp auto-unwraps this; to read the raw file by hand, run `jq -r .output assessment_job_output.json \| jq`. |

---

## Development

The Job is a single self-contained file. Edits take effect after running
**Sync Now** on the Git Repository (Option A) or restarting the Nautobot
worker (Option B).

For syntax validation without a live Nautobot:

```bash
python -m py_compile jobs/nautobot_upgrade_readiness.py
```
