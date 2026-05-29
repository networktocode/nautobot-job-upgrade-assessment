"""Nautobot Upgrade Readiness Assessment Job.

This Job performs a deep inspection of a Nautobot instance to support an
upgrade readiness assessment. It produces a structured JSON report that
inventories installed apps, analyzes source code for upgrade complexity,
catalogs jobs and integrations, and enumerates data-model objects whose
schema changed across Nautobot major versions.

---------------------------------------------------------------------------
Version-agnostic design
---------------------------------------------------------------------------
The job detects features dynamically (model availability, settings presence,
attribute shapes) instead of assuming a specific Nautobot major version. The
same file runs on Nautobot 1.x, 2.x, and 3.x. Checks that probe a feature
unavailable on the running version emit a ``null``/``skipped`` marker
instead of an error, so the output always has the same shape and reviewers
can tell "not present" from "present but empty".

---------------------------------------------------------------------------
Data safety
---------------------------------------------------------------------------
The output contains NO device credentials, passwords, custom-field values,
or user-generated content. Only schema shape, object counts, import paths,
class names, and deprecated-pattern evidence are included.

---------------------------------------------------------------------------
What the report covers (mirrors the method ordering below)
---------------------------------------------------------------------------
  A. Environment & infrastructure (Nautobot/Python/Django/DB, queue backend)
  B. Settings checks (removed settings still present)
  C. Installed apps (runtime introspection + source-code deprecation scan)
  D. App compatibility (Requires-Dist constraints vs target version)
  E. Registered jobs (metadata + per-job code analysis)
  F. Data-model inventory (DCIM/IPAM/Extras/Tenancy/Circuits counts)
  G. Integrations (outbound: SSoT, webhooks, Git repos, secrets groups)
  H. API consumers (inbound: tokens, recent changes, auth backends)
  I. Feature audits (dynamic groups, saved views, permission constraints,
     GraphQL queries)
  J. Retention metrics (ObjectChange/JobResult volumes)

---------------------------------------------------------------------------
Deprecated-pattern catalogs
---------------------------------------------------------------------------
The source-scanner compares each app's installed Python files against a set
of catalogs adapted directly from Network-to-Code's `pylint-nautobot`
linter. Findings therefore stay aligned with what NTC's own tooling would
flag during a code review. Catalogs live in the section labeled "DEPRECATED
PATTERN CATALOGS" below.

---------------------------------------------------------------------------
Usage
---------------------------------------------------------------------------
    1. Install this file in your Nautobot Jobs directory.
    2. Run the Job from the Nautobot UI
       (Jobs -> Jobs -> Upgrade Readiness Assessment).
    3. Retrieve the JSON output from the Job Result page.
    4. Transmit the output to NTC per the agreed secure method.
"""

import importlib
import json
import pathlib
import platform
import re

from django.conf import settings
from django.db import connection

# The ``Job`` base class and ``ChoiceVar`` moved between ``nautobot.extras``
# (1.x) and ``nautobot.apps`` (2.x). Prefer the 2.x public location and fall
# back to the 1.x path so this file loads on any supported version.
try:
    from nautobot.apps.jobs import Job, ChoiceVar
except ImportError:
    from nautobot.extras.jobs import Job, ChoiceVar

# ``register_jobs`` is required on Nautobot 2.0+ for jobs loaded via
# ``JOBS_ROOT`` / a git repository to be picked up by the registry; it does
# not exist on 1.x, where simply defining the class is enough. Keep its import
# isolated so a missing/renamed ``register_jobs`` never takes ``Job`` or
# ``ChoiceVar`` down with it.
try:
    from nautobot.apps.jobs import register_jobs
except ImportError:
    register_jobs = None


# Path to this script itself. The source scanner excludes this file so the
# deprecated-pattern catalogs below — which necessarily contain the very
# strings we look for — don't match themselves when the job happens to be
# installed inside an app whose source tree is being analyzed.
_SELF_SOURCE_FILE = pathlib.Path(__file__).resolve()


# ============================================================================
#                          VERSION-AGNOSTIC HELPERS
# ============================================================================
# Small utilities that normalize over Nautobot / Django differences so the
# rest of the module can stay concise. Every helper swallows exceptions and
# returns ``None`` (or an empty container) on failure — the assessment must
# complete end-to-end even when individual probes fail.
# ============================================================================


def _nautobot_version_tuple():
    """Return the Nautobot version as a tuple of ints, or ``None``.

    Example: ``(1, 5, 6)``, ``(2, 3, 0)``. Used by callers to gate checks
    whose availability depends on the running major version.
    """
    try:
        import nautobot

        raw = getattr(nautobot, "__version__", "") or ""
    except Exception:
        return None
    parts = []
    for piece in raw.split(".")[:3]:
        match = re.match(r"(\d+)", piece)
        if not match:
            break
        parts.append(int(match.group(1)))
    return tuple(parts) if parts else None


def _get_distribution_metadata(dist_name):
    """Return ``(version, metadata_str)`` for an installed Python distribution.

    Uses :mod:`importlib.metadata` first (stdlib, preferred) and only falls
    back to ``pkg_resources`` if that fails, since ``pkg_resources`` is being
    removed from setuptools in newer releases.
    """
    try:
        from importlib import metadata as importlib_metadata

        try:
            version = importlib_metadata.version(dist_name)
        except importlib_metadata.PackageNotFoundError:
            return None, ""
        try:
            meta_obj = importlib_metadata.metadata(dist_name)
            meta_str = str(meta_obj).lower() if meta_obj else ""
        except Exception:
            meta_str = ""
        return version, meta_str
    except Exception:
        pass

    try:
        import pkg_resources  # pylint: disable=import-outside-toplevel

        dist = pkg_resources.get_distribution(dist_name)
        return dist.version, str(getattr(dist, "metadata", "") or "").lower()
    except Exception:
        return None, ""


def _get_requires_dist(dist_name):
    """Return the ``Requires-Dist`` entries for an installed package.

    Each entry is a raw requirement string (e.g. ``"nautobot>=1.5,<2.0"``).
    Used to read each installed app's declared Nautobot version range so we
    can gate compatibility with a target version.
    """
    try:
        from importlib import metadata as importlib_metadata

        try:
            return list(importlib_metadata.requires(dist_name) or [])
        except importlib_metadata.PackageNotFoundError:
            return []
    except Exception:
        return []


def _safe_get_model(app_label, model_name):
    """Return a Django model class, or ``None`` if it doesn't exist here.

    Using Django's ``apps.get_model`` (not a direct import) keeps this
    non-fatal on Nautobot versions where the model has been removed
    (``Site`` is gone on 2.x, ``Namespace`` is absent on 1.x, and so on).
    """
    try:
        from django.apps import apps

        return apps.get_model(app_label, model_name)
    except Exception:
        return None


def _safe_count(app_label, model_name):
    """Return ``.objects.count()`` for a model, or ``None`` if unavailable.

    ``None`` means the model doesn't exist on this version — a distinct
    signal from ``0`` (model exists, no rows). The caller relies on that
    distinction to plan data migrations.
    """
    model = _safe_get_model(app_label, model_name)
    if model is None:
        return None
    try:
        return model.objects.count()
    except Exception:
        return None


def _parse_version_string(ver):
    """Parse a dotted version string into an ``(int, int)`` major/minor tuple.

    Returns ``None`` if ``ver`` is empty or unparseable. Used for comparing
    the target-version picker choice against declared upper bounds like
    ``nautobot<2.4`` without pulling in :mod:`packaging`.
    """
    if not ver:
        return None
    pieces = str(ver).split(".")
    if not pieces:
        return None
    major_match = re.match(r"\d+", pieces[0])
    if major_match is None:
        return None
    major = int(major_match.group(0))
    minor = 0
    if len(pieces) > 1:
        minor_match = re.match(r"\d+", pieces[1])
        if minor_match is not None:
            minor = int(minor_match.group(0))
    return (major, minor)


def _count_import_occurrences(content, import_path):
    """Count real import statements in ``content`` that target ``import_path``.

    This is what replaces the old ``if imp in content`` substring check.
    Anchoring to real ``import``/``from`` statements eliminates the false
    positives where ``import_path`` simply appears in a string literal,
    docstring, or comment.

    Matched forms:
      * ``import <import_path>`` / ``import <import_path> as alias``
      * ``from <import_path> import ...``
      * ``from <parent> import <leaf>`` where ``import_path == "parent.leaf"``
    """
    escaped = re.escape(import_path)
    count = 0

    # `from <full_path> import ...`  and  `import <full_path>`
    count += len(re.findall(rf"(?m)^\s*from\s+{escaped}\s+import\b", content))
    count += len(
        re.findall(rf"(?m)^\s*import\s+{escaped}(?:\s+as\s+\w+)?\s*(?:#.*)?$", content)
    )

    # `from <parent> import <leaf>` — only meaningful when the path has a dot.
    if "." in import_path:
        parent, leaf = import_path.rsplit(".", 1)
        pattern = (
            rf"(?m)^\s*from\s+{re.escape(parent)}\s+import\s+[^\n#]*?\b"
            rf"{re.escape(leaf)}\b"
        )
        count += len(re.findall(pattern, content))

    return count


# ============================================================================
#                       DEPRECATED PATTERN CATALOGS
# ============================================================================
# The source-scanner compares each app's installed Python files against the
# catalogs below and reports every match. Most entries are adapted directly
# from Network-to-Code's ``pylint-nautobot`` linter so findings stay aligned
# with what NTC's official tooling would flag.
#
# Structure:
#   * ``V1_TO_V2_IMPORT_MOVES`` — 1.x → 2.x module/class relocations
#   * ``V2_TO_V3_CLASS_REMOVALS`` — 2.x → 3.x classes that are gone/moved
#   * ``V1_TO_V2_MODEL_REPLACEMENTS`` — the six big model consolidations
#   * ``REMOVED_DEPENDENCIES`` — third-party packages Nautobot no longer uses
#   * ``REMOVED_SETTINGS`` — settings.py keys dropped in 2.0
#   * ``DEPRECATED_CODE_PATTERNS`` — regex patterns for non-import deprecations
#   * ``BOOTSTRAP3_CLASSES`` / ``BOOTSTRAP3_AMBIGUOUS_CLASSES`` /
#     ``BOOTSTRAP3_REGEX_RULES`` — Bootstrap 3 → 5 classes, attributes, and
#     jQuery usage removed/renamed when BS3 was dropped (compiled into
#     ``BOOTSTRAP_MIGRATION_RULES``)
# ============================================================================


# ----------------------------------------------------------------------------
# V1 → V2 import moves (84 entries).
# Source: pylint-nautobot's ``data/v2/v2-code-location-changes.yaml``.
# Covers the large-scale restructuring that collapsed ``nautobot.utilities.*``
# into ``nautobot.core.*`` and scattered a handful of classes into
# ``nautobot.apps.*``. Key is the old dotted path, value is the replacement.
# ----------------------------------------------------------------------------
V1_TO_V2_IMPORT_MOVES = {
    # Entire-module moves (everything inside the old module moved as a unit)
    "nautobot.utilities.api": "nautobot.core.api.utils",
    "nautobot.utilities.apps": "nautobot.core.apps",
    "nautobot.utilities.checks": "nautobot.core.checks",
    "nautobot.utilities.choices": "nautobot.core.choices",
    "nautobot.utilities.config": "nautobot.core.utils.config",
    "nautobot.utilities.constants": "nautobot.core.constants",
    "nautobot.utilities.deprecation": "nautobot.core.utils.deprecation",
    "nautobot.utilities.error_handlers": "nautobot.core.views.utils",
    "nautobot.utilities.exceptions": "nautobot.core.exceptions",
    "nautobot.utilities.factory": "nautobot.core.factory",
    "nautobot.utilities.fields": "nautobot.core.models.fields",
    "nautobot.utilities.filters": "nautobot.core.filters",
    "nautobot.utilities.forms": "nautobot.core.forms",
    "nautobot.utilities.git": "nautobot.core.utils.git",
    "nautobot.utilities.logging": "nautobot.core.utils.logging",
    "nautobot.utilities.management": "nautobot.core.management",
    "nautobot.utilities.ordering": "nautobot.core.utils.ordering",
    "nautobot.utilities.paginator": "nautobot.core.views.paginator",
    "nautobot.utilities.permissions": "nautobot.core.utils.permissions",
    "nautobot.utilities.query_functions": "nautobot.core.models.query_functions",
    "nautobot.utilities.querysets": "nautobot.core.models.querysets",
    "nautobot.utilities.tables": "nautobot.core.tables",
    "nautobot.utilities.tasks": "nautobot.core.tasks",
    "nautobot.utilities.templatetags": "nautobot.core.templatetags",
    "nautobot.utilities.testing": "nautobot.core.testing",
    "nautobot.utilities.tree_queries": "nautobot.core.models.tree_queries",
    # 56 individual utilities.utils members were split up — flagging the old
    # module tells the customer their imports need touching.
    "nautobot.utilities.utils": "nautobot.core.utils (multiple targets)",
    "nautobot.utilities.validators": "nautobot.core.models.validators",
    "nautobot.utilities.views": "nautobot.core.views.mixins",
    # Targeted class/field moves
    "nautobot.core.api.utils.TreeModelSerializerMixin": "nautobot.core.api.serializers.TreeModelSerializerMixin",
    "nautobot.core.fields": "nautobot.core.models.fields",
    "nautobot.dcim.fields.MACAddressCharField": "nautobot.core.models.fields.MACAddressCharField",
    "nautobot.dcim.forms.MACAddressField": "nautobot.core.forms.MACAddressField",
}


# ----------------------------------------------------------------------------
# V2 → V3 deprecated/removed classes (27 entries).
# Source: pylint-nautobot's ``data/v3/v3-code-removals.yaml``.
# Primarily "move to ``nautobot.apps.*``" and "``Plugin*`` → unprefixed"
# renames, plus a handful of filterset/form mixin relocations.
# ----------------------------------------------------------------------------
V2_TO_V3_CLASS_REMOVALS = {
    "nautobot.dcim.filters.DeviceComponentFilterSet": "nautobot.dcim.filters.mixins.DeviceComponentModelFilterSetMixin",
    "nautobot.dcim.filters.DeviceTypeComponentFilterSet": "nautobot.dcim.filters.mixins.DeviceComponentTemplateModelFilterSetMixin",
    "nautobot.dcim.filters.CableTerminationFilterSet": "nautobot.dcim.filters.mixins.CableTerminationModelFilterSetMixin",
    "nautobot.dcim.filters.PathEndpointFilterSet": "nautobot.dcim.filters.mixins.PathEndpointModelFilterSetMixin",
    "nautobot.dcim.filters.ConnectionFilterSet": "nautobot.dcim.filters.ConnectionFilterSetMixin",
    "nautobot.dcim.api.serializers.CableTerminationSerializer": "nautobot.dcim.api.serializers.CableTerminationModelSerializerMixin",
    "nautobot.dcim.api.serializers.ConnectedEndpointSerializer": "nautobot.dcim.api.serializers.PathEndpointModelSerializerMixin",
    "nautobot.extras.filters.CreatedUpdatedFilterSet": "nautobot.apps.filters.CreatedUpdatedModelFilterSetMixin",
    "nautobot.extras.filters.RelationshipModelFilterSet": "nautobot.apps.filters.RelationshipModelFilterSetMixin",
    "nautobot.extras.filters.CustomFieldModelFilterSet": "nautobot.apps.filters.CustomFieldModelFilterSetMixin",
    "nautobot.extras.filters.LocalContextFilterSet": "nautobot.apps.filters.LocalContextModelFilterSetMixin",
    "nautobot.extras.forms.forms.CustomFieldBulkCreateForm": "nautobot.apps.forms.CustomFieldModelBulkEditFormMixin",
    "nautobot.extras.forms.mixins.AddRemoveTagsForm": "nautobot.apps.forms.TagsBulkEditFormMixin",
    "nautobot.extras.forms.mixins.CustomFieldBulkEditForm": "nautobot.apps.forms.CustomFieldModelBulkEditFormMixin",
    "nautobot.extras.forms.mixins.CustomFieldModelForm": "nautobot.apps.forms.CustomFieldModelFormMixin",
    "nautobot.extras.forms.mixins.RelationshipModelForm": "nautobot.apps.forms.RelationshipModelFormMixin",
    "nautobot.extras.forms.mixins.StatusBulkEditFormMixin": "nautobot.apps.forms.StatusModelBulkEditFormMixin",
    "nautobot.extras.forms.mixins.StatusFilterFormMixin": "nautobot.apps.forms.StatusModelFilterFormMixin",
    "nautobot.tenancy.filters.TenancyFilterSet": "nautobot.apps.filters.TenancyModelFilterSetMixin",
    "nautobot.core.testing.filters.FilterTestCases.NameOnlyFilterTestCase": "nautobot.apps.testing.FilterTestCases.FilterTestCase",
    "nautobot.core.testing.filters.FilterTestCases.NameSlugFilterTestCase": "nautobot.apps.testing.FilterTestCases.FilterTestCase",
    "nautobot.extras.choices.CustomLinkButtonClassChoices": "nautobot.apps.choices.ButtonClassChoices",
    "nautobot.extras.plugins.PluginConfig": "nautobot.apps.NautobotAppConfig",
    "nautobot.extras.plugins.PluginTemplateExtension": "nautobot.apps.ui.TemplateExtension",
    "nautobot.extras.plugins.PluginBanner": "nautobot.apps.ui.Banner",
    "nautobot.extras.plugins.PluginFilterExtension": "nautobot.apps.filters.FilterExtension",
    "nautobot.extras.plugins.PluginCustomValidator": "nautobot.apps.models.CustomValidator",
    # --- v3.0: data-validation-engine classes folded into core ---
    "nautobot_data_validation_engine.custom_validators.DataComplianceRule": "nautobot.apps.models.DataComplianceRule",
    "nautobot_data_validation_engine.custom_validators.ComplianceError": "nautobot.apps.models.ComplianceError",
}


# ----------------------------------------------------------------------------
# V1 → V2 model replacements.
# Source: pylint-nautobot's ``replaced_models.py``.
# These six consolidations drive the single biggest chunk of 1.x → 2.x code
# churn and are flagged with their replacement model.
# ----------------------------------------------------------------------------
V1_TO_V2_MODEL_REPLACEMENTS = {
    "nautobot.dcim.models.Site": "nautobot.dcim.models.Location",
    "nautobot.dcim.models.Region": "nautobot.dcim.models.Location",
    "nautobot.dcim.models.DeviceRole": "nautobot.extras.models.Role",
    "nautobot.dcim.models.RackRole": "nautobot.extras.models.Role",
    "nautobot.ipam.models.Role": "nautobot.extras.models.Role",
    "nautobot.ipam.models.Aggregate": "nautobot.ipam.models.Prefix",
}


# ----------------------------------------------------------------------------
# Third-party dependency packages Nautobot dropped in 2.0. Any app still
# importing one of these will fail on 2.x+.
# ----------------------------------------------------------------------------
REMOVED_DEPENDENCIES = [
    "django_cacheops",  # Nautobot no longer uses cacheops
    "django_cryptography",  # Secrets feature replaces encrypted fields
    "django_mptt",  # Replaced by django-tree-queries
    "django_rq",  # Celery is now the sole queue backend
]


# ----------------------------------------------------------------------------
# Settings that Nautobot 2.0 removed from the supported configuration. If
# any are still present we surface them — behavior changes silently when
# the upgrade ignores them.
# ----------------------------------------------------------------------------
REMOVED_SETTINGS = [
    # --- 2.0 ---
    "CACHEOPS",
    "CACHEOPS_DEFAULTS",
    "CACHEOPS_ENABLED",
    "CACHEOPS_REDIS",
    "ENFORCE_GLOBAL_UNIQUE",  # replaced by IPAM Namespace uniqueness
    "DISABLE_PREFIX_LIST_HIERARCHY",
    "RQ_QUEUES",  # django-rq is gone; Celery-only now
    # --- 2.1 ---
    "HIDE_RESTRICTED_UI",  # restricted UI is now always hidden
    # --- 2.3 ---
    "DYNAMIC_GROUPS_MEMBER_CACHE_TIMEOUT",  # superseded by StaticGroupAssociation
    # --- 2.4 deprecated / 3.1 removed: storage settings merged into STORAGES ---
    "DEFAULT_FILE_STORAGE",
    "STATICFILES_STORAGE",
    "STORAGE_BACKEND",
    "STORAGE_CONFIG",
    "JOB_FILE_IO_STORAGE",
    # --- 3.0 removed branding keys ---
    "HEADER_BULLET",
    "NAV_BULLET",
    "JAVASCRIPT",
    "CSS",
    # --- 3.1 removed: per-user locale preferences now drive formatting ---
    "DATE_FORMAT",
    "DATETIME_FORMAT",
    "TIME_FORMAT",
    "SHORT_DATE_FORMAT",
    "SHORT_DATETIME_FORMAT",
]


# ----------------------------------------------------------------------------
# REST API URL paths removed in Nautobot 2.0. External systems calling these
# endpoints will receive 404s after the upgrade. The scanner looks for these
# path literals in webhook ``payload_url`` values, ConfigContext JSON,
# ExportTemplate bodies, and Python/template source — anywhere a customer
# might have hard-coded a URL to a now-removed endpoint.
#
# Keys are old paths; values are the 2.x replacements (``None`` where there
# is no direct replacement).
# ----------------------------------------------------------------------------
# Field and model identifiers removed or renamed in the Nautobot 2.0
# GraphQL schema. Saved queries that still reference these tokens will
# silently return empty data (or error) after the upgrade. The scanner
# counts whole-word occurrences in each saved query's text — the query
# text itself is NOT emitted, so no customer schema detail leaks out.
REMOVED_GRAPHQL_TOKENS = [
    # --- 2.0: model consolidations ---
    "site",  # dcim.site → dcim.location
    "region",  # dcim.region → dcim.location
    "device_role",  # dcim.device_role → extras.role
    "rack_role",  # dcim.rack_role → extras.role
    "aggregate",  # ipam.aggregate → ipam.prefix (type=Container)
    "assigned_object",  # IPAddress.assigned_object removed
    "ipam_role",  # ipam.role → extras.role
    # --- 2.3: renamed reverse-relations and filters ---
    "static_groups",  # static_groups → dynamic_groups
    "object_metadatas",  # object_metadatas → object_metadata
    "associated_object_metadatas",  # → associated_object_metadata
    "CloudType",  # renamed to CloudResourceType
]


DEPRECATED_API_URLS = {
    # --- 2.0: model consolidations ---
    "/api/dcim/sites/": "/api/dcim/locations/",
    "/api/dcim/regions/": "/api/dcim/locations/",
    "/api/dcim/device-roles/": "/api/extras/roles/",
    "/api/dcim/rack-roles/": "/api/extras/roles/",
    "/api/ipam/roles/": "/api/extras/roles/",
    "/api/ipam/aggregates/": "/api/ipam/prefixes/",  # type=Container
    # --- 2.1: user/token endpoints removed ---
    "/api/users/users/my-profile/": None,
    "/api/users/users/session/": None,
    "/api/users/tokens/authenticate/": None,
    "/api/users/tokens/logout/": None,
    # --- 2.1: file / job-button URL collapse ---
    "/files/get/": None,
    "/extras/job-button/": "/extras/jobs/",  # run URL moved under /jobs/
    # --- 2.3: plural object-metadata slug corrected to singular ---
    "/api/extras/object-metadatas/": "/api/extras/object-metadata/",
}


# ----------------------------------------------------------------------------
# Target-version compatibility matrix.
# Nautobot's official support grid tells us which Python / Django versions
# each Nautobot release supports. The job compares the runtime against the
# target version the user selected on the Job form and flags any mismatch.
#
# NOTE: These ranges are a conservative best-effort as of Nautobot 2.4 and
# should be reviewed against the official release notes before each major
# upgrade. Unknown future versions will gracefully degrade to "unknown".
# ----------------------------------------------------------------------------
TARGET_VERSION_REQUIREMENTS = {
    # ``postgres_min`` / ``mysql_min`` are compared against the running DB
    # server version; 3.1 is the first release to drop PostgreSQL 12/13 and
    # MySQL <8.0.11, so this matters most for that target.
    "2.3": {
        "python_min": (3, 8),
        "python_max": (3, 11),
        "django": "3.2.x",
        "postgres_min": (12, 0),
        "mysql_min": (8, 0, 0),
    },
    "2.4": {
        "python_min": (3, 9),
        "python_max": (3, 12),
        "django": "4.2.x",
        "postgres_min": (12, 0),
        "mysql_min": (8, 0, 0),
    },
    "3.0": {
        "python_min": (3, 10),
        "python_max": (3, 12),
        "django": "4.2.x",
        "postgres_min": (12, 0),
        "mysql_min": (8, 0, 0),
    },
    "3.1": {
        "python_min": (3, 10),
        "python_max": (3, 12),
        "django": "5.2.x",
        "postgres_min": (14, 0),
        "mysql_min": (8, 0, 11),
    },
}


# Choices presented in the Job form's "Target Nautobot Version" dropdown.
# Ordered oldest-to-newest so the UI renders chronologically. Build the
# tuples from the requirements dict so adding a new release only has to
# happen in one place.
TARGET_VERSION_CHOICES = tuple((v, v) for v in TARGET_VERSION_REQUIREMENTS)

DEFAULT_TARGET_VERSION = "3.1"


# ----------------------------------------------------------------------------
# Regex patterns for deprecated *code* (as opposed to deprecated *imports*).
# These run across the concatenated text of every Python file in an app and
# record per-file matches so the report can point to the exact file that
# needs refactoring.
#
# Grouped by which major-version boundary introduced the deprecation.
# ----------------------------------------------------------------------------
DEPRECATED_CODE_PATTERNS = {
    # --- v1 → v2: model consolidation ---
    # The ``slug`` field was removed from nearly every core model.
    "slug_field_usage": r"\bslug\s*=\s*models\.",
    # Django ForeignKeys that target removed models.
    "site_foreign_key": r"(?:models\.ForeignKey|ForeignKey)\([^)]*['\"]dcim\.Site['\"]",
    "region_foreign_key": r"(?:models\.ForeignKey|ForeignKey)\([^)]*['\"]dcim\.Region['\"]",
    "aggregate_foreign_key": r"(?:models\.ForeignKey|ForeignKey)\([^)]*['\"]ipam\.Aggregate['\"]",
    "device_role_foreign_key": r"(?:models\.ForeignKey|ForeignKey)\([^)]*['\"]dcim\.DeviceRole['\"]",
    "rack_role_foreign_key": r"(?:models\.ForeignKey|ForeignKey)\([^)]*['\"]dcim\.RackRole['\"]",
    # Uses of the old-style role accessor names on Device/Rack/IPAddress.
    "old_role_reference": r"\b(?:device_role|rack_role|ipam_role)\b",
    # --- v1 → v2: IPAM overhaul ---
    # IPAddress.assigned_object was removed; use IPAddressToInterface M2M.
    "ip_assigned_object": r"\bassigned_object(?:_type|_id)?\b",
    # IPAddress.prefix renamed to IPAddress.parent.
    "ip_prefix_attr": r"\.prefix\s*=\s*[\"'\d]",
    # is_pool boolean replaced by Prefix.type enum.
    "is_pool_boolean": r"\bis_pool\s*=\s*(?:True|False)\b",
    # Prefix.get_child_prefixes() renamed to .descendants().
    "get_child_prefixes": r"\bget_child_prefixes\b",
    # --- v1 → v2: REST API surface changes ---
    # ?brief query param / brief_mode kwarg replaced by ?depth.
    "brief_param": r"\?brief\b|\bbrief_mode\s*=",
    # Nested*Serializer classes were collapsed into depth-aware serializers.
    "nested_serializer": r"\bNested[A-Z]\w*Serializer\b",
    # _id-suffixed filter kwargs were removed; filters now accept name/UUID.
    "id_suffix_filter": r"\b[a-z_]+_id\s*=\s*django_filters\.",
    # --- v1 → v2: JobResult field renames ---
    # Several fields were renamed; this catches attribute access patterns.
    "jobresult_old_fields": r"\bJobResult\.[a-z_]+\b|"
    r"\b(?:job_kwargs|obj_type|job_id)\s*=",
    # --- v1 → v2: django-mptt artifacts ---
    # Tree-fields lft/rght/tree_id/level are gone with django-tree-queries.
    "mptt_fields": r"\b(?:lft|rght|tree_id|level)\s*=\s*models\.",
    # --- v2 → v3: removed Job metadata ---
    # approval_required moved off of Job.Meta onto the Job model row.
    "approval_required": r"\bapproval_required\b",
    # commit_default is gone in the refreshed Job API.
    "commit_default": r"\bcommit_default\b",
    # --- v2 → v3: removed GraphQL helpers ---
    "execute_query": r"\bexecute_query\b",
    "execute_saved_query": r"\bexecute_saved_query\b",
    # --- v2 → v3: StatusModel inheritance deprecated ---
    # New code declares a StatusField explicitly instead of inheriting.
    "status_model_inherit": r"\bStatusModel\b",
    # __filter_fields__ dunder is deprecated.
    "dunder_filter_fields": r"__filter_fields__",
    # --- v1 → v2: legacy view base classes (should be NautobotUIViewSet) ---
    "legacy_object_view": r"\bObjectView\b",
    "legacy_object_list_view": r"\bObjectListView\b",
    "legacy_object_edit_view": r"\bObjectEditView\b",
    "legacy_object_delete_view": r"\bObjectDeleteView\b",
    "legacy_bulk_edit_view": r"\bBulkEditView\b",
    "legacy_bulk_delete_view": r"\bBulkDeleteView\b",
    "legacy_bulk_import_view": r"\bBulkImportView\b",
    # --- v1 → v2: nav menu item class ---
    "plugin_menu_item": r"\bPluginMenuItem\b",
    # --- v1 → v2: legacy manage.py reference (script must be nautobot-server) ---
    "legacy_manage_py": r"\bmanage\.py\b",
    # --- v1 → v2: Job.run() signature change ---
    # 1.x: ``def run(self, data, commit):``  (positional form)
    # 2.x: ``def run(self, **kwargs):``       (kwargs-only form)
    # Any Job still declaring the 1.x signature will silently stop receiving
    # form input on 2.x+.
    "legacy_run_signature": r"def\s+run\s*\(\s*self\s*,\s*data\s*,\s*commit\b",
    # --- 2.3: renames and removals ---
    # StaticGroup was merged into DynamicGroup with group_type="static".
    "static_group_class": r"\bStaticGroup\b",
    # DynamicGroupMixin was renamed to DynamicGroupsModelMixin.
    "dynamic_group_mixin_old": r"\bDynamicGroupMixin\b",
    # CloudType was renamed to CloudResourceType.
    "cloud_type_class": r"\bCloudType\b",
    # TreeManager default flipped — apps relying on automatic tree fields
    # must now explicitly call ``.with_tree_fields()``.
    "with_tree_fields_call": r"\.with_tree_fields\s*\(",
    # --- 2.2: Controller model renames ---
    "controller_device_group_old": r"\bControllerDeviceGroup\b",
    "deployed_controller_device": r"\bdeployed_controller_device\b",
    "deployed_controller_group": r"\bdeployed_controller_group\b",
    # --- 2.4: task-queue attribute deprecated ---
    # ``task_queues`` on Job classes is replaced by ``job_queues`` via the
    # new JobQueue model.
    "task_queues_attr": r"\btask_queues\s*=",
    # --- 3.0: GraphQL response.to_dict() removed ---
    "response_to_dict": r"\.to_dict\s*\(\s*\)",
    # --- 3.1 / Django 5.2: ``Meta.index_together`` removed ---
    "meta_index_together": r"\bindex_together\s*=",
    # --- 3.1: test helper renames (lowercase-s forms) ---
    "assert_queryset_equal_old": r"\bassertQuerysetEqual\b",
    "assert_queryset_equal_nonempty_old": r"\bassertQuerysetEqualAndNotEmpty\b",
    # --- 3.1: deprecated front-end library imported as a Python module ---
    # (CSS-class / template usage of these libraries is caught by the
    # separate frontend scanner further down.)
    "django_ajax_tables": r"\bimport\s+django_ajax_tables\b",
    # --- 1.1: REST query-param rename ``opt_in_fields`` → ``include`` ---
    "opt_in_fields_param": r"\bopt_in_fields\s*=",
    # --- 1.1 / 2.0: ``@job`` decorator was the RQ-era pattern ---
    "rq_job_decorator": r"^\s*@job\b",
    # --- 1.3: class-path-based Job REST URL, removed in 2.0 ---
    "class_path_job_url": r"/api/extras/jobs/[^/\s'\"]+/(?!\w)",
    # --- 2.0: CSV helper methods removed; CSV now goes through serializers ---
    "csv_headers_attr": r"\bcsv_headers\s*=",
    "to_csv_method": r"\bdef\s+to_csv\s*\(",
    # --- 2.0: ``composite_key`` removed from user-facing APIs ---
    "composite_key": r"\bcomposite_key\b",
}


# ----------------------------------------------------------------------------
# Bootstrap 3 → 5 migration markers. Nautobot 2.4 moved to Bootstrap 5, so the
# legacy classes/attributes below signal template (and JS/CSS) work. Catalog
# mirrors the upstream guide:
#   .../development/apps/migration/from-v2/upgrading-from-bootstrap-v3-to-v5/
#
# Three sub-catalogs feed a single compiled rule set (BOOTSTRAP_MIGRATION_RULES):
#   * ``BOOTSTRAP3_CLASSES`` — hyphenated classes safe to match as a whole token.
#   * ``BOOTSTRAP3_AMBIGUOUS_CLASSES`` — bare words (``label``, ``close`` …) that
#     collide with HTML tags/attributes/prose, so they are matched only inside a
#     ``class="…"`` attribute or as a CSS ``.selector``.
#   * ``BOOTSTRAP3_REGEX_RULES`` — grid prefixes, ``data-*`` attributes, and
#     jQuery usage expressed directly as regex.
# Each match carries its Bootstrap-5 / Nautobot replacement so the report gives
# an inline migration hint (same convention as the deprecated-import catalog).
# ----------------------------------------------------------------------------

# Hyphenated classes — matched as a whole CSS token so substrings of longer
# class names don't false-positive (``well`` won't match ``farewell``).
BOOTSTRAP3_CLASSES = {
    # Panels → Cards
    "panel-heading": "card-header",
    "panel-title": "card-title",
    "panel-body": "card-body",
    "panel-footer": "card-footer",
    "panel-default": "card",
    "panel-primary": "card border-primary",
    "panel-success": "card border-success",
    "panel-info": "card border-info",
    "panel-warning": "card border-warning",
    "panel-danger": "card border-danger",
    # Labels → Badges
    "label-default": "bg-default",
    "label-primary": "bg-primary",
    "label-success": "bg-success",
    "label-info": "bg-info",
    "label-warning": "bg-warning",
    "label-danger": "bg-danger",
    "label-transparent": "bg-transparent",
    # Buttons
    "btn-default": "btn-secondary",
    "btn-lg": "btn",
    "btn-xs": "btn-sm",
    # Forms
    "control-label": "col-form-label",
    "form-control-static": "form-control-plaintext",
    "form-group": "mb-10 d-flex justify-content-center (or nb-form-group)",
    "help-block": "form-text",
    "checkbox-inline": "form-check-input",
    # Dropdowns: directional alignment
    "dropdown-menu-left": "dropdown-menu-start",
    "dropdown-menu-right": "dropdown-menu-end",
    # Float / alignment helpers
    "pull-left": "float-start",
    "pull-right": "float-end",
    "center-block": "d-block mx-auto",
    "text-left": "text-start",
    "text-right": "text-end",
    "text-muted": "text-secondary",
    "text-hide": "removed",
    # Accessibility helpers
    "sr-only": "visually-hidden",
    "sr-only-focusable": "visually-hidden-focusable",
    # Images
    "img-responsive": "img-fluid",
    "img-rounded": "rounded",
    "img-circle": "rounded-circle",
    # Visibility helpers → d-* utilities
    "hidden-xs": "d-block d-sm-none",
    "hidden-sm": "d-* responsive utility",
    "hidden-md": "d-* responsive utility",
    "hidden-lg": "d-* responsive utility",
    "visible-xs": "d-none d-sm-block",
    "visible-sm": "d-* responsive utility",
    "visible-md": "d-* responsive utility",
    "visible-lg": "d-* responsive utility",
    "noprint": "d-print-none",
    # Nautobot-specific renames (all gain an ``nb-`` prefix or are removed)
    "accordion-toggle": "nb-collapse-toggle",
    "accordion-toggle-all": "data-nb-toggle",
    "banner-bottom": "nb-banner-bottom",
    "btn-inline": "nb-btn-inline-hover",
    "color-block": "nb-color-block",
    "editor-container": "nb-editor-container",
    "filter-container": "removed",
    "report-stats": "nb-report-stats",
    "right-side-panel": "nb-right-side-panel",
    "software-image-hierarchy": "nb-software-image-hierarchy",
    "style-line": "nb-style-line",
    "table-headings": "nb-table-headings",
    "tile-description": "nb-tile-description",
    "tile-footer": "nb-tile-footer",
    "tile-header": "nb-tile-header",
    "tree-hierarchy": "nb-tree-hierarchy",
}

# Bare words that collide with HTML tags (``<label>``), attributes (``required``,
# ``hidden``), or prose — matched only when used as a CSS class to keep noise low.
BOOTSTRAP3_AMBIGUOUS_CLASSES = {
    # Components renamed/removed in Bootstrap 5
    "panel": "card",
    "well": "card",
    "thumbnail": "card",
    "glyphicon": "mdi mdi-* icon",
    "caret": "mdi mdi-chevron-down",
    "close": "btn-close",
    "checkbox": "form-check",
    "label": "badge",
    "hidden": "d-none",
    "show": "d-block",
    # Nautobot-specific renames
    "tile": "nb-tile",
    "tiles": "nb-tiles",
    "description": "nb-description",
    "required": "nb-required",
    "loading": "nb-loading",
}

# Grid prefixes, data attributes, and jQuery usage — expressed directly as regex.
# Value is ``(regex, replacement)``.
BOOTSTRAP3_REGEX_RULES = {
    # Grid: xs breakpoint removed (mobile-first is now the default)
    "col-xs-*": (r"(?<![\w-])col-xs-\w+", "col-sm-* (xs breakpoint removed)"),
    # Grid: offset syntax change
    "col-*-offset-*": (
        r"(?<![\w-])col-(?:xs|sm|md|lg)-offset-\d+",
        "offset-*-* (or justify-content-center)",
    ),
    # Grid: push/pull replaced by order-* utilities
    "col-*-push/pull-*": (
        r"(?<![\w-])col-(?:xs|sm|md|lg)-(?:push|pull)-\d+",
        "order-* utilities",
    ),
    # jQuery Bootstrap data-attributes gained a ``bs`` namespace
    "data-* (legacy Bootstrap attrs)": (
        r"\bdata-(?:toggle|target|dismiss|backdrop|title)\s*=",
        "data-bs-*",
    ),
    # Bootstrap 5 dropped jQuery; components are vanilla JS now
    "jQuery usage": (
        r"(?<![\w$.])\$\(|\bjQuery\(",
        "vanilla JS (Bootstrap 5 dropped jQuery)",
    ),
}


def _bootstrap_class_token(cls):
    """Regex matching a CSS class as a whole hyphenated token."""
    return r"(?<![\w-])" + re.escape(cls) + r"(?![\w-])"


def _bootstrap_class_in_context(cls):
    """Regex matching a class only inside a ``class="…"`` attribute or CSS ``.selector``.

    Used for ambiguous bare words so they don't match HTML tags, attributes, or
    prose (e.g. ``hidden`` the attribute vs. ``hidden`` the class).
    """
    token = _bootstrap_class_token(cls)
    return r"""class\s*=\s*['"][^'"]*""" + token + r"|\." + token


def _build_bootstrap_migration_rules():
    """Compile the three Bootstrap sub-catalogs into one ``(label, regex, replacement)`` list."""
    rules = []
    for cls, replacement in BOOTSTRAP3_CLASSES.items():
        rules.append((cls, re.compile(_bootstrap_class_token(cls)), replacement))
    for cls, replacement in BOOTSTRAP3_AMBIGUOUS_CLASSES.items():
        rules.append((cls, re.compile(_bootstrap_class_in_context(cls)), replacement))
    for label, (pattern, replacement) in BOOTSTRAP3_REGEX_RULES.items():
        rules.append((label, re.compile(pattern), replacement))
    return rules


# Precompiled once at import: list of ``(label, compiled_regex, replacement)``.
BOOTSTRAP_MIGRATION_RULES = _build_bootstrap_migration_rules()


# ----------------------------------------------------------------------------
# Deprecated *frontend* patterns.
# These regex rules run against the app's HTML templates AND its JS/CSS
# static assets — places the Python-only ``DEPRECATED_CODE_PATTERNS``
# scanner can't reach. Keep entries narrow so they don't blow up on
# incidental text.
# ----------------------------------------------------------------------------
DEPRECATED_FRONTEND_PATTERNS = {
    # --- 2.3: template-block names deprecated (export/import buttons) ---
    "block_export_button": r"\{%\s*block\s+export_button\b",
    "block_import_button": r"\{%\s*block\s+import_button\b",
    # --- 2.4 / 3.1: ``querystring`` tag conflicts with Django 5.1+ ---
    # App templates should move to ``django_querystring`` / ``legacy_querystring``.
    "querystring_tag": r"\{%\s*querystring\b",
    # --- 3.1: front-end libraries being removed ---
    "bootstrap_filestyle": r"bootstrap[-_]filestyle",
    "django_ajax_tables": r"django[-_]ajax[-_]tables",
    # --- 2.3: ``.with_tree_fields`` calls in templates (rare but possible) ---
    "with_tree_fields_tpl": r"\.with_tree_fields\s*\(",
}


# ----------------------------------------------------------------------------
# ContentTypes pointing at models removed in Nautobot 2.0. Features like
# ``CustomField``, ``Relationship``, ``Status``, ``Tag``, ``Webhook``,
# ``CustomLink``, ``ExportTemplate``, ``ComputedField``, ``JobHook``,
# ``JobButton``, and ``Note`` all associate with one or more content types.
# When the underlying ContentType row no longer resolves (because the model
# is gone in 2.x), those associations stay in the database but become dead
# weight — a Webhook attached to ``dcim.site`` silently stops firing, etc.
#
# The audit iterates each feature model, reads its content-type field(s),
# and flags any entry that targets a model in this set. Values are the
# replacement model name purely for the report.
# ----------------------------------------------------------------------------
REMOVED_CONTENT_TYPES = {
    "dcim.site": "dcim.location",
    "dcim.region": "dcim.location",
    "dcim.devicerole": "extras.role",
    "dcim.rackrole": "extras.role",
    "ipam.aggregate": "ipam.prefix",  # with type=Container
    "ipam.role": "extras.role",
}


# Merged view used by the scanner: every (old_path, new_path) entry from all
# three import catalogs, plus removed dependencies mapped to ``None``. Using
# one flat dict lets the scanner emit a single list of findings, each with
# its specific replacement hint when one is known.
ALL_DEPRECATED_IMPORTS = {}
ALL_DEPRECATED_IMPORTS.update(V1_TO_V2_IMPORT_MOVES)
ALL_DEPRECATED_IMPORTS.update(V2_TO_V3_CLASS_REMOVALS)
ALL_DEPRECATED_IMPORTS.update(V1_TO_V2_MODEL_REPLACEMENTS)
for _dep in REMOVED_DEPENDENCIES:
    ALL_DEPRECATED_IMPORTS.setdefault(_dep, None)


# ============================================================================
#                              THE JOB CLASS
# ============================================================================
# The class is a thin orchestrator: ``run()`` calls one method per check
# category and assembles a flat JSON document. Each ``_get_*`` method is
# independent, handles its own errors, and gracefully degrades on any
# Nautobot version.
#
# Section map (matches the module docstring):
#     A  _get_environment / _get_settings_checks
#     B  _get_installed_apps (+ helpers)
#     C  _get_app_compatibility
#     D  _get_registered_jobs (+ _analyze_job_code)
#     E  _get_data_model_inventory (+ per-app helpers)
#     F  _get_integrations
#     G  _get_api_consumers
#     H  _get_dynamic_groups / _get_saved_views / _get_permission_constraints
#        / _get_graphql_queries
#     I  _get_retention_metrics
# ============================================================================


class UpgradeReadinessAssessment(Job):
    """Collect Nautobot environment data for upgrade readiness assessment."""

    name = "Upgrade Readiness Assessment"
    description = (
        "Deep inspection of the Nautobot environment for NTC upgrade assessment. "
        "Analyzes app source code, job complexity, integrations, API consumers, "
        "and inventories objects whose schema changed between major versions. "
        "No device data, credentials, or secrets are included in the output."
    )
    read_only = True

    # ------------------------------------------------------------------
    # Job form inputs
    # ------------------------------------------------------------------
    # ``ChoiceVar`` renders as a Nautobot Job-form dropdown with enforced
    # choices. The selected value is passed into ``run()`` via kwargs and
    # drives the ``compatibility_matrix`` and ``app_compatibility`` checks,
    # as well as which version-specific notes appear in the output.
    target_version = ChoiceVar(
        choices=TARGET_VERSION_CHOICES,
        default=DEFAULT_TARGET_VERSION,
        required=False,
        label="Target Nautobot Version",
        description=(
            "The Nautobot version the customer is upgrading toward. Drives "
            "per-app compatibility gating and the Python/Django matrix check."
        ),
    )

    class Meta:
        name = "Upgrade Readiness Assessment"
        description = (
            "Deep inspection of the Nautobot environment for NTC upgrade assessment."
        )
        has_sensitive_variables = False

    # ------------------------------------------------------------------
    # Logging shim (Nautobot 1.x vs 2.x differ)
    # ------------------------------------------------------------------
    def _emit_log(self, level, msg, *args):
        """Version-agnostic logging.

        Nautobot 2.x exposes ``self.logger`` (a standard :mod:`logging`
        logger). Nautobot 1.x exposes ``self.log_info`` / ``self.log_warning``
        methods that take a single pre-formatted string.

        Do NOT name this ``_log`` — the 1.x base class defines its own
        ``_log`` and our method would shadow it.
        """
        nb_logger = getattr(self, "logger", None)
        if nb_logger is not None and not callable(nb_logger):
            getattr(nb_logger, level)(msg, *args)
            return
        method = getattr(self, f"log_{level}", None) or getattr(self, "log_info", None)
        if method:
            method(msg % args if args else msg)

    # ==================================================================
    # ENTRY POINT
    # ==================================================================

    def run(self, *args, **kwargs):
        """Execute the full assessment and return a structured result.

        The ``*args, **kwargs`` signature accepts both calling conventions:
        Nautobot 1.x calls ``run(data, commit)`` and Nautobot 2.x calls
        ``run()`` with only keyword arguments. On 1.x the form data is the
        first positional argument (a dict); on 2.x each form field is
        delivered as a named kwarg.

        Returns a dict (not a JSON string). Nautobot stores it directly in
        ``JobResult.result``, giving the customer a clean structured
        document rather than the nested escaped-string wrapping that used
        to ship. A pretty-printed JSON copy is also emitted to the log.
        """
        # --- Pull target_version from either 1.x form-data or 2.x kwargs ---
        # 1.x delivers the form as ``data`` (positional); 2.x delivers each
        # field as a named kwarg. Accept both.
        target_version = kwargs.get("target_version")
        if target_version is None and args:
            data = args[0] if isinstance(args[0], dict) else {}
            target_version = data.get("target_version")
        target_version = target_version or DEFAULT_TARGET_VERSION

        results = {
            # Assessment metadata — what target the rest of the report is
            # evaluated against.
            "assessment_metadata": {
                "target_version": target_version,
                "target_version_requirements": TARGET_VERSION_REQUIREMENTS.get(
                    target_version,
                    {"note": "unknown target — verify against release notes"},
                ),
            },
            # Section A — environment & infrastructure
            "environment": self._get_environment(),
            "settings_checks": self._get_settings_checks(),
            "compatibility_matrix": self._get_compatibility_matrix(target_version),
            # Section B — installed apps (runtime introspection + source scan)
            "installed_apps": self._get_installed_apps(),
            # Section C — dependency compatibility gating (per-app Requires-Dist)
            "app_compatibility": self._get_app_compatibility(target_version),
            # Section D — registered + scheduled jobs
            "registered_jobs": self._get_registered_jobs(),
            "scheduled_jobs": self._get_scheduled_jobs(),
            # Section N — Approval Workflow migration readiness (3.0/3.1)
            "job_approval_readiness": self._get_job_approval_readiness(),
            # Section O — JobQueue migration (2.4)
            "task_queue_migration": self._get_task_queue_migration(),
            # Section E — data-model inventory (counts of models that changed)
            "data_model_inventory": self._get_data_model_inventory(),
            # Section P — field-state deltas (single-FK → M2M migrations)
            "field_state_deltas": self._get_field_state_deltas(),
            # Section Q — UI Component Framework impact (2.4 detail-view migrations)
            "ui_component_framework": self._get_ui_component_framework_impact(),
            # Section R — feature rows (CustomField/Webhook/etc.) pinned to removed ContentTypes
            "content_type_feature_usage": self._get_content_type_feature_usage(),
            # Section S — opportunistic read-traffic detection
            "read_traffic_signals": self._get_read_traffic_signals(),
            # Section F — integrations (outbound)
            "integrations": self._get_integrations(),
            # Section G — API consumers (inbound)
            "api_consumers": self._get_api_consumers(),
            # Section H — cross-version feature audits
            "dynamic_groups": self._get_dynamic_groups(),
            "saved_views": self._get_saved_views(),
            "permission_constraints": self._get_permission_constraints(),
            "graphql_queries": self._get_graphql_queries(),
            "deprecated_api_urls": self._get_deprecated_api_urls(),
            # Section I — retention / migration-window planning
            "retention_metrics": self._get_retention_metrics(),
            "migration_audit": self._get_migration_audit(),
            # Section J — run Nautobot's own pre-migration validators
            "pre_migrate_report": self._get_pre_migrate_report(),
        }

        self._emit_log("info", "Assessment data collection complete.")
        # Log a pretty copy so the Job Result page is human-readable even
        # when the customer reads the log pane rather than the structured
        # result pane.
        self._emit_log(
            "info", "Output JSON:\n%s", json.dumps(results, indent=2, default=str)
        )

        # --- Return-value shaping (cross-version) ----------------------
        # Nautobot 2.x+ stores the ``run()`` return value in
        # ``JobResult.result`` as a proper JSONField — returning a dict
        # gives the customer clean structured data.
        #
        # Nautobot 1.x, however, coerces any non-string return via
        # ``str()`` before storing it. That turns a dict into Python repr
        # ({'key': 'value'} with single quotes) which is ugly and not
        # machine-parseable. On 1.x we therefore pre-serialize to a
        # *compact* JSON string (no indent / no newlines) so the outer
        # JobResult wrapper doesn't fill the file with ``\n`` escape
        # sequences. The customer parses the ``output`` string with
        # ``json.loads()`` and gets a clean object.
        version_tuple = _nautobot_version_tuple()
        if version_tuple and version_tuple[0] >= 2:
            return results
        return json.dumps(results, default=str)

    # ==================================================================
    # SECTION A — ENVIRONMENT & INFRASTRUCTURE
    # ==================================================================
    # Establish what we're running on: Nautobot/Python/Django versions, the
    # database backend, and which queue backend is active. This is the
    # foundation against which every other finding is interpreted.
    # ==================================================================

    def _get_environment(self):
        """Collect platform, runtime, and database details.

        Also exposes a parsed version tuple so downstream consumers can
        reason about major-version boundaries without re-parsing the string.
        """
        nautobot_version = "unknown"
        try:
            import nautobot

            nautobot_version = nautobot.__version__
        except ImportError:
            pass

        version_tuple = _nautobot_version_tuple()

        # Django version — helps gate Django-version-specific upgrade paths.
        django_version = "unknown"
        try:
            import django

            django_version = django.get_version()
        except Exception:
            pass

        # Database engine + server version (via a cheap SELECT version()).
        db_settings = settings.DATABASES.get("default", {})
        engine = db_settings.get("ENGINE", "unknown")
        db_version = "unknown"
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT version();")
                db_version = cursor.fetchone()[0]
        except Exception as exc:
            db_version = f"error: {exc}"

        return {
            "nautobot_version": nautobot_version,
            "nautobot_major": version_tuple[0] if version_tuple else None,
            "nautobot_version_tuple": list(version_tuple) if version_tuple else None,
            "python_version": platform.python_version(),
            "django_version": django_version,
            "database_engine": engine,
            "database_version": db_version,
        }

    def _get_settings_checks(self):
        """Flag settings removed or repurposed in newer Nautobot versions.

        We only report the *presence* of removed keys, never their values —
        settings often hold connection strings.

        Also detects which queue backend is active so the NTC team can plan
        Celery adoption (Nautobot 2.x is Celery-only).
        """
        removed_present = [name for name in REMOVED_SETTINGS if hasattr(settings, name)]

        # --- 1.4: STRICT_FILTERING defaults to True. Setting it to False
        # silences unknown-filter errors — great for migration-era
        # compatibility hacks, bad for long-term data integrity. Flag it.
        strict_filtering_disabled = (
            hasattr(settings, "STRICT_FILTERING")
            and getattr(settings, "STRICT_FILTERING") is False
        )

        # --- 1.5: Celery default queue renamed from ``celery`` to ``default``.
        # Deployments whose workers were pinned to the old name (or whose
        # ``CELERY_TASK_DEFAULT_QUEUE`` still explicitly sets ``"celery"``)
        # will silently stop executing jobs after upgrade until queue
        # plumbing is realigned.
        legacy_celery_queue = (
            str(getattr(settings, "CELERY_TASK_DEFAULT_QUEUE", "")) == "celery"
        )

        return {
            "removed_settings_present": removed_present,
            "queue_backend": self._detect_queue_backend(),
            "debug_mode": bool(getattr(settings, "DEBUG", False)),
            "auth_backends": list(getattr(settings, "AUTHENTICATION_BACKENDS", [])),
            "strict_filtering_disabled": strict_filtering_disabled,
            "legacy_celery_default_queue": legacy_celery_queue,
        }

    def _detect_queue_backend(self):
        """Determine whether the instance runs on Celery, RQ, or both.

        Returns one of: ``"celery"``, ``"rq"``, ``"both"``, ``"unknown"``.
        A "both" result means the deployment is mid-migration.
        """
        installed_apps = list(getattr(settings, "INSTALLED_APPS", []))
        has_celery = "django_celery_beat" in installed_apps or bool(
            getattr(settings, "CELERY_BROKER_URL", None)
        )
        has_rq = "django_rq" in installed_apps or bool(
            getattr(settings, "RQ_QUEUES", None)
        )
        if has_celery and has_rq:
            return "both"
        if has_celery:
            return "celery"
        if has_rq:
            return "rq"
        return "unknown"

    # ==================================================================
    # SECTION B — INSTALLED APPS
    # ==================================================================
    # Every Nautobot app installed on this instance is analyzed with two
    # complementary strategies:
    #   1. Runtime introspection (primary) — inspect live Python objects
    #      via Django's app registry, ``inspect``, and ``issubclass``.
    #   2. Source scanning (supplementary) — read installed source files
    #      for patterns that can't be detected at runtime (CSS in templates,
    #      import conventions, deprecated-pattern catalogs, asset counts).
    # ==================================================================

    def _get_installed_apps(self):
        """Inventory every installed Nautobot app with source-code analysis."""
        apps = []
        nautobot_apps = getattr(settings, "PLUGINS", [])
        for app_name in nautobot_apps:
            app_info = self._analyze_app(app_name)
            apps.append(app_info)
            self._emit_log("info", "Analyzed app: %s", app_name)
        return apps

    def _analyze_app(self, app_name):
        """Return a detailed profile of a single Nautobot app."""
        import inspect as _inspect

        info = {
            "name": app_name,
            "version": "unknown",
            "source": "unknown",  # ntc | community | custom
            "runtime": {},  # from live introspection
            "source_scan": {},  # from reading installed files
        }

        # ---- Package metadata -----------------------------------------
        # Apps may be declared with hyphens or underscores; distribution
        # names normally use hyphens. Try the hyphenated form first.
        version, meta = _get_distribution_metadata(app_name.replace("_", "-"))
        if version:
            info["version"] = version
            # Infer source: NTC-authored vs community vs bespoke.
            if "network to code" in meta or "networktocode" in meta:
                info["source"] = "ntc"
            else:
                info["source"] = "community"
        else:
            info["source"] = "custom"

        # ---- Runtime introspection (primary) --------------------------
        info["runtime"] = self._introspect_app(app_name, _inspect)

        # ---- Source file scanning (supplementary) ---------------------
        try:
            mod = importlib.import_module(app_name)
            app_root = pathlib.Path(mod.__file__).parent
            info["source_scan"] = self._scan_app_source(app_root)
        except Exception as exc:
            info["source_scan"] = {"error": f"unable to locate source: {exc}"}

        return info

    # ------------------------------------------------------------------
    # Runtime introspection — inspect live objects in memory
    # ------------------------------------------------------------------

    def _introspect_app(self, app_name, _inspect):
        """Inspect a running app via Django registries and Python introspection."""
        return {
            "models": self._introspect_models(app_name),
            "views": self._introspect_views(app_name, _inspect),
            "api_endpoints": self._introspect_api(app_name, _inspect),
            "filtersets": self._introspect_filtersets(app_name, _inspect),
            "template_extensions": self._introspect_template_extensions(app_name),
            "nav_items": self._introspect_nav(app_name),
        }

    def _introspect_models(self, app_name):
        """Use Django's app registry to enumerate models owned by this app."""
        from django.apps import apps as django_apps

        models = []
        try:
            app_config = django_apps.get_app_config(app_name.split(".")[-1])
            for model in app_config.get_models():
                model_info = {
                    "name": model.__name__,
                    "db_table": model._meta.db_table,
                    "field_count": len(model._meta.get_fields()),
                    "fields": {},
                }
                # Capture ForeignKey / M2M targets — lets NTC see whether the
                # model points at removed models like dcim.Site.
                for field in model._meta.get_fields():
                    if hasattr(field, "related_model") and field.related_model:
                        target = (
                            f"{field.related_model._meta.app_label}."
                            f"{field.related_model.__name__}"
                        )
                        model_info["fields"][field.name] = {
                            "type": type(field).__name__,
                            "target": target,
                        }
                models.append(model_info)
        except LookupError:
            pass  # App may use a different label than its module name
        except Exception as exc:
            return {"error": str(exc)}

        return {"count": len(models), "models": models}

    def _introspect_views(self, app_name, _inspect):
        """Inspect view classes to see how close the app is to UIViewSet adoption.

        Classifies every ``View`` subclass defined in ``<app>.views`` into
        one of three buckets: NautobotUIViewSet (modern), legacy Nautobot
        view classes (needs migration), or generic Django view classes
        (which also require review).
        """
        views_info = {
            "uiviewset_classes": [],
            "legacy_view_classes": [],
            "other_view_classes": [],
            "url_pattern_count": 0,
        }

        # Resolve the modern UIViewSet base class (only present on 2.x+).
        uiviewset_base = None
        try:
            from nautobot.apps.views import NautobotUIViewSet

            uiviewset_base = NautobotUIViewSet
        except ImportError:
            pass

        # Resolve the classic Nautobot view bases — any subclass of these
        # should be migrated to NautobotUIViewSet.
        legacy_bases = []
        for cls_name in [
            "ObjectView",
            "ObjectListView",
            "ObjectEditView",
            "ObjectDeleteView",
            "ObjectBulkEditView",
            "ObjectBulkDeleteView",
            "ObjectBulkImportView",
            "ObjectChangeLogView",
            "ObjectNotesView",
        ]:
            try:
                mod = importlib.import_module("nautobot.apps.views")
                cls = getattr(mod, cls_name, None)
                if cls:
                    legacy_bases.append(cls)
            except ImportError:
                pass

        try:
            views_mod = importlib.import_module(f"{app_name}.views")
            for name, obj in _inspect.getmembers(views_mod, _inspect.isclass):
                # Skip classes imported into the views module but not defined there.
                if not obj.__module__.startswith(app_name):
                    continue
                if uiviewset_base and issubclass(obj, uiviewset_base):
                    views_info["uiviewset_classes"].append(name)
                elif any(issubclass(obj, lb) for lb in legacy_bases if lb):
                    views_info["legacy_view_classes"].append(name)
                else:
                    try:
                        from django.views import View

                        if issubclass(obj, View):
                            views_info["other_view_classes"].append(name)
                    except ImportError:
                        pass
        except (ImportError, ModuleNotFoundError):
            pass

        # Count registered URL patterns that mention this app.
        try:
            from django.urls import URLResolver, URLPattern
            from nautobot.core.urls import urlpatterns as root_patterns

            def _count_patterns(patterns, prefix=""):
                count = 0
                for p in patterns:
                    full = prefix + str(getattr(p, "pattern", ""))
                    if isinstance(p, URLResolver):
                        count += _count_patterns(p.url_patterns, full)
                    elif isinstance(p, URLPattern):
                        if app_name.replace("_", "-") in full or app_name in full:
                            count += 1
                return count

            views_info["url_pattern_count"] = _count_patterns(root_patterns)
        except Exception:
            pass

        views_info["uses_uiviewsets"] = bool(views_info["uiviewset_classes"])
        views_info["views_needing_migration"] = len(
            views_info["legacy_view_classes"]
        ) + len(views_info["other_view_classes"])
        return views_info

    def _introspect_api(self, app_name, _inspect):
        """Inspect API serializer and viewset classes at runtime."""
        api_info = {"serializers": [], "viewsets": []}

        # REST Framework Serializers declared by the app.
        try:
            api_ser_mod = importlib.import_module(f"{app_name}.api.serializers")
            from rest_framework.serializers import Serializer

            for name, obj in _inspect.getmembers(api_ser_mod, _inspect.isclass):
                if obj.__module__.startswith(app_name) and issubclass(obj, Serializer):
                    api_info["serializers"].append(name)
        except (ImportError, ModuleNotFoundError):
            pass

        # REST Framework ViewSets declared by the app.
        try:
            api_views_mod = importlib.import_module(f"{app_name}.api.views")
            from rest_framework.viewsets import ViewSetMixin

            for name, obj in _inspect.getmembers(api_views_mod, _inspect.isclass):
                if obj.__module__.startswith(app_name) and issubclass(
                    obj, ViewSetMixin
                ):
                    api_info["viewsets"].append(name)
        except (ImportError, ModuleNotFoundError):
            pass

        return api_info

    def _introspect_filtersets(self, app_name, _inspect):
        """Inspect FilterSet classes at runtime, capturing declared filters."""
        filtersets = []
        try:
            filters_mod = importlib.import_module(f"{app_name}.filters")
            from django_filters import FilterSet

            for name, obj in _inspect.getmembers(filters_mod, _inspect.isclass):
                if obj.__module__.startswith(app_name) and issubclass(obj, FilterSet):
                    declared = (
                        list(obj.declared_filters.keys())
                        if hasattr(obj, "declared_filters")
                        else []
                    )
                    filtersets.append(
                        {
                            "name": name,
                            "declared_filter_count": len(declared),
                            "declared_filters": declared,
                        }
                    )
        except (ImportError, ModuleNotFoundError):
            pass
        except Exception:
            pass
        return {"count": len(filtersets), "filtersets": filtersets}

    def _introspect_template_extensions(self, app_name):
        """Check for ``template_content.py`` (banner / panel / tab hooks)."""
        try:
            mod = importlib.import_module(f"{app_name}.template_content")
            import inspect as _inspect

            extensions = [
                name
                for name, obj in _inspect.getmembers(mod, _inspect.isclass)
                if obj.__module__.startswith(app_name)
            ]
            return {"has_template_extensions": True, "classes": extensions}
        except (ImportError, ModuleNotFoundError):
            return {"has_template_extensions": False}

    def _introspect_nav(self, app_name):
        """Detect navbar menu entries exposed by the app."""
        try:
            mod = importlib.import_module(f"{app_name}.navigation")
            items = getattr(mod, "menu_items", None) or getattr(mod, "nav_menu", None)
            return {"has_navigation": items is not None}
        except (ImportError, ModuleNotFoundError):
            return {"has_navigation": False}

    # ------------------------------------------------------------------
    # Source file scanning — supplements runtime introspection where it
    # can't reach (templates, static assets, import style, deprecated
    # string patterns in source).
    # ------------------------------------------------------------------

    def _scan_app_source(self, app_root):
        """Read installed source files for patterns invisible to runtime."""
        scan = {
            "size": {},
            "import_conventions": {},
            "deprecated_patterns": {},
            "templates": {},
            "static_assets": {},
            "html_in_python": [],
            "html_in_python_bootstrap_issues": {},
        }

        # Exclude this file itself so the deprecated-pattern catalogs above
        # don't get matched against their own string literals.
        py_files = [
            p for p in app_root.rglob("*.py") if p.resolve() != _SELF_SOURCE_FILE
        ]
        html_files = list(app_root.rglob("*.html"))
        js_files = list(app_root.rglob("*.js"))
        css_files = list(app_root.rglob("*.css"))

        # Read every Python file once and cache the content — the scanner
        # passes the dict to several downstream helpers.
        all_py_content = {}
        total_lines = 0
        for pf in py_files:
            try:
                content = pf.read_text(errors="replace")
                all_py_content[str(pf.relative_to(app_root))] = content
                total_lines += len(content.splitlines())
            except Exception:
                pass

        scan["size"] = {
            "python_files": len(py_files),
            "python_lines": total_lines,
            "template_files": len(html_files),
            "javascript_files": len(js_files),
            "css_files": len(css_files),
        }

        scan["import_conventions"] = self._check_import_conventions(all_py_content)
        scan["deprecated_patterns"] = self._scan_deprecated_patterns(all_py_content)

        # HTML embedded in Python source files (tables, etc.) often needs
        # migration when Bootstrap changes — flag the file and run the same
        # Bootstrap catalog against its contents.
        for path, content in all_py_content.items():
            if re.search(
                r"<(?:div|span|table|tr|td|th|a|button|form|input)\b", content
            ):
                scan["html_in_python"].append(path)
                bootstrap_hits = self._scan_bootstrap_content(content)
                if bootstrap_hits:
                    scan["html_in_python_bootstrap_issues"][path] = bootstrap_hits

        scan["templates"] = self._analyze_templates(app_root, html_files)

        scan["static_assets"] = {
            "javascript_files": [str(f.relative_to(app_root)) for f in js_files],
            "css_files": [str(f.relative_to(app_root)) for f in css_files],
            "total_js_lines": sum(
                len(f.read_text(errors="replace").splitlines())
                for f in js_files
                if f.stat().st_size < 500_000  # skip vendored bundles
            ),
            # Run the same deprecated-frontend-pattern catalog against JS/CSS
            # files — ``bootstrap-filestyle`` and ``django-ajax-tables``
            # typically appear as CSS classes or script tags here.
            "frontend_pattern_hits": self._scan_frontend_static(
                app_root, js_files + css_files
            ),
            # Bootstrap 3 → 5 classes/attributes/jQuery can also live in JS/CSS
            # (e.g. ``classList.add("panel")`` or ``.panel { … }``).
            "bootstrap_hits": self._scan_files_for_bootstrap(
                app_root, js_files + css_files
            ),
        }
        return scan

    def _scan_frontend_static(self, app_root, files):
        """Apply DEPRECATED_FRONTEND_PATTERNS to JS/CSS files.

        Skips vendored bundles (files >500 KB) to keep the scan fast and
        avoid accidental matches inside minified blobs.
        """
        hits: dict = {}
        for f in files:
            try:
                if f.stat().st_size >= 500_000:
                    continue
                content = f.read_text(errors="replace")
            except Exception:
                continue
            file_hits = []
            for name, pattern in DEPRECATED_FRONTEND_PATTERNS.items():
                matches = re.findall(pattern, content)
                if matches:
                    file_hits.append({"pattern": name, "occurrences": len(matches)})
            if file_hits:
                hits[str(f.relative_to(app_root))] = file_hits
        return hits

    def _scan_bootstrap_content(self, content):
        """Match the Bootstrap 3 → 5 migration catalog against a blob of text.

        Returns ``[{"pattern", "occurrences", "replacement"}, ...]``. Shared by
        the template, JS/CSS, and HTML-in-Python scanners so all three surface
        the same findings (and the same inline replacement hints).
        """
        hits = []
        for label, regex, replacement in BOOTSTRAP_MIGRATION_RULES:
            count = len(regex.findall(content))
            if count:
                hits.append(
                    {
                        "pattern": label,
                        "occurrences": count,
                        "replacement": replacement,
                    }
                )
        return hits

    def _scan_files_for_bootstrap(self, app_root, files):
        """Apply the Bootstrap 3 → 5 catalog to JS/CSS files.

        Skips vendored bundles (files >500 KB), mirroring
        :meth:`_scan_frontend_static`.
        """
        hits: dict = {}
        for f in files:
            try:
                if f.stat().st_size >= 500_000:
                    continue
                content = f.read_text(errors="replace")
            except Exception:
                continue
            file_hits = self._scan_bootstrap_content(content)
            if file_hits:
                hits[str(f.relative_to(app_root))] = file_hits
        return hits

    def _check_import_conventions(self, py_files):
        """Check whether the app follows the recommended ``nautobot.apps.*`` convention."""
        all_content = "\n".join(py_files.values())

        # ``nautobot.apps.*`` is the blessed public API for apps and jobs.
        apps_imports = len(re.findall(r"from nautobot\.apps\.", all_content))
        # ``nautobot.core.*`` works but is not the recommended convention.
        core_imports = len(re.findall(r"from nautobot\.core\.", all_content))
        # ``nautobot.utilities.*`` is fully removed in v2+.
        utilities_imports = len(re.findall(r"from nautobot\.utilities\.", all_content))
        # Direct model imports are fragile — they bypass the public API.
        direct_model_imports = len(
            re.findall(
                r"from nautobot\.(?:dcim|ipam|extras|circuits|tenancy|virtualization)\.",
                all_content,
            )
        )

        return {
            "nautobot_apps_imports": apps_imports,
            "nautobot_core_imports": core_imports,
            "nautobot_utilities_imports": utilities_imports,
            "direct_model_imports": direct_model_imports,
            "uses_recommended_convention": apps_imports > 0 and utilities_imports == 0,
        }

    def _scan_deprecated_patterns(self, py_files):
        """Scan all Python files for deprecated imports and code patterns.

        Uses :func:`_count_import_occurrences` (anchored regex against real
        ``import``/``from`` statements) instead of substring matching, which
        keeps false-positive noise low. Each finding is tagged with its
        known replacement so reviewers get a migration hint inline.
        """
        results = {"deprecated_imports": [], "deprecated_code": {}}

        # --- Deprecated imports (from the combined catalog) ------------
        for old_path, new_path in ALL_DEPRECATED_IMPORTS.items():
            per_file = []  # [(relpath, n_occurrences), ...]
            for relpath, content in py_files.items():
                n = _count_import_occurrences(content, old_path)
                if n:
                    per_file.append((relpath, n))
            if not per_file:
                continue
            results["deprecated_imports"].append(
                {
                    "import": old_path,
                    "replacement": new_path,
                    "file_count": len(per_file),
                    "total_occurrences": sum(n for _, n in per_file),
                    "files": [relpath for relpath, _ in per_file],
                }
            )

        # --- Deprecated code patterns (regex) --------------------------
        all_content = "\n".join(py_files.values())
        for pattern_name, pattern in DEPRECATED_CODE_PATTERNS.items():
            total = len(re.findall(pattern, all_content))
            if not total:
                continue
            files_with = [
                relpath
                for relpath, content in py_files.items()
                if re.search(pattern, content)
            ]
            results["deprecated_code"][pattern_name] = {
                "match_count": total,
                "file_count": len(files_with),
                "files": files_with,
            }
        return results

    def _analyze_templates(self, app_root, html_files):
        """Analyze HTML templates for Bootstrap 3 and deprecated-frontend patterns."""
        template_analysis: dict = {
            "template_count": len(html_files),
            "template_files": [str(f.relative_to(app_root)) for f in html_files],
            "bootstrap3_issues": {},
            "frontend_pattern_hits": {},  # matches from DEPRECATED_FRONTEND_PATTERNS
            "templates_needing_migration": [],
            "total_template_lines": 0,
        }

        for tf in html_files:
            try:
                content = tf.read_text(errors="replace")
                template_analysis["total_template_lines"] += len(content.splitlines())
                rel_path = str(tf.relative_to(app_root))

                issues_in_file = self._scan_bootstrap_content(content)

                # Additional regex: breadcrumb <li> missing breadcrumb-item.
                if re.search(
                    r"<li(?![^>]*breadcrumb-item)[^>]*>.*</li>\s*<!--.*breadcrumb",
                    content,
                ):
                    issues_in_file.append(
                        {
                            "pattern": "breadcrumb <li> missing breadcrumb-item class",
                            "occurrences": 1,
                        }
                    )

                if issues_in_file:
                    template_analysis["bootstrap3_issues"][rel_path] = issues_in_file
                    template_analysis["templates_needing_migration"].append(rel_path)

                # Deprecated-frontend regex catalog (querystring tag, block
                # names, filestyle refs, etc.). Anything matching here also
                # counts as "needs migration" even without Bootstrap 3 hits.
                fe_hits = []
                for name, pattern in DEPRECATED_FRONTEND_PATTERNS.items():
                    matches = re.findall(pattern, content)
                    if matches:
                        fe_hits.append({"pattern": name, "occurrences": len(matches)})
                if fe_hits:
                    template_analysis["frontend_pattern_hits"][rel_path] = fe_hits
                    if rel_path not in template_analysis["templates_needing_migration"]:
                        template_analysis["templates_needing_migration"].append(
                            rel_path
                        )
            except Exception:
                pass

        template_analysis["templates_needing_migration_count"] = len(
            template_analysis["templates_needing_migration"]
        )
        return template_analysis

    # ==================================================================
    # SECTION C — APP COMPATIBILITY GATING
    # ==================================================================
    # For each installed app, read the package metadata ``Requires-Dist``
    # entries and surface the declared Nautobot version range. If an app
    # says ``nautobot>=1.5,<2.0`` it's actively blocking a 2.x upgrade
    # until it ships a 2.x-compatible release.
    # ==================================================================

    def _get_app_compatibility(self, target_version):
        """Per-app Nautobot version constraints from package metadata.

        For each installed app:
          * ``nautobot_requirements`` — the raw ``Requires-Dist`` entries
            that mention Nautobot.
          * ``blocks_upgrade_to_v2`` / ``blocks_upgrade_to_v3`` — whether
            any declared upper bound excludes the earliest v2 / v3 release.
            A ``<2.0.0`` pin sets both flags; a ``<3.0.0`` pin sets only v3.
          * ``blocks_target_version`` — whether any declared upper bound
            excludes the specific target chosen on the form.
          * ``all_requirements`` — every ``Requires-Dist`` entry so
            transitive compat issues (e.g. a pinned ``django-rq``) surface.
        """
        # Parse the target once so each app comparison is cheap.
        target_parts = _parse_version_string(target_version)

        apps_info = []
        for app_name in getattr(settings, "PLUGINS", []):
            dist_name = app_name.replace("_", "-")
            requires = _get_requires_dist(dist_name)

            # Keep only requirements that name Nautobot itself.
            nautobot_reqs = [
                r for r in requires if re.match(r"^\s*nautobot\b", r, re.IGNORECASE)
            ]

            # Parse every declared upper bound once so the v2 / v3 / target
            # checks all use the same version-aware comparison. A pin like
            # ``nautobot<2.4`` yields upper = (2, 4), which excludes v2.4 and
            # everything above — including all of v3.
            upper_bounds = []
            for req in nautobot_reqs:
                match = re.search(r"<\s*(\d+)(?:\.(\d+))?", req)
                if match:
                    upper_bounds.append((int(match.group(1)), int(match.group(2) or 0)))

            def _excluded_by_any_upper(version):
                return any(version >= ub for ub in upper_bounds)

            # An app blocks upgrade to a given release line when any declared
            # upper bound excludes its earliest release. ``<2.0.0`` blocks
            # both v2 and v3; ``<2.4`` blocks v3 but still allows v2.0-v2.3.
            blocks_v2 = _excluded_by_any_upper((2, 0))
            blocks_v3 = _excluded_by_any_upper((3, 0))
            blocks_target = bool(target_parts) and _excluded_by_any_upper(target_parts)

            apps_info.append(
                {
                    "name": app_name,
                    "distribution": dist_name,
                    "nautobot_requirements": nautobot_reqs,
                    "blocks_upgrade_to_v2": blocks_v2,
                    "blocks_upgrade_to_v3": blocks_v3,
                    "blocks_target_version": blocks_target,
                    "all_requirements": requires,
                }
            )
        return apps_info

    # ==================================================================
    # SECTION D — REGISTERED JOBS
    # ==================================================================
    # Enumerate every Nautobot Job (from apps or local modules), capture
    # its metadata, and run the deprecated-pattern catalog against its
    # source file. The assessment Job itself is skipped to avoid matching
    # its own pattern strings.
    # ==================================================================

    def _get_registered_jobs(self):
        """Inventory all registered Nautobot Jobs with per-job code analysis."""
        from nautobot.extras.models import Job as JobModel

        jobs = []
        # Precompute this job's identity so we can skip it in the loop.
        self_module = type(self).__module__
        self_class = type(self).__name__

        try:
            for job in JobModel.objects.all():
                # Skip self — its source contains every deprecated pattern
                # we look for (as string literals).
                if job.module_name == self_module and job.job_class_name == self_class:
                    continue

                job_info = {
                    "name": job.name,
                    "module_name": job.module_name,
                    "job_class_name": job.job_class_name,
                    "installed": job.installed,
                    "enabled": job.enabled,
                    "source": "unknown",
                    "code_analysis": {},
                }

                # ``approval_required`` exists on Nautobot 2.x Job rows but
                # is being deprecated — surface its value where available.
                if hasattr(job, "approval_required"):
                    job_info["uses_approval_required"] = job.approval_required

                # Classify source: core, app-provided, or local file.
                module = job.module_name or ""
                if module.startswith("nautobot."):
                    job_info["source"] = "nautobot_core"
                elif any(
                    module.startswith(app) for app in getattr(settings, "PLUGINS", [])
                ):
                    job_info["source"] = "app"
                else:
                    job_info["source"] = "local"

                job_info["code_analysis"] = self._analyze_job_code(job)
                jobs.append(job_info)
        except Exception as exc:
            self._emit_log("warning", "Could not enumerate jobs: %s", exc)

        return jobs

    def _analyze_job_code(self, job):
        """Inspect a Job's source file for deprecated patterns and size.

        Runs both the import catalog and the regex pattern catalog against
        the Job's own Python file so the per-job report mirrors the per-app
        scan.
        """
        try:
            module = importlib.import_module(job.module_name)
            source_file = getattr(module, "__file__", None)
            if not source_file:
                return {"error": "no source file"}

            # Same self-skip safeguard — if a Job's source file happens to
            # match this script, it produces catalog-poisoned findings.
            if pathlib.Path(source_file).resolve() == _SELF_SOURCE_FILE:
                return {"skipped": "source is the assessment Job itself"}

            content = pathlib.Path(source_file).read_text(errors="replace")
            lines = len(content.splitlines())

            deprecated = []
            # Import-based deprecations (anchored to real imports).
            for imp, replacement in ALL_DEPRECATED_IMPORTS.items():
                if _count_import_occurrences(content, imp):
                    deprecated.append({"import": imp, "replacement": replacement})
            # Regex-based code deprecations.
            pattern_hits = []
            for pattern_name, pattern in DEPRECATED_CODE_PATTERNS.items():
                if re.search(pattern, content):
                    pattern_hits.append(pattern_name)

            return {
                "source_file": source_file,
                "line_count": lines,
                "deprecated_imports": deprecated,
                "deprecated_patterns": pattern_hits,
                "deprecated_total": len(deprecated) + len(pattern_hits),
            }
        except Exception as exc:
            return {"error": f"unable to analyze: {exc}"}

    # ==================================================================
    # SECTION E — DATA-MODEL INVENTORY
    # ==================================================================
    # The single biggest chunk of 1.x → 2.x effort is data migration — the
    # counts below let NTC size the migration work concretely.
    #
    # Convention: ``None`` means the model doesn't exist on this Nautobot
    # version (removed or not yet introduced); ``0`` means the model exists
    # but is empty.
    # ==================================================================

    def _get_data_model_inventory(self):
        """Counts of objects in models that change across major versions."""
        return {
            "dcim": self._inventory_dcim(),
            "ipam": self._inventory_ipam(),
            "extras": self._inventory_extras(),
            "tenancy": self._inventory_tenancy(),
            "circuits": self._inventory_circuits(),
            "virtualization": self._inventory_virtualization(),
        }

    def _inventory_dcim(self):
        """DCIM object counts, covering both 1.x and 2.x+ schemas."""
        return {
            # --- Removed in 2.0 (migrated into Location) ---
            "site_count": _safe_count("dcim", "Site"),
            "region_count": _safe_count("dcim", "Region"),
            # --- Added in 2.0 ---
            "location_count": _safe_count("dcim", "Location"),
            "location_type_count": _safe_count("dcim", "LocationType"),
            # --- Removed in 2.0 (migrated into extras.Role) ---
            "device_role_count": _safe_count("dcim", "DeviceRole"),
            "rack_role_count": _safe_count("dcim", "RackRole"),
            # --- Unchanged across versions ---
            "device_count": _safe_count("dcim", "Device"),
            "device_type_count": _safe_count("dcim", "DeviceType"),
            "manufacturer_count": _safe_count("dcim", "Manufacturer"),
            "platform_count": _safe_count("dcim", "Platform"),
            "rack_count": _safe_count("dcim", "Rack"),
            "rack_group_count": _safe_count("dcim", "RackGroup"),
            "interface_count": _safe_count("dcim", "Interface"),
            "cable_count": _safe_count("dcim", "Cable"),
            "power_panel_count": _safe_count("dcim", "PowerPanel"),
            "power_feed_count": _safe_count("dcim", "PowerFeed"),
            "virtual_chassis_count": _safe_count("dcim", "VirtualChassis"),
            # --- Added in 1.5 (DeviceRedundancyGroup) / 1.6 (InterfaceRedundancyGroup) ---
            # Counts here are ``None`` on older instances where the model
            # didn't exist yet.
            "device_redundancy_group_count": _safe_count(
                "dcim", "DeviceRedundancyGroup"
            ),
            "interface_redundancy_group_count": _safe_count(
                "dcim", "InterfaceRedundancyGroup"
            ),
        }

    def _inventory_ipam(self):
        """IPAM object counts.

        The IPAM schema was overhauled in 2.0 (Namespace introduced, Prefix
        gained a ``type`` field and self-parent FK, IPAddress.parent is
        mandatory), so we capture counts that directly drive the migration
        plan.
        """
        # Typed as plain ``dict`` (not narrowed) so we can layer in per-type
        # breakdown dicts and error strings alongside the integer counts.
        out: dict = {
            # --- Removed in 2.0 (migrated into Prefix with type='Container') ---
            "aggregate_count": _safe_count("ipam", "Aggregate"),
            # --- Added in 2.0 ---
            "namespace_count": _safe_count("ipam", "Namespace"),
            # --- Unchanged names, but schema shifted ---
            "prefix_count": _safe_count("ipam", "Prefix"),
            "ip_address_count": _safe_count("ipam", "IPAddress"),
            "vlan_count": _safe_count("ipam", "VLAN"),
            "vlan_group_count": _safe_count("ipam", "VLANGroup"),
            "vrf_count": _safe_count("ipam", "VRF"),
            "route_target_count": _safe_count("ipam", "RouteTarget"),
            "service_count": _safe_count("ipam", "Service"),
            # --- Removed in 2.0 (migrated into extras.Role) ---
            "ipam_role_count": _safe_count("ipam", "Role"),
        }

        # Prefix type breakdown — only meaningful on 2.x+ where the Prefix
        # model has a ``type`` field. On 1.x, Prefix has ``is_pool`` (bool).
        prefix_model = _safe_get_model("ipam", "Prefix")
        if prefix_model is not None:
            fields = {f.name for f in prefix_model._meta.get_fields()}
            if "type" in fields:
                try:
                    breakdown = {}
                    for row in prefix_model.objects.values("type"):
                        key = row["type"] or "unset"
                        breakdown[key] = breakdown.get(key, 0) + 1
                    out["prefix_type_breakdown"] = breakdown
                except Exception as exc:
                    out["prefix_type_breakdown_error"] = str(exc)
            if "is_pool" in fields:
                try:
                    out["prefix_is_pool_count"] = prefix_model.objects.filter(
                        is_pool=True
                    ).count()
                except Exception as exc:
                    out["prefix_is_pool_error"] = str(exc)

        # IPAddress.assigned_object exists on 1.x; count IPs bound to an
        # interface so we know how many IPAddressToInterface rows will be
        # created during the migration.
        ip_model = _safe_get_model("ipam", "IPAddress")
        if ip_model is not None:
            ip_fields = {f.name for f in ip_model._meta.get_fields()}
            if "assigned_object_id" in ip_fields:
                try:
                    out["ip_with_assigned_object"] = ip_model.objects.exclude(
                        assigned_object_id=None
                    ).count()
                except Exception as exc:
                    out["ip_with_assigned_object_error"] = str(exc)

        # ---------- NAMESPACE MIGRATION FORECAST ----------
        # The single largest 1.x → 2.x pain point we've seen in the field
        # is the introduction of ``ipam.Namespace``. On 1.x, prefix/VRF
        # uniqueness was governed by ``VRF.enforce_unique`` and the global
        # ``ENFORCE_GLOBAL_UNIQUE`` setting. The 2.x migration maps each
        # VRF with ``enforce_unique=True`` into its own Namespace, moves
        # non-VRF prefixes into the default "Global" Namespace, and shunts
        # anything that would create a duplicate into a "Cleanup
        # Namespace". Big counts here = lots of post-upgrade cleanup work.
        out["namespace_migration"] = self._forecast_namespace_migration()

        return out

    def _forecast_namespace_migration(self):
        """Estimate the scope of the 1.x → 2.x Namespace migration.

        Returns a dict describing the current IPAM layout in terms of
        future Namespaces. On 1.x this is a forecast; on 2.x+ it reports
        the actual per-Namespace distribution.
        """
        forecast: dict = {}

        vrf_model = _safe_get_model("ipam", "VRF")
        prefix_model = _safe_get_model("ipam", "Prefix")
        ip_model = _safe_get_model("ipam", "IPAddress")
        namespace_model = _safe_get_model("ipam", "Namespace")

        # --- 1.x VRF posture ---------------------------------------------
        # Each VRF with enforce_unique=True becomes a dedicated Namespace
        # on 2.x, so the count is a direct "new Namespace" prediction.
        if vrf_model is not None:
            vrf_fields = {f.name for f in vrf_model._meta.get_fields()}
            if "enforce_unique" in vrf_fields:
                try:
                    forecast["vrfs_with_enforce_unique"] = vrf_model.objects.filter(
                        enforce_unique=True
                    ).count()
                    forecast["vrfs_without_enforce_unique"] = vrf_model.objects.filter(
                        enforce_unique=False
                    ).count()
                except Exception as exc:
                    forecast["vrf_enforce_unique_error"] = str(exc)

        # --- Prefix distribution -----------------------------------------
        # 1.x: group by VRF to predict Namespace membership.
        # 2.x: group by actual Namespace (truth on the ground).
        if prefix_model is not None:
            pfx_fields = {f.name for f in prefix_model._meta.get_fields()}
            if "namespace" in pfx_fields:
                # 2.x schema — group by real namespace name.
                try:
                    dist: dict = {}
                    for row in prefix_model.objects.values("namespace__name"):
                        key = row.get("namespace__name") or "(none)"
                        dist[key] = dist.get(key, 0) + 1
                    forecast["prefixes_by_namespace"] = dist
                except Exception as exc:
                    forecast["prefixes_by_namespace_error"] = str(exc)
            elif "vrf" in pfx_fields:
                # 1.x schema — forecast.
                try:
                    forecast["prefixes_without_vrf_default_global_ns"] = (
                        prefix_model.objects.filter(vrf__isnull=True).count()
                    )
                    forecast["prefixes_with_vrf"] = prefix_model.objects.exclude(
                        vrf__isnull=True
                    ).count()
                except Exception as exc:
                    forecast["prefix_vrf_distribution_error"] = str(exc)

                # Duplicate-prefix detection. Two prefixes with the same
                # CIDR+VRF land in the Cleanup Namespace on 2.x, which is
                # what usually bites people. Count pairs rather than
                # enumerating them (enumeration could be large).
                try:
                    seen: dict = {}
                    for row in prefix_model.objects.values("prefix", "vrf_id"):
                        key = (str(row.get("prefix")), row.get("vrf_id"))
                        seen[key] = seen.get(key, 0) + 1
                    dup_count = sum(n - 1 for n in seen.values() if n > 1)
                    forecast["duplicate_prefix_candidates"] = dup_count
                except Exception as exc:
                    forecast["duplicate_prefix_error"] = str(exc)

        # --- IPAddress distribution --------------------------------------
        if ip_model is not None:
            ip_fields = {f.name for f in ip_model._meta.get_fields()}
            if "parent" in ip_fields:
                # 2.x — each IP has a Namespace via its parent Prefix.
                try:
                    dist = {}
                    for row in ip_model.objects.values("parent__namespace__name"):
                        key = row.get("parent__namespace__name") or "(none)"
                        dist[key] = dist.get(key, 0) + 1
                    forecast["ips_by_namespace"] = dist
                except Exception as exc:
                    forecast["ips_by_namespace_error"] = str(exc)
            elif "vrf" in ip_fields:
                # 1.x — group by VRF (predicts future namespace).
                try:
                    forecast["ips_without_vrf_default_global_ns"] = (
                        ip_model.objects.filter(vrf__isnull=True).count()
                    )
                    forecast["ips_with_vrf"] = ip_model.objects.exclude(
                        vrf__isnull=True
                    ).count()
                except Exception as exc:
                    forecast["ip_vrf_distribution_error"] = str(exc)

                # Duplicate (address, vrf) pairs end up in the Cleanup
                # Namespace — same rule as for Prefixes.
                try:
                    seen = {}
                    for row in ip_model.objects.values("address", "vrf_id"):
                        key = (str(row.get("address")), row.get("vrf_id"))
                        seen[key] = seen.get(key, 0) + 1
                    dup_count = sum(n - 1 for n in seen.values() if n > 1)
                    forecast["duplicate_ip_candidates"] = dup_count
                except Exception as exc:
                    forecast["duplicate_ip_error"] = str(exc)

        # --- Existing Namespace rows (2.x only) --------------------------
        if namespace_model is not None:
            try:
                forecast["existing_namespaces"] = list(
                    namespace_model.objects.values_list("name", flat=True)
                )
            except Exception as exc:
                forecast["existing_namespaces_error"] = str(exc)

        return forecast

    def _inventory_extras(self):
        """Extras object counts, including the new unified Role model."""
        # Typed as plain ``dict`` so we can mix integer counts with
        # breakdown dicts (e.g. custom-field type histogram).
        out: dict = {
            # --- 2.0+: consolidated Role model ---
            "role_count": _safe_count("extras", "Role"),
            # --- Unchanged ---
            "status_count": _safe_count("extras", "Status"),
            "tag_count": _safe_count("extras", "Tag"),
            "custom_field_count": _safe_count("extras", "CustomField"),
            "custom_field_choice_count": _safe_count("extras", "CustomFieldChoice"),
            "relationship_count": _safe_count("extras", "Relationship"),
            "relationship_association_count": _safe_count(
                "extras", "RelationshipAssociation"
            ),
            "config_context_count": _safe_count("extras", "ConfigContext"),
            "config_context_schema_count": _safe_count("extras", "ConfigContextSchema"),
            "custom_link_count": _safe_count("extras", "CustomLink"),
            "export_template_count": _safe_count("extras", "ExportTemplate"),
            "graphql_query_count": _safe_count("extras", "GraphQLQuery"),
            "webhook_count": _safe_count("extras", "Webhook"),
            "job_count": _safe_count("extras", "Job"),
            "scheduled_job_count": _safe_count("extras", "ScheduledJob"),
            "job_hook_count": _safe_count("extras", "JobHook"),
            "job_button_count": _safe_count("extras", "JobButton"),
            "git_repository_count": _safe_count("extras", "GitRepository"),
            "secrets_group_count": _safe_count("extras", "SecretsGroup"),
            "note_count": _safe_count("extras", "Note"),
            "dynamic_group_count": _safe_count("extras", "DynamicGroup"),
        }

        # Custom field type breakdown — the ``select`` / ``multi-select``
        # choice schemas changed between versions.
        cf_model = _safe_get_model("extras", "CustomField")
        if cf_model is not None:
            try:
                type_field = (
                    "type"
                    if any(f.name == "type" for f in cf_model._meta.get_fields())
                    else None
                )
                if type_field:
                    breakdown = {}
                    for row in cf_model.objects.values(type_field):
                        key = str(row[type_field] or "unset")
                        breakdown[key] = breakdown.get(key, 0) + 1
                    out["custom_field_type_breakdown"] = breakdown
            except Exception as exc:
                out["custom_field_type_breakdown_error"] = str(exc)

        # Relationship type breakdown — peer vs directional matters for the
        # 2.x migration of extras.Relationship.
        rel_model = _safe_get_model("extras", "Relationship")
        if rel_model is not None:
            try:
                breakdown = {}
                for row in rel_model.objects.values("type"):
                    key = str(row["type"] or "unset")
                    breakdown[key] = breakdown.get(key, 0) + 1
                out["relationship_type_breakdown"] = breakdown
            except Exception as exc:
                out["relationship_type_breakdown_error"] = str(exc)

        return out

    def _inventory_tenancy(self):
        """Tenancy object counts."""
        return {
            "tenant_count": _safe_count("tenancy", "Tenant"),
            "tenant_group_count": _safe_count("tenancy", "TenantGroup"),
        }

    def _inventory_circuits(self):
        """Circuits object counts."""
        return {
            "provider_count": _safe_count("circuits", "Provider"),
            "circuit_count": _safe_count("circuits", "Circuit"),
            "circuit_type_count": _safe_count("circuits", "CircuitType"),
            "circuit_termination_count": _safe_count("circuits", "CircuitTermination"),
            "provider_network_count": _safe_count("circuits", "ProviderNetwork"),
        }

    def _inventory_virtualization(self):
        """Virtualization (VM/cluster) object counts."""
        return {
            "cluster_count": _safe_count("virtualization", "Cluster"),
            "cluster_group_count": _safe_count("virtualization", "ClusterGroup"),
            "cluster_type_count": _safe_count("virtualization", "ClusterType"),
            "virtual_machine_count": _safe_count("virtualization", "VirtualMachine"),
            "vm_interface_count": _safe_count("virtualization", "VMInterface"),
        }

    # ==================================================================
    # SECTION F — INTEGRATIONS (OUTBOUND)
    # ==================================================================
    # Enumerate systems that Nautobot talks *out* to: SSoT adapters,
    # webhooks, Git repos for config/job delivery, and secrets groups
    # (which imply external secret stores).
    # ==================================================================

    def _get_integrations(self):
        """Detect outbound integrations: SSoT, webhooks, Git repos, secrets."""
        integrations = {
            "ssot_adapters": [],
            "webhooks": [],
            "git_repositories": [],
            "secrets_groups": [],
        }

        # SSoT adapters — only present if the nautobot-ssot app is installed.
        try:
            from nautobot_ssot.models import Sync

            recent_syncs = Sync.objects.values_list("source", "target").distinct()
            for source, target in recent_syncs:
                integrations["ssot_adapters"].append(
                    {"source": source, "target": target}
                )
        except ImportError:
            integrations["ssot_installed"] = False
        except Exception as exc:
            integrations["ssot_error"] = str(exc)

        # Webhooks (outbound notifications to external systems).
        try:
            from nautobot.extras.models import Webhook

            for wh in Webhook.objects.all():
                integrations["webhooks"].append(
                    {
                        "name": wh.name,
                        "payload_url": wh.payload_url,
                        "type_create": wh.type_create,
                        "type_update": wh.type_update,
                        "type_delete": wh.type_delete,
                        "enabled": wh.enabled,
                    }
                )
        except Exception as exc:
            integrations["webhooks_error"] = str(exc)

        # Git repositories (external config/data inputs).
        try:
            from nautobot.extras.models import GitRepository

            for repo in GitRepository.objects.all():
                # ``provided_contents`` is a list on 1.x and a RelatedManager
                # on some 2.x versions — normalize defensively.
                raw_contents = getattr(repo, "provided_contents", None)
                if raw_contents is None:
                    contents = []
                else:
                    try:
                        contents = list(raw_contents.all())
                    except AttributeError:
                        try:
                            contents = list(raw_contents)
                        except TypeError:
                            contents = [str(raw_contents)]

                # Credential-storage style detection.
                # 1.x stored auth directly on GitRepository: ``username``,
                # ``_token`` (encrypted), and sometimes ``password``.
                # 2.x moved auth to a linked ``SecretsGroup``. Any repo
                # still using inline credentials needs to be rewired to a
                # SecretsGroup before the upgrade — we report *presence*
                # as booleans, never the credential values themselves.
                has_inline_username = bool(getattr(repo, "username", None))
                has_inline_token = bool(
                    getattr(repo, "_token", None) or getattr(repo, "token", None)
                )
                has_inline_password = bool(getattr(repo, "password", None))
                secrets_group_obj = getattr(repo, "secrets_group", None)
                secrets_group_name = (
                    str(secrets_group_obj) if secrets_group_obj else None
                )
                if has_inline_username or has_inline_token or has_inline_password:
                    credential_style = "legacy_inline"
                elif secrets_group_name:
                    credential_style = "secrets_group"
                else:
                    credential_style = "none"

                integrations["git_repositories"].append(
                    {
                        "name": repo.name,
                        "remote_url": repo.remote_url,
                        "provided_contents": [str(c) for c in contents],
                        "credential_style": credential_style,
                        "has_inline_username": has_inline_username,
                        "has_inline_token": has_inline_token,
                        "has_inline_password": has_inline_password,
                        "secrets_group": secrets_group_name,
                    }
                )
        except Exception as exc:
            integrations["git_repositories_error"] = str(exc)

        # Secrets groups (indicate external secrets backends are wired up).
        try:
            from nautobot.extras.models import SecretsGroup

            for sg in SecretsGroup.objects.all():
                integrations["secrets_groups"].append({"name": sg.name})
        except Exception as exc:
            integrations["secrets_groups_error"] = str(exc)

        return integrations

    # ==================================================================
    # SECTION G — API CONSUMERS (INBOUND)
    # ==================================================================
    # Identify external systems that "reach in" to this Nautobot: API
    # tokens, recent API-authored ObjectChange records, non-default auth
    # backends (SSO/LDAP/SAML), and admin log volume.
    # ==================================================================

    def _get_api_consumers(self):
        """Detect external systems consuming the Nautobot API."""
        consumers = {
            "api_tokens": [],
            "recent_api_activity": {},
            "external_auth_backends": [],
        }

        # ---- API tokens ------------------------------------------------
        # Each token represents a potential external consumer. Tokens
        # themselves are never emitted — only the owning user's username,
        # description, and timestamps.
        try:
            from nautobot.users.models import Token

            for token in Token.objects.select_related("user").all():
                consumers["api_tokens"].append(
                    {
                        "user": token.user.username,
                        "description": token.description or "",
                        "created": str(token.created),
                        "expires": str(token.expires) if token.expires else None,
                        # ``write_enabled`` exists on 1.x/early 2.x; dropped later.
                        "write_enabled": getattr(token, "write_enabled", None),
                        # ``last_used`` is only on newer Nautobot versions.
                        "last_used": str(getattr(token, "last_used", None)),
                    }
                )
        except Exception as exc:
            consumers["api_tokens_error"] = str(exc)

        # ---- Recent API-sourced changes --------------------------------
        # ObjectChange rows reveal which models external systems write to.
        try:
            from nautobot.extras.models import ObjectChange

            from datetime import timedelta
            from django.utils import timezone

            cutoff = timezone.now() - timedelta(days=90)

            # Also pull the ContentType's ``app_label`` so we can build the
            # "app_label.model" key used by ``REMOVED_CONTENT_TYPES`` and
            # flag writes that are hitting models 2.0 will remove.
            api_changes = (
                ObjectChange.objects.filter(time__gte=cutoff)
                .exclude(user_name="")
                .values(
                    "user_name",
                    "changed_object_type__app_label",
                    "changed_object_type__model",
                )
                .distinct()
            )

            user_activity: dict = {}
            legacy_writes: list = []
            for change in api_changes:
                user = change["user_name"]
                app_label = change["changed_object_type__app_label"] or ""
                model = change["changed_object_type__model"] or ""
                key = f"{app_label}.{model}".lower()
                user_activity.setdefault(user, {"models_changed": set()})
                user_activity[user]["models_changed"].add(model)
                # A write against a removed-in-2.0 model is the strongest
                # signal we can produce (without external logs) that
                # something is still using deprecated API endpoints.
                if key in REMOVED_CONTENT_TYPES:
                    legacy_writes.append(
                        {
                            "user": user,
                            "content_type": key,
                            "replacement": REMOVED_CONTENT_TYPES[key],
                        }
                    )

            # Convert sets to sorted lists for JSON serialization.
            for data in user_activity.values():
                data["models_changed"] = sorted(data["models_changed"])

            consumers["recent_api_activity"] = {
                "period_days": 90,
                "users_with_changes": user_activity,
                "writes_to_deprecated_models": legacy_writes,
                "writes_to_deprecated_models_count": len(legacy_writes),
            }
        except Exception as exc:
            consumers["recent_api_activity_error"] = str(exc)

        # ---- Admin log volume ------------------------------------------
        try:
            from django.contrib.admin.models import LogEntry
            from datetime import timedelta
            from django.utils import timezone

            cutoff = timezone.now() - timedelta(days=90)
            consumers["admin_log_entries_90d"] = LogEntry.objects.filter(
                action_time__gte=cutoff
            ).count()
        except Exception:
            pass

        # ---- External auth backends ------------------------------------
        # Non-default auth backends indicate SSO/LDAP/SAML integrations.
        # The shipped default set varies between major versions, so union
        # the known defaults.
        backends = getattr(settings, "AUTHENTICATION_BACKENDS", [])
        default_backends = {
            # 1.x defaults
            "nautobot.core.authentication.ObjectPermissionBackend",
            "django.contrib.auth.backends.ModelBackend",
            "django.contrib.auth.backends.RemoteUserBackend",
            # 2.x+ defaults
            "nautobot.core.authentication.RemoteUserBackend",
            "social_core.backends.utils.load_backends",
        }
        consumers["external_auth_backends"] = [
            b for b in backends if b not in default_backends
        ]
        return consumers

    # ==================================================================
    # SECTION H — FEATURE AUDITS
    # ==================================================================
    # Features whose filter syntax or model definitions change across
    # major versions. Each helper degrades gracefully if the feature
    # wasn't available on the running Nautobot version.
    # ==================================================================

    def _get_dynamic_groups(self):
        """Audit Dynamic Groups for filter syntax that may need migration.

        DynamicGroup was added in Nautobot 1.3.
        """
        try:
            from nautobot.extras.models import DynamicGroup
        except ImportError:
            return {
                "skipped": "DynamicGroup model not present (requires Nautobot >= 1.3)"
            }
        try:
            groups = []
            for dg in DynamicGroup.objects.all():
                # ``filter`` is a JSONField in 1.x; 2.x may rename or
                # restructure the attribute — getattr keeps this safe.
                groups.append(
                    {
                        "name": dg.name,
                        "content_type": str(getattr(dg, "content_type", "")),
                        "filter": getattr(dg, "filter", None),
                    }
                )
            return {"count": len(groups), "groups": groups}
        except Exception as exc:
            return {"error": str(exc)}

    def _get_saved_views(self):
        """Audit Saved Views. The SavedView model was added in Nautobot 2.3."""
        try:
            from nautobot.extras.models import SavedView
        except ImportError:
            return {"skipped": "SavedView model not present (requires Nautobot >= 2.3)"}
        try:
            views = []
            for sv in SavedView.objects.all():
                views.append(
                    {
                        "name": sv.name,
                        "view": getattr(sv, "view", None),
                        "config": getattr(sv, "config", None),
                    }
                )
            return {"count": len(views), "views": views}
        except Exception as exc:
            return {"error": str(exc)}

    def _get_permission_constraints(self):
        """Audit ObjectPermission constraints for references to renamed/removed models.

        Finds constraints whose JSON payload still mentions legacy terms
        (``site``, ``region``, ``device_role``, etc.). Those constraints
        silently stop matching after the upgrade and require hand-editing.
        """
        # Full list of terms that changed meaning or disappeared in 2.x.
        deprecated_refs = [
            "site",
            "region",
            "device_role",
            "rack_role",
            "aggregate",
            "ipam_role",
            "group",  # Rack.group → Rack.rack_group
            "vrf",  # namespace-scoped on 2.x
        ]

        try:
            from nautobot.users.models import ObjectPermission

            flagged = []
            for perm in ObjectPermission.objects.all():
                constraints = perm.constraints or {}
                constraint_str = json.dumps(constraints).lower()
                # A constraint is suspect if its JSON text contains any of
                # the deprecated terms as a substring.
                matches = [ref for ref in deprecated_refs if ref in constraint_str]
                if matches:
                    flagged.append(
                        {
                            "name": perm.name,
                            "deprecated_references": matches,
                            "constraints": constraints,
                        }
                    )
            return {
                "total_permissions": ObjectPermission.objects.count(),
                "flagged": flagged,
                "flagged_count": len(flagged),
            }
        except Exception as exc:
            return {"error": str(exc)}

    def _get_graphql_queries(self):
        """Inventory saved GraphQL queries and count deprecated tokens.

        GraphQL schema changes across major versions silently break saved
        queries — a query that references ``site`` or ``device_role`` on
        2.x returns empty data because the field simply no longer exists.

        For each query we emit:
          * ``name`` — the saved query name
          * ``length`` — the query text size (character count, not content)
          * ``deprecated_token_hits`` — count of whole-word occurrences of
            each removed identifier from ``REMOVED_GRAPHQL_TOKENS``

        The query text itself is never emitted. Token hits let reviewers
        spot queries that need hand-editing without exposing the
        customer's GraphQL surface.
        """
        try:
            from nautobot.extras.models import GraphQLQuery
        except ImportError:
            return {"skipped": "GraphQLQuery model not present"}
        try:
            queries = []
            for q in GraphQLQuery.objects.all():
                # Some versions store text on ``query`` vs ``query_text``.
                text = getattr(q, "query", "") or getattr(q, "query_text", "") or ""
                # Whole-word counts keep the check precise — we don't
                # want ``website`` matching the token ``site``.
                token_hits = {}
                for token in REMOVED_GRAPHQL_TOKENS:
                    n = len(re.findall(rf"\b{re.escape(token)}\b", text))
                    if n:
                        token_hits[token] = n
                queries.append(
                    {
                        "name": getattr(q, "name", ""),
                        "length": len(text),
                        "deprecated_token_hits": token_hits,
                    }
                )
            return {"count": len(queries), "queries": queries}
        except Exception as exc:
            return {"error": str(exc)}

    # ==================================================================
    # SECTION I — RETENTION METRICS
    # ==================================================================
    # Row counts for the "tall" logging tables. These drive the
    # migration-window estimate: large ObjectChange / JobResult tables
    # can extend the upgrade downtime by hours if not pruned first.
    # ==================================================================

    def _get_retention_metrics(self):
        """Row counts for retention-sensitive log tables.

        These tables grow continuously and can extend migration windows.
        The customer may want to prune them before the upgrade.
        """
        return {
            "object_change_count": _safe_count("extras", "ObjectChange"),
            "job_result_count": _safe_count("extras", "JobResult"),
            "job_log_entry_count": _safe_count("extras", "JobLogEntry"),
            # Admin log table is populated by the Django admin UI; useful
            # as a secondary indicator of how much human-driven change
            # occurs on this instance.
            "admin_log_entry_count": self._safe_admin_log_count(),
        }

    @staticmethod
    def _safe_admin_log_count():
        """Count rows in django.contrib.admin's LogEntry table."""
        try:
            from django.contrib.admin.models import LogEntry

            return LogEntry.objects.count()
        except Exception:
            return None

    # ==================================================================
    # SECTION J — TARGET-VERSION COMPATIBILITY
    # ==================================================================
    # Evaluate the current runtime (Python, Django) against the version
    # the customer is trying to reach. Flags "your runtime can't host the
    # target version" situations up front — those need to be resolved
    # before any other migration work begins.
    # ==================================================================

    def _get_compatibility_matrix(self, target_version):
        """Compare running Python/Django versions against target requirements.

        Returns a ``status`` verdict for each axis:
          * ``ok`` — runtime is inside the supported range
          * ``runtime_too_old`` / ``runtime_too_new`` — needs a runtime
            upgrade before the Nautobot upgrade can proceed
          * ``unknown`` — we don't have requirements on record for the
            target version; the customer should verify the release notes

        The matrix itself (``TARGET_VERSION_REQUIREMENTS``) is defined at
        module scope so it's easy to audit and update.
        """
        requirements = TARGET_VERSION_REQUIREMENTS.get(target_version)
        if not requirements:
            return {
                "target_version": target_version,
                "status": "unknown",
                "note": "No requirements on record; verify the Nautobot release notes.",
            }

        # --- Python axis ---------------------------------------------------
        py_current = (
            int(platform.python_version_tuple()[0]),
            int(platform.python_version_tuple()[1]),
        )
        py_min = requirements["python_min"]
        py_max = requirements["python_max"]
        if py_current < py_min:
            py_status = "runtime_too_old"
        elif py_current > py_max:
            py_status = "runtime_too_new"
        else:
            py_status = "ok"

        # --- Django axis ---------------------------------------------------
        django_version = "unknown"
        try:
            import django

            django_version = django.get_version()
        except Exception:
            pass
        # Django requirements are expressed as a single "A.B.x" pin-to-minor
        # band — an exact major+minor match is what Nautobot certifies.
        target_django = requirements["django"]
        target_django_mm = ".".join(target_django.split(".")[:2])
        current_django_mm = ".".join(str(django_version).split(".")[:2])
        django_status = "ok" if current_django_mm == target_django_mm else "mismatch"

        # --- Database server axis -----------------------------------------
        # Pull ``SELECT version()`` and parse the first number sequence out
        # of the result. Compare to the target's ``postgres_min`` /
        # ``mysql_min`` tuple. This matters most for the 3.1 target because
        # PostgreSQL <14 and MySQL <8.0.11 are no longer supported.
        db_status = "ok"
        db_engine = settings.DATABASES.get("default", {}).get("ENGINE", "")
        db_version_str = "unknown"
        db_required = None
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT version();")
                db_version_str = cursor.fetchone()[0]
        except Exception as exc:
            db_version_str = f"error: {exc}"

        def _parse_triplet(raw):
            """Return (major, minor, patch) from the first numeric run in raw."""
            m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", str(raw) or "")
            if not m:
                return None
            return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))

        current_db = _parse_triplet(db_version_str)
        if "postgres" in db_engine.lower():
            db_required = requirements.get("postgres_min")
            engine_label = "postgresql"
        elif "mysql" in db_engine.lower():
            db_required = requirements.get("mysql_min")
            engine_label = "mysql"
        else:
            engine_label = db_engine or "unknown"

        if db_required is not None and current_db is not None:
            # Pad/truncate both to the same length for an apples-to-apples cmp.
            required_len = len(db_required)
            cur = current_db[:required_len]
            if cur < db_required:
                db_status = "db_too_old"
        elif db_required is not None and current_db is None:
            db_status = "unknown"

        return {
            "target_version": target_version,
            "python": {
                "current": platform.python_version(),
                "required_min": "{}.{}".format(*py_min),
                "required_max": "{}.{}".format(*py_max),
                "status": py_status,
            },
            "django": {
                "current": django_version,
                "required": target_django,
                "status": django_status,
            },
            "database": {
                "engine": engine_label,
                "current": db_version_str,
                "required_min": (
                    ".".join(str(p) for p in db_required) if db_required else None
                ),
                "status": db_status,
            },
        }

    # ==================================================================
    # SECTION K — DEPRECATED API URL SCAN
    # ==================================================================
    # External callers that still hit the pre-2.0 REST endpoints will
    # break silently. We can't see every external caller from inside
    # Nautobot, but we can catch the places where a customer is most
    # likely to have embedded those URLs:
    #   * Webhook ``payload_url`` (outbound notifications)
    #   * ConfigContext JSON (often references URL paths for automation)
    #   * ExportTemplate text (templated output commonly embeds URLs)
    #   * Job source (hard-coded URLs used for self-calls)
    # ==================================================================

    def _get_deprecated_api_urls(self):
        """Find references to REST API paths that Nautobot 2.0 removed.

        The four scan targets above cover the lion's share of customer
        integrations. Each finding names the source, the old URL, and the
        replacement path so the customer can ack/fix each occurrence.
        """
        # Typed as plain ``dict`` so error entries (strings) can sit
        # alongside the per-category finding lists.
        findings: dict = {
            "webhooks": [],
            "config_contexts": [],
            "export_templates": [],
            "jobs": [],
        }

        # --- Webhooks --------------------------------------------------
        wh_model = _safe_get_model("extras", "Webhook")
        if wh_model is not None:
            try:
                for wh in wh_model.objects.all():
                    # ``getattr`` keeps us version-proof — attribute names
                    # have shifted slightly across releases.
                    payload_url = getattr(wh, "payload_url", "") or ""
                    hits = [
                        {"url": old, "replacement": new}
                        for old, new in DEPRECATED_API_URLS.items()
                        if old in payload_url
                    ]
                    if hits:
                        findings["webhooks"].append(
                            {
                                "name": getattr(wh, "name", ""),
                                "payload_url": payload_url,
                                "hits": hits,
                            }
                        )
            except Exception as exc:
                findings["webhooks_error"] = str(exc)

        # --- ConfigContext ---------------------------------------------
        cc_model = _safe_get_model("extras", "ConfigContext")
        if cc_model is not None:
            try:
                for cc in cc_model.objects.all():
                    # ConfigContext.data is a JSONField; serializing it
                    # lets the scanner look for URL literals regardless of
                    # their position in the tree.
                    data_blob = json.dumps(getattr(cc, "data", None) or {})
                    hits = [
                        {"url": old, "replacement": new}
                        for old, new in DEPRECATED_API_URLS.items()
                        if old in data_blob
                    ]
                    if hits:
                        findings["config_contexts"].append(
                            {"name": getattr(cc, "name", ""), "hits": hits}
                        )
            except Exception as exc:
                findings["config_contexts_error"] = str(exc)

        # --- ExportTemplate --------------------------------------------
        et_model = _safe_get_model("extras", "ExportTemplate")
        if et_model is not None:
            try:
                for et in et_model.objects.all():
                    # ``template_code`` is the classic attribute name on
                    # 1.x/2.x. ``template`` appears on some versions.
                    body = (
                        getattr(et, "template_code", "")
                        or getattr(et, "template", "")
                        or ""
                    )
                    hits = [
                        {"url": old, "replacement": new}
                        for old, new in DEPRECATED_API_URLS.items()
                        if old in body
                    ]
                    if hits:
                        findings["export_templates"].append(
                            {"name": getattr(et, "name", ""), "hits": hits}
                        )
            except Exception as exc:
                findings["export_templates_error"] = str(exc)

        # --- Jobs source -----------------------------------------------
        # Re-read each registered Job's source file (cheaply; they're
        # small) and grep for deprecated URL literals. Self is skipped.
        job_model = _safe_get_model("extras", "Job")
        if job_model is not None:
            self_module = type(self).__module__
            self_class = type(self).__name__
            try:
                for job in job_model.objects.all():
                    job_module = getattr(job, "module_name", "") or ""
                    job_class = getattr(job, "job_class_name", "") or ""
                    if job_module == self_module and job_class == self_class:
                        continue
                    try:
                        module = importlib.import_module(job_module)
                        source_file = getattr(module, "__file__", None)
                        if not source_file:
                            continue
                        if pathlib.Path(source_file).resolve() == _SELF_SOURCE_FILE:
                            continue
                        text = pathlib.Path(source_file).read_text(errors="replace")
                    except Exception:
                        continue
                    hits = [
                        {"url": old, "replacement": new}
                        for old, new in DEPRECATED_API_URLS.items()
                        if old in text
                    ]
                    if hits:
                        findings["jobs"].append(
                            {
                                "name": getattr(job, "name", ""),
                                "module_name": job_module,
                                "hits": hits,
                            }
                        )
            except Exception as exc:
                findings["jobs_error"] = str(exc)

        return findings

    # ==================================================================
    # SECTION L — PRE-MIGRATE + MIGRATION AUDIT
    # ==================================================================
    # Nautobot ships three read-only management commands that validate
    # data before a major upgrade. We invoke them and capture their
    # output into the report, and we also summarize the Django
    # migrations table (pending migrations are a pre-upgrade hazard).
    # ==================================================================

    def _get_pre_migrate_report(self):
        """Run Nautobot's built-in pre-migration validators and capture output.

        Commands attempted (each is safe / read-only):
          * ``pre_migrate`` — ConfigContext / ConfigContextSchema /
            VirtualChassis uniqueness, permission-constraint audit.
          * ``audit_dynamic_groups`` — filter fields invalidated by
            renames/removed models.
          * ``audit_graphql_queries`` — saved queries that reference
            fields that changed.

        Output is unstructured text, so the report stores it verbatim.
        Any command missing on this Nautobot version is recorded as
        ``"not_available"`` rather than raised as an error.
        """
        from io import StringIO
        from django.core.management import call_command, CommandError

        report = {}
        for command in ("pre_migrate", "audit_dynamic_groups", "audit_graphql_queries"):
            stdout = StringIO()
            stderr = StringIO()
            try:
                call_command(command, stdout=stdout, stderr=stderr)
                report[command] = {
                    "stdout": stdout.getvalue(),
                    "stderr": stderr.getvalue(),
                }
            except CommandError as exc:
                # ``CommandError`` typically means the command doesn't exist
                # on this Nautobot version.
                report[command] = {"not_available": str(exc)}
            except Exception as exc:
                report[command] = {"error": str(exc)}
        return report

    def _get_migration_audit(self):
        """Summarize the Django migrations table.

        Reports applied migrations grouped by app and computes the list of
        pending migrations. Pending migrations before an upgrade are a
        classic source of surprise failures.
        """
        audit = {}

        # --- Applied migrations, grouped by app -----------------------
        try:
            from django.db.migrations.recorder import MigrationRecorder

            applied = MigrationRecorder.Migration.objects.values_list("app", flat=True)
            by_app: dict = {}
            for app in applied:
                by_app[app] = by_app.get(app, 0) + 1
            audit["applied_by_app"] = by_app
            audit["applied_total"] = sum(by_app.values())
        except Exception as exc:
            audit["applied_error"] = str(exc)

        # --- Pending migrations (on-disk but not yet in the DB) -------
        try:
            from django.db.migrations.executor import MigrationExecutor

            executor = MigrationExecutor(connection)
            targets = executor.loader.graph.leaf_nodes()
            plan = executor.migration_plan(targets)
            audit["pending_count"] = len(plan)
            audit["pending"] = [
                {"app": mig.app_label, "name": mig.name} for mig, _ in plan
            ]
        except Exception as exc:
            audit["pending_error"] = str(exc)

        return audit

    # ==================================================================
    # SECTION M — SCHEDULED JOB DETAIL
    # ==================================================================
    # Details of every scheduled job. Count alone (already in the data
    # inventory) doesn't tell the customer which automation is pinned to
    # this instance — the name, interval, and approval state do.
    # ==================================================================

    def _get_scheduled_jobs(self):
        """Enumerate scheduled jobs with interval and approval state."""
        model = _safe_get_model("extras", "ScheduledJob")
        if model is None:
            return {"skipped": "ScheduledJob model not present"}
        try:
            items = []
            for sj in model.objects.all():
                items.append(
                    {
                        "name": getattr(sj, "name", ""),
                        # ``task`` holds the dotted-path job identifier.
                        "task": getattr(sj, "task", None),
                        # ``interval`` varies across versions — str() is safe.
                        "interval": str(getattr(sj, "interval", "")) or None,
                        # "Is this schedule actively running?"
                        "enabled": getattr(sj, "enabled", None),
                        # Approval only meaningful on 2.x; missing on 1.x.
                        "approval_required": getattr(sj, "approval_required", None),
                        # Last-run timestamp helps identify stale schedules.
                        "last_run_at": str(getattr(sj, "last_run_at", "")) or None,
                    }
                )
            return {"count": len(items), "scheduled_jobs": items}
        except Exception as exc:
            return {"error": str(exc)}

    # ==================================================================
    # SECTION N — APPROVAL-WORKFLOW MIGRATION READINESS
    # ==================================================================
    # Nautobot 3.0 removed ``Job.approval_required`` — approvals are now
    # modeled as first-class ``ApprovalWorkflow`` / ``ApprovalWorkflowStage``
    # rows. Nautobot 3.1 followed up by removing ``ScheduledJob.approval_required``
    # in favor of a computed ``state`` property.
    #
    # Any Job / ScheduledJob still relying on the old boolean needs the
    # customer to either (a) remove the flag before upgrade and accept that
    # runs execute without approval, or (b) model an Approval Workflow that
    # preserves the gating behavior. This audit lists what needs attention.
    # ==================================================================

    def _get_job_approval_readiness(self):
        """List every Job/ScheduledJob that still uses the legacy approval flag."""
        result: dict = {"jobs": [], "scheduled_jobs": []}

        job_model = _safe_get_model("extras", "Job")
        if job_model is not None:
            try:
                fields = {f.name for f in job_model._meta.get_fields()}
                if "approval_required" in fields:
                    # Flag every Job row where approval_required=True; these
                    # are the jobs that will lose their gating on 3.0+.
                    for j in job_model.objects.filter(approval_required=True):
                        result["jobs"].append(
                            {
                                "name": getattr(j, "name", ""),
                                "module_name": getattr(j, "module_name", ""),
                                "job_class_name": getattr(j, "job_class_name", ""),
                                "enabled": getattr(j, "enabled", None),
                            }
                        )
            except Exception as exc:
                result["jobs_error"] = str(exc)

        sj_model = _safe_get_model("extras", "ScheduledJob")
        if sj_model is not None:
            try:
                fields = {f.name for f in sj_model._meta.get_fields()}
                if "approval_required" in fields:
                    for sj in sj_model.objects.filter(approval_required=True):
                        result["scheduled_jobs"].append(
                            {
                                "name": getattr(sj, "name", ""),
                                "task": getattr(sj, "task", None),
                                "interval": str(getattr(sj, "interval", "")) or None,
                            }
                        )
            except Exception as exc:
                result["scheduled_jobs_error"] = str(exc)

        result["jobs_count"] = len(result["jobs"])
        result["scheduled_jobs_count"] = len(result["scheduled_jobs"])
        return result

    # ==================================================================
    # SECTION O — TASK-QUEUE MIGRATION (2.4)
    # ==================================================================
    # Nautobot 2.4 introduced the ``JobQueue`` model. Jobs that still
    # declare ``task_queues`` (list of strings) and ScheduledJobs that
    # still populate the legacy ``queue`` CharField need to be migrated to
    # the new ``job_queues`` / ``job_queue`` FK relationships before
    # deprecation is enforced in a future major release.
    # ==================================================================

    def _get_task_queue_migration(self):
        """Counts of rows still using legacy task_queue plumbing."""
        result: dict = {}

        sj_model = _safe_get_model("extras", "ScheduledJob")
        if sj_model is not None:
            try:
                fields = {f.name for f in sj_model._meta.get_fields()}
                # Legacy ``queue`` CharField — present on 1.x through 2.3.
                if "queue" in fields:
                    result["scheduled_jobs_with_legacy_queue"] = (
                        sj_model.objects.exclude(queue__isnull=True)
                        .exclude(queue__exact="")
                        .count()
                    )
                # New ``job_queue`` FK — present on 2.4+.
                if "job_queue" in fields:
                    result["scheduled_jobs_with_job_queue"] = sj_model.objects.exclude(
                        job_queue__isnull=True
                    ).count()
            except Exception as exc:
                result["scheduled_jobs_error"] = str(exc)

        # Count Jobs that still declare ``task_queues`` via the Job model row.
        # 2.4+ stores this on the Job DB record (mirrored from the Job class).
        job_model = _safe_get_model("extras", "Job")
        if job_model is not None:
            try:
                fields = {f.name for f in job_model._meta.get_fields()}
                if "task_queues" in fields:
                    # ``task_queues`` is a JSONField on the Job model; non-empty
                    # list means the class-level attribute is populated.
                    total = 0
                    for j in job_model.objects.all():
                        tq = getattr(j, "task_queues", None)
                        if tq:
                            total += 1
                    result["jobs_with_task_queues"] = total
            except Exception as exc:
                result["jobs_error"] = str(exc)

        # JobQueue presence is a direct "is this deployment already on 2.4+"
        # signal — 0 here on 2.4+ means no one has created a JobQueue yet.
        result["job_queue_count"] = _safe_count("extras", "JobQueue")
        return result

    # ==================================================================
    # SECTION P — FIELD-STATE DELTAS
    # ==================================================================
    # Fields that changed from single-FK to M2M across major versions.
    # The legacy single-FK *attribute* often remains on the model as a
    # backward-compat property, but the underlying column is gone — so
    # rows that still have data in the old field need to be migrated.
    # This check emits "how many rows have the old field populated" so
    # the NTC team can size the migration precisely.
    # ==================================================================

    def _get_field_state_deltas(self):
        """Counts of rows with the pre-M2M single-FK field still set."""
        result: dict = {}

        # --- 2.2: Prefix.location → Prefix.locations -----------------
        prefix_model = _safe_get_model("ipam", "Prefix")
        if prefix_model is not None:
            pfx_fields = {f.name for f in prefix_model._meta.get_fields()}
            if "location" in pfx_fields:
                try:
                    result["prefixes_with_legacy_location_fk"] = (
                        prefix_model.objects.exclude(location__isnull=True).count()
                    )
                except Exception as exc:
                    result["prefixes_legacy_location_error"] = str(exc)

        # --- 2.2: VLAN.location → VLAN.locations ---------------------
        vlan_model = _safe_get_model("ipam", "VLAN")
        if vlan_model is not None:
            vlan_fields = {f.name for f in vlan_model._meta.get_fields()}
            if "location" in vlan_fields:
                try:
                    result["vlans_with_legacy_location_fk"] = (
                        vlan_model.objects.exclude(location__isnull=True).count()
                    )
                except Exception as exc:
                    result["vlans_legacy_location_error"] = str(exc)

        # --- 3.0: Device.cluster → Device.clusters -------------------
        device_model = _safe_get_model("dcim", "Device")
        if device_model is not None:
            dev_fields = {f.name for f in device_model._meta.get_fields()}
            if "cluster" in dev_fields:
                try:
                    result["devices_with_legacy_cluster_fk"] = (
                        device_model.objects.exclude(cluster__isnull=True).count()
                    )
                except Exception as exc:
                    result["devices_legacy_cluster_error"] = str(exc)

        return result

    # ==================================================================
    # SECTION Q — UI COMPONENT FRAMEWORK IMPACT
    # ==================================================================
    # Nautobot 2.4 migrated a long list of detail views to the UI
    # Component Framework. App ``TemplateExtension`` subclasses that
    # target any of those models need refactoring — the old
    # ``left_page()`` / ``right_page()`` / ``detail_tabs()`` hooks still
    # render but the Framework encourages the Panel/Tab APIs instead.
    # ==================================================================

    # Models whose detail view was migrated to the UI Component Framework
    # in Nautobot 2.4. Used to tag template extensions that target them.
    UI_COMPONENT_FRAMEWORK_MIGRATED = {
        "dcim.location": "LocationType-scoped detail",
        "dcim.device": "Add Components buttons",
        "dcim.locationtype": "",
        "circuits.circuit": "",
        "circuits.provider": "",
        "ipam.routetarget": "",
        "ipam.vrf": "",
        "tenancy.tenant": "",
        "virtualization.clustertype": "",
        "extras.externalintegration": "",
        "extras.secret": "",
    }

    def _get_ui_component_framework_impact(self):
        """Identify template extensions whose target model migrated to UICF."""
        hits = []
        for app_name in getattr(settings, "PLUGINS", []):
            try:
                mod = importlib.import_module(f"{app_name}.template_content")
            except (ImportError, ModuleNotFoundError):
                continue
            import inspect as _inspect

            for cls_name, obj in _inspect.getmembers(mod, _inspect.isclass):
                if not obj.__module__.startswith(app_name):
                    continue
                target = getattr(obj, "model", None)
                if target and target in self.UI_COMPONENT_FRAMEWORK_MIGRATED:
                    hits.append(
                        {
                            "app": app_name,
                            "class": cls_name,
                            "target_model": target,
                            "note": self.UI_COMPONENT_FRAMEWORK_MIGRATED[target]
                            or "migrated to UI Component Framework in 2.4",
                        }
                    )
        return {"count": len(hits), "extensions_on_migrated_models": hits}

    # ==================================================================
    # SECTION R — CONTENT-TYPE FEATURE USAGE
    # ==================================================================
    # Nautobot features like CustomField / Relationship / Status / Tag /
    # Webhook / CustomLink / ExportTemplate / ComputedField / JobHook /
    # JobButton / Note all associate themselves with one or more
    # ContentTypes. When a model is removed (Site, Region, DeviceRole,
    # RackRole, Aggregate, ipam.Role), the M2M/FK rows pointing at its
    # ContentType become orphans — the feature stops firing / filtering
    # / rendering without raising an error.
    #
    # For each feature model we enumerate its content-type references and
    # flag any that target ``REMOVED_CONTENT_TYPES``. The output groups
    # findings per feature so reviewers see exactly which Webhooks / CFs
    # / etc. need to be re-pointed before the upgrade.
    # ==================================================================

    # Feature-model → (attribute-name, is_m2m) tuples. Some features have a
    # single ``content_type`` FK (CustomLink, ExportTemplate,
    # ComputedField, Note); others have an M2M ``content_types`` manager
    # (CustomField, Status, Tag, Webhook, JobHook, JobButton). Relationship
    # uses two FKs: ``source_type`` and ``destination_type``.
    _CONTENT_TYPE_FEATURES = [
        # (app_label, model_name, field_name, kind)
        ("extras", "CustomField", "content_types", "m2m"),
        ("extras", "Status", "content_types", "m2m"),
        ("extras", "Tag", "content_types", "m2m"),
        ("extras", "Webhook", "content_types", "m2m"),
        ("extras", "JobHook", "content_types", "m2m"),
        ("extras", "JobButton", "content_types", "m2m"),
        ("extras", "CustomLink", "content_type", "fk"),
        ("extras", "ExportTemplate", "content_type", "fk"),
        ("extras", "ComputedField", "content_type", "fk"),
        ("extras", "Note", "assigned_object_type", "fk"),
        # Relationship uses two content-type FKs (one per direction).
        ("extras", "Relationship", "source_type", "fk"),
        ("extras", "Relationship", "destination_type", "fk"),
    ]

    def _get_content_type_feature_usage(self):
        """Flag feature rows whose content type(s) point at removed models."""
        findings: dict = {"flagged": [], "flagged_count": 0}

        for app_label, model_name, field_name, kind in self._CONTENT_TYPE_FEATURES:
            model = _safe_get_model(app_label, model_name)
            if model is None:
                continue
            try:
                for obj in model.objects.all():
                    legacy_targets = self._legacy_content_types_on(
                        obj, field_name, kind
                    )
                    if not legacy_targets:
                        continue
                    findings["flagged"].append(
                        {
                            "feature": f"{app_label}.{model_name}",
                            "field": field_name,
                            "name": getattr(obj, "name", str(obj)),
                            "legacy_targets": [
                                {
                                    "content_type": ct,
                                    "replacement": REMOVED_CONTENT_TYPES[ct],
                                }
                                for ct in legacy_targets
                            ],
                        }
                    )
            except Exception as exc:
                findings.setdefault("errors", {})[f"{app_label}.{model_name}"] = str(
                    exc
                )

        findings["flagged_count"] = len(findings["flagged"])
        return findings

    @staticmethod
    def _legacy_content_types_on(obj, field_name, kind):
        """Return the subset of an object's content types that are removed models.

        ``kind`` is ``"m2m"`` for ``content_types`` managers and ``"fk"``
        for single ``content_type`` foreign keys.
        """

        def _key(ct):
            # ``ct`` is a ContentType row; build "app_label.model" lowercase.
            if ct is None:
                return None
            try:
                return f"{ct.app_label}.{ct.model}".lower()
            except Exception:
                return None

        targets: list = []
        if kind == "m2m":
            mgr = getattr(obj, field_name, None)
            if mgr is None:
                return []
            try:
                for ct in mgr.all():
                    key = _key(ct)
                    if key and key in REMOVED_CONTENT_TYPES:
                        targets.append(key)
            except Exception:
                return []
        else:  # fk
            ct = getattr(obj, field_name, None)
            key = _key(ct)
            if key and key in REMOVED_CONTENT_TYPES:
                targets.append(key)
        return targets

    # ==================================================================
    # SECTION S — READ-TRAFFIC DETECTION (OPPORTUNISTIC)
    # ==================================================================
    # Nautobot itself doesn't log REST reads. The one signal we can read
    # without bringing in external dependencies is django-prometheus's
    # per-view request counters — the same data ``/metrics`` exposes.
    # We read those counters directly from the in-process
    # ``prometheus_client`` registry so no HTTP call or auth is needed.
    #
    # Coverage scope:
    #   * Multi-process mode (``PROMETHEUS_MULTIPROC_DIR`` set) — we see
    #     aggregated counts across every uWSGI + Celery process.
    #   * Single-process mode — we see only this Celery worker's counts,
    #     which is typically zero for HTTP views. The output says so.
    #
    # When the metrics aren't reachable we emit a ready-to-install
    # middleware snippet so operators can deploy it for ~1 week and
    # re-run the assessment for caller attribution.
    # ==================================================================

    def _get_read_traffic_signals(self):
        """Best-effort detection of reads against deprecated endpoints."""
        return {
            "prometheus_counters": self._probe_prometheus_counters(),
            "middleware_snippet": self._emit_middleware_snippet(),
        }

    def _probe_prometheus_counters(self):
        """Read django-prometheus counters for legacy URL views.

        If ``PROMETHEUS_MULTIPROC_DIR`` is configured we use
        :class:`prometheus_client.multiprocess.MultiProcessCollector` to
        aggregate across all Nautobot workers. Otherwise we read the
        Celery-worker-local registry, which is only useful if the
        customer has already been hitting legacy endpoints from within
        the worker's own Python code.
        """
        import os as _os

        try:
            from prometheus_client import REGISTRY, CollectorRegistry
        except ImportError:
            return {
                "skipped": "prometheus_client not installed",
                "recommendation": (
                    "Enable /metrics by installing django-prometheus or "
                    "the nautobot_capacity_metrics app."
                ),
            }

        # Multi-process registry aggregates across every Python process
        # writing to the shared dir (uWSGI workers + Celery workers).
        # Both env-var and settings lookups are supported.
        multiproc_dir = (
            _os.environ.get("PROMETHEUS_MULTIPROC_DIR")
            or _os.environ.get("prometheus_multiproc_dir")
            or getattr(settings, "PROMETHEUS_MULTIPROC_DIR", None)
        )
        registry = REGISTRY
        multiproc_used = False
        if multiproc_dir:
            try:
                from prometheus_client.multiprocess import MultiProcessCollector

                registry = CollectorRegistry()
                MultiProcessCollector(registry)
                multiproc_used = True
            except Exception:
                # Fall back silently to the in-process registry.
                registry = REGISTRY

        # django-prometheus names the per-view metric family
        # ``django_http_requests_total_by_view_transport_method`` and
        # labels each sample with ``view``. Look for label values that
        # reference any removed URL namespace.
        legacy_view_tokens = [
            "dcim:site",
            "dcim:region",
            "dcim:devicerole",
            "dcim:rackrole",
            "ipam:aggregate",
            "ipam:role",
        ]
        hits = []
        try:
            families = list(registry.collect())
        except Exception as exc:
            return {"error": f"unable to collect registry: {exc}"}

        for family in families:
            if "django_http_requests_total" not in family.name:
                continue
            for sample in family.samples:
                view_label = (
                    sample.labels.get("view") or sample.labels.get("view_name") or ""
                )
                if any(tok in view_label for tok in legacy_view_tokens):
                    hits.append(
                        {
                            "view": view_label,
                            "method": sample.labels.get("method"),
                            "status": sample.labels.get("status"),
                            "count": int(sample.value),
                        }
                    )

        return {
            "multiproc_enabled": multiproc_used,
            "legacy_view_hits": hits,
            "note": (
                "Aggregated across all Nautobot processes."
                if multiproc_used
                else (
                    "Single-process registry — likely empty for HTTP "
                    "counters. For full read attribution, set "
                    "PROMETHEUS_MULTIPROC_DIR and share it between "
                    "uWSGI and Celery workers, or install the middleware "
                    "snippet below."
                )
            ),
        }

    @staticmethod
    def _emit_middleware_snippet():
        """Return a ready-to-install middleware that logs deprecated-URL hits.

        The snippet is intentionally tiny — operators drop it into a
        temporary ``MIDDLEWARE`` position for a week, then re-run the
        assessment. Nothing in this Job runs the snippet; it's purely
        documentation.
        """
        return {
            "purpose": (
                "Temporary middleware to log reads of deprecated REST "
                "endpoints. Install for ~1 week, then re-run this Job to "
                "correlate the log with callers."
            ),
            "python": (
                "import logging\n"
                "logger = logging.getLogger('nautobot.deprecated_urls')\n"
                "\n"
                "DEPRECATED_PREFIXES = (\n"
                "    '/api/dcim/sites/', '/api/dcim/regions/',\n"
                "    '/api/dcim/device-roles/', '/api/dcim/rack-roles/',\n"
                "    '/api/ipam/aggregates/', '/api/ipam/roles/',\n"
                ")\n"
                "\n"
                "class DeprecatedURLLogger:\n"
                "    def __init__(self, get_response):\n"
                "        self.get_response = get_response\n"
                "    def __call__(self, request):\n"
                "        if request.path.startswith(DEPRECATED_PREFIXES):\n"
                "            logger.warning(\n"
                "                'DEPRECATED %s %s by %s from %s',\n"
                "                request.method, request.path,\n"
                "                getattr(request.user, 'username', 'anon'),\n"
                "                request.META.get('REMOTE_ADDR'),\n"
                "            )\n"
                "        return self.get_response(request)\n"
            ),
            "install": (
                "Add the class path (e.g. 'nautobot_config.DeprecatedURLLogger') "
                "to MIDDLEWARE in nautobot_config.py, restart Nautobot, "
                "and configure LOGGING['loggers']['nautobot.deprecated_urls'] "
                "to write to its own file."
            ),
        }


jobs = [UpgradeReadinessAssessment]

# On Nautobot 2.0+ the registry only discovers jobs that call ``register_jobs``;
# on 1.x the symbol doesn't exist (``register_jobs is None``) and defining the
# class above is sufficient. We deliberately don't swallow exceptions from the
# call itself — if registration fails on a version that needs it, the job would
# silently never appear, so let that error surface in the Nautobot logs.
if register_jobs is not None:
    register_jobs(*jobs)
