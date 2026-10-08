"""Record shaping, flattening, field definitions and totals."""
import json
import re
from datetime import datetime, timezone

ENGINE_ORDER = ("sast", "sca", "kics", "containers", "apisec", "scs")
# scan-summary block -> engine it belongs to
SUMMARY_BLOCKS = {
    "sastCounters": "sast",
    "kicsCounters": "kics",
    "scaCounters": "sca",
    "scaPackagesCounters": "sca",
    "containersCounters": "containers",
    "scaContainersCounters": "containers",
    "microEnginesCounters": "microengines",
    "apiSecCounters": "apisec",
    "aiscCounters": "aisc",
}
FINDING_ENGINES = ("sast", "kics", "sca", "containers", "apisec", "microengines", "aisc")
NOT_SCANNED = "no SAST"

_TS_FRAC = re.compile(r"(\.\d{6})\d+")


# ---------------------------------------------------------------- parsing helpers
def parse_ts(value):
    """Parse ISO timestamps with 7-9 fractional digits and 'Z'. Returns aware datetime or None."""
    if not value or not isinstance(value, str):
        return None
    s = _TS_FRAC.sub(r"\1", value.strip())
    if s.endswith(("Z", "z")):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def seconds_between(start, end):
    a, b = parse_ts(start), parse_ts(end)
    if a is None or b is None:
        return None
    return round(max((b - a).total_seconds(), 0.0), 1)


def counter_map(items):
    """[{severity: 'HIGH', counter: 3}, ...] -> {'HIGH': 3}. Name key = first non-counter string field."""
    out = {}
    for it in items or []:
        if not isinstance(it, dict):
            continue
        count = it.get("counter", it.get("count"))
        name = next((v for k, v in it.items() if k not in ("counter", "count") and isinstance(v, str)), None)
        if name is not None and isinstance(count, (int, float)):
            out[name] = out.get(name, 0) + int(count)
    return out


def _find_counter_list(block, *needles):
    """Find a list-of-counters value whose key contains any needle (case-insensitive)."""
    for key, value in (block or {}).items():
        if isinstance(value, list) and any(n in key.lower() for n in needles):
            return counter_map(value)
    return {}


def _num(block, *keys):
    for k in keys:
        v = (block or {}).get(k)
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            return int(v)
    return None


def _clean_pairs(d):
    """Drop null keys/values (e.g. {"null": null})."""
    if not isinstance(d, dict):
        return {}
    return {k: v for k, v in d.items() if k not in (None, "", "null") and v is not None}


def _top(d, n):
    return dict(sorted(d.items(), key=lambda kv: -kv[1])[:n])


# ---------------------------------------------------------------- record construction
def new_record(scan_id):
    return {
        "scan_id": scan_id, "project_id": None, "project_name": None, "branch": None, "commit": None,
        "repo_url": None, "status": None, "created_at": None, "updated_at": None, "engines": [],
        "initiator": None, "source_type": None, "source_origin": None, "user_agent": None, "tags": None,
        "timing": {"duration_s": None, "engines": {}},
        "sast": {"loc": None, "scanned_loc": None, "files": None, "preset": None, "scan_mode": NOT_SCANNED,
                 "base_scan_id": None, "files_added": None, "files_changed": None, "files_deleted": None,
                 "change_pct": None, "has_configuration_changed": None, "engine_version": None,
                 "memory_peak_mb": None, "virtual_memory_peak_mb": None, "languages": None,
                 "languages_not_scanned": None, "is_incremental": False, "incremental_cancelled": False,
                 "cancel_reason": None},
        "sizing": {"last_full_loc": None, "last_full_scan_id": None, "sizing_loc": None, "sizing_note": None},
        "iac": {"files_scanned": None, "findings": None, "by_severity": None, "platforms": None,
                "categories": None, "files_with_findings": None, "top_files": None, "providers": None,
                "resource_types": None},
        "sca": {"packages": None, "outdated": None, "package_risk_levels": None, "vulnerabilities": None,
                "by_severity": None, "top_licenses": None},
        "containers": {"packages": None, "vulnerable_images": None, "findings": None},
        "findings": {},
        "config": None,
        "source_loc": None,
        "errors": [],
    }


def apply_scan(rec, scan):
    rec["project_id"] = scan.get("projectId")
    rec["project_name"] = scan.get("projectName")
    rec["branch"] = scan.get("branch")
    rec["status"] = scan.get("status")
    rec["created_at"] = scan.get("createdAt")
    rec["updated_at"] = scan.get("updatedAt")
    rec["engines"] = [str(e).lower() for e in (scan.get("engines") or [])]
    rec["initiator"] = scan.get("initiator")
    rec["source_type"] = scan.get("sourceType")
    rec["source_origin"] = scan.get("sourceOrigin")
    rec["user_agent"] = scan.get("userAgent")
    rec["tags"] = scan.get("tags")
    git = ((scan.get("metadata") or {}).get("Handler") or {}).get("GitHandler") or {}
    rec["repo_url"] = git.get("repo_url") or git.get("repoUrl")
    rec["commit"] = next((git[k] for k in ("commit", "commit_id", "commitId", "sha") if git.get(k)), None)
    details = scan.get("statusDetails") or []
    general = next((d for d in details if str(d.get("name", "")).lower() == "general"), None)
    dur = seconds_between(general.get("startDate"), general.get("endDate")) if general else None
    if dur is None:
        dur = seconds_between(scan.get("createdAt"), scan.get("updatedAt"))
    rec["timing"]["duration_s"] = dur
    for d in details:
        name = str(d.get("name", "")).lower()
        if name and name != "general":
            rec["timing"]["engines"][name] = seconds_between(d.get("startDate"), d.get("endDate"))
        if name == "sast" and isinstance(d.get("loc"), (int, float)):
            rec["sast"]["_status_loc"] = int(d["loc"])


def apply_sast_meta(rec, meta):
    s = rec["sast"]
    loc = meta.get("loc")
    s["loc"] = int(loc) if isinstance(loc, (int, float)) else s.get("_status_loc")
    s["files"] = meta.get("fileCount")
    s["preset"] = meta.get("queryPreset")
    s["is_incremental"] = bool(meta.get("isIncremental"))
    s["incremental_cancelled"] = bool(meta.get("isIncrementalCanceled"))
    set_scan_mode(rec)


def set_scan_mode(rec):
    s = rec["sast"]
    if s["incremental_cancelled"]:
        reason = s.get("cancel_reason")
        s["scan_mode"] = f"full (incremental cancelled: {reason})" if reason else "full (incremental cancelled)"
    elif s["is_incremental"]:
        s["scan_mode"] = "incremental"
    else:
        s["scan_mode"] = "full"


def is_incremental_mode(rec):
    return rec["sast"]["scan_mode"] == "incremental"


def apply_sast_detail(rec, d):
    s = rec["sast"]
    s["base_scan_id"] = d.get("baseId")
    s["files_added"] = d.get("addedFilesCount")
    s["files_changed"] = d.get("changedFilesCount")
    s["files_deleted"] = d.get("deletedFilesCount")
    s["change_pct"] = d.get("changePercentage")
    s["has_configuration_changed"] = d.get("hasConfigurationChanged")
    s["cancel_reason"] = d.get("incrementalCancelReason")
    if s["incremental_cancelled"]:
        set_scan_mode(rec)


def apply_metrics(rec, m):
    s = rec["sast"]
    s["scanned_loc"] = m.get("totalScannedLoc")
    if s["files"] is None:
        s["files"] = m.get("totalScannedFilesCount")
    s["memory_peak_mb"] = m.get("memoryPeak")
    s["virtual_memory_peak_mb"] = m.get("virtualMemoryPeak")
    ok = _clean_pairs(m.get("successfullLocPerLanguage"))  # sic: API spells it with two l's
    failed = _clean_pairs(m.get("failedLocPerLanguage"))
    files = _clean_pairs(m.get("scannedFilesPerLanguage"))
    langs = []
    for lang in sorted(set(ok) | set(failed) | set(files), key=lambda k: -(ok.get(k) or 0)):
        f = files.get(lang) if isinstance(files.get(lang), dict) else {}
        langs.append({"language": lang, "loc_scanned": ok.get(lang, 0), "loc_failed": failed.get(lang, 0),
                      "files_good": f.get("goodFiles", 0), "files_partial": f.get("partiallyGoodFiles", 0),
                      "files_bad": f.get("badFiles", 0)})
    s["languages"] = langs
    ns = m.get("fileCountOfDetectedButNotScannedLanguages")
    if isinstance(ns, dict):
        s["languages_not_scanned"] = [{"language": k, "files": v} for k, v in _clean_pairs(ns).items()]
    elif isinstance(ns, list):
        s["languages_not_scanned"] = [{"language": str(k), "files": None} for k in ns if k]
    else:
        s["languages_not_scanned"] = []


def apply_summary(rec, summary):
    """Fill IaC/SCA/container/findings from one scansSummaries[] entry. Blocks of engines that did
    not run are zeroed by the API, so they are reported as null (not ran) based on `engines`."""
    ran = set(rec["engines"])
    blocks = {}
    for block_name, engine in SUMMARY_BLOCKS.items():
        blocks[block_name] = summary.get(block_name) if engine in ran else None
    for engine in FINDING_ENGINES:
        main = {"sast": "sastCounters", "kics": "kicsCounters", "sca": "scaCounters",
                "containers": "containersCounters", "apisec": "apiSecCounters",
                "microengines": "microEnginesCounters", "aisc": "aiscCounters"}[engine]
        b = blocks.get(main)
        if b is None:
            continue
        rec["findings"][engine] = {
            "total": _num(b, "totalCounter") or 0,
            "by_severity": counter_map(b.get("severityCounters")),
            "by_status": {k.upper(): v for k, v in counter_map(b.get("statusCounters")).items()},
        }
    kics = blocks["kicsCounters"]
    if kics is not None:
        i = rec["iac"]
        i["files_scanned"] = _num(kics, "filesScannedCounter")  # the only real filesScannedCounter
        i["findings"] = _num(kics, "totalCounter") or 0
        i["by_severity"] = counter_map(kics.get("severityCounters"))
        i["platforms"] = _find_counter_list(kics, "platform")
        i["categories"] = _find_counter_list(kics, "categor")
    sca, pk = blocks["scaCounters"], blocks["scaPackagesCounters"]
    if sca is not None:
        c = rec["sca"]
        c["vulnerabilities"] = _num(sca, "totalCounter") or 0
        c["by_severity"] = counter_map(sca.get("severityCounters"))
        lic = _find_counter_list(sca, "licen") or _find_counter_list(pk, "licen")
        c["top_licenses"] = _top(lic, 5)
    if pk is not None:
        c = rec["sca"]
        c["packages"] = _num(pk, "totalCounter") or 0
        c["outdated"] = _num(pk, "outdatedCounter", "outdatedPackagesCounter", "totalOutdatedCounter")
        c["package_risk_levels"] = _find_counter_list(pk, "risk")
    cont, scac = blocks["containersCounters"], blocks["scaContainersCounters"]
    if cont is not None or scac is not None:
        c = rec["containers"]
        pkgs = _num(scac, "totalPackagesCounter", "totalCounter") if scac else None
        c["packages"] = pkgs if pkgs is not None else (_num(cont, "totalPackagesCounter") if cont else None)
        imgs = _num(cont, "totalImagesCounter", "imagesCounter", "vulnerableImagesCounter") if cont else None
        c["vulnerable_images"] = imgs
        c["findings"] = _num(cont, "totalCounter") if cont else None


def apply_kics_detail(rec, results):
    files, providers, rtypes = {}, {}, {}
    for r in results:
        fn = r.get("fileName")
        if fn:
            files[fn] = files.get(fn, 0) + 1
        if r.get("cloudProvider"):
            providers[r["cloudProvider"]] = providers.get(r["cloudProvider"], 0) + 1
        if r.get("resourceType"):
            rtypes[r["resourceType"]] = rtypes.get(r["resourceType"], 0) + 1
    i = rec["iac"]
    i["files_with_findings"] = len(files)
    i["top_files"] = _top(files, 10)
    i["providers"] = providers
    i["resource_types"] = _top(rtypes, 10)


def apply_config(rec, items):
    out = {}
    for it in items or []:
        key = it.get("key") or ""
        if key.startswith("scan.config."):
            out[key] = {"value": it.get("value"), "origin": it.get("originLevel")}
    rec["config"] = out


def finalize(rec):
    """Drop internal keys; use the statusDetails LOC when sast-metadata gave none."""
    s = rec["sast"]
    fallback = s.pop("_status_loc", None)
    if s["loc"] is None and s["scan_mode"] != NOT_SCANNED:
        s["loc"] = fallback
    return rec


def apply_sizing_default(rec, sizing_enabled):
    """Full scans size themselves; incremental ones need the --sizing walk-back."""
    z, s = rec["sizing"], rec["sast"]
    if s["scan_mode"].startswith("full"):
        z["sizing_loc"] = s["loc"]
    elif s["scan_mode"] == "incremental" and not sizing_enabled:
        z["sizing_note"] = "incremental: re-run with --sizing"


def apply_last_full(rec, found):
    """found = (scan_id, loc) or None."""
    z, s = rec["sizing"], rec["sast"]
    if found:
        z["last_full_scan_id"], z["last_full_loc"] = found
        z["sizing_loc"] = z["last_full_loc"]
    else:
        z["sizing_loc"] = s["loc"]
        z["sizing_note"] = "no full scan found (undercount)"


# ---------------------------------------------------------------- flattening
def _path(*p):
    return p


# flat name -> (path into nested record, group). group None = always shown by default.
FIELD_PATHS = {}
FIELD_GROUPS = {}


def _add(name, path, group=None):
    FIELD_PATHS[name] = path
    FIELD_GROUPS[name] = group


for _n in ("scan_id", "project_id", "project_name", "branch", "commit", "status", "created_at", "engines",
           "initiator", "source_type", "source_origin"):
    _add(_n, (_n,))
_add("duration_s", ("timing", "duration_s"))
for _e in ENGINE_ORDER:
    _add(f"{_e}_duration_s", ("timing", "engines", _e))
for _flat, _key in (("sast_loc", "loc"), ("sast_scanned_loc", "scanned_loc"), ("sast_files", "files"),
                    ("preset", "preset"), ("scan_mode", "scan_mode"), ("base_scan_id", "base_scan_id"),
                    ("files_added", "files_added"), ("files_changed", "files_changed"),
                    ("files_deleted", "files_deleted"), ("change_pct", "change_pct"),
                    ("engine_version", "engine_version"), ("memory_peak_mb", "memory_peak_mb")):
    _add(_flat, ("sast", _key))
_add("languages", ("sast", "languages"), "languages")
_add("languages_not_scanned", ("sast", "languages_not_scanned"), "languages")
for _n in ("last_full_loc", "last_full_scan_id", "sizing_loc", "sizing_note"):
    _add(_n, ("sizing", _n))
_add("iac_files_scanned", ("iac", "files_scanned"))
_add("iac_findings", ("iac", "findings"))
_add("iac_by_severity", ("iac", "by_severity"))
_add("iac_platforms", ("iac", "platforms"))
_add("iac_categories", ("iac", "categories"))
for _n in ("files_with_findings", "top_files", "providers", "resource_types"):
    _add(f"iac_{_n}", ("iac", _n), "iac_detail")
_add("sca_packages", ("sca", "packages"))
_add("sca_outdated", ("sca", "outdated"))
_add("sca_package_risk_levels", ("sca", "package_risk_levels"))
_add("sca_vulnerabilities", ("sca", "vulnerabilities"))
_add("sca_by_severity", ("sca", "by_severity"))
_add("sca_top_licenses", ("sca", "top_licenses"))
_add("container_packages", ("containers", "packages"))
_add("vulnerable_images", ("containers", "vulnerable_images"))
_add("container_findings", ("containers", "findings"))
for _e in ("sast", "apisec", "microengines"):
    _add(f"{_e}_findings", ("findings", _e, "total"))
    _add(f"{_e}_by_severity", ("findings", _e, "by_severity"))
_add("sast_by_status", ("findings", "sast", "by_status"))
_add("config", ("config",), "config")
for _n in ("app_code_loc", "iac_loc", "iac_files", "iac_platforms", "languages"):
    _add(f"source_{_n}", ("source_loc", _n), "source_loc")
_add("errors", ("errors",))

ALL_FIELDS = list(FIELD_PATHS)


def default_fields(languages=False, config=False, iac_detail=False, source_loc=False):
    enabled = {None}
    if languages:
        enabled.add("languages")
    if config:
        enabled.add("config")
    if iac_detail:
        enabled.add("iac_detail")
    if source_loc:
        enabled.add("source_loc")
    return [f for f in ALL_FIELDS if FIELD_GROUPS[f] in enabled]


def get_path(rec, path):
    cur = rec
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def _format(name, value):
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if name == "errors":
        return " | ".join(value)
    if name == "engines":
        return ";".join(value)
    if name == "languages" and value and isinstance(value, list) and isinstance(value[0], dict):
        return ";".join(f"{x['language']}={x.get('loc_scanned', 0)}" for x in value)
    if name == "languages_not_scanned" and isinstance(value, list):
        return ";".join(f"{x['language']}={x['files']}" if x.get("files") is not None else x["language"]
                        for x in value)
    if name == "config" and isinstance(value, dict):
        return json.dumps({k: v.get("value") for k, v in value.items()}, separators=(",", ":"))
    if isinstance(value, dict):
        if all(not isinstance(v, (dict, list)) for v in value.values()):
            return ";".join(f"{k}={v}" for k, v in value.items())
        return json.dumps(value, separators=(",", ":"))
    if isinstance(value, list):
        return json.dumps(value, separators=(",", ":"))
    return str(value)


def flatten(rec, fields=None):
    """Flat {field: string-or-number} view of a record (numbers kept numeric for the table)."""
    out = {}
    for name in fields or ALL_FIELDS:
        path = FIELD_PATHS.get(name)
        value = get_path(rec, path) if path else rec.get(name)
        out[name] = value if isinstance(value, (int, float)) and not isinstance(value, bool) else _format(name, value)
    return out


# ---------------------------------------------------------------- totals
class Totals:
    def __init__(self, languages=False):
        self.scans = 0
        self.with_sast = 0
        self.incremental = 0
        self.sast_loc = 0
        self.unsized_incremental = 0
        self.iac_files = 0
        self.sca_packages = 0
        self.errors = 0
        self.languages = {} if languages else None
        self._sizing = {}  # (project, branch) -> (created_at, sizing_loc): latest only

    def add(self, rec):
        self.scans += 1
        s = rec["sast"]
        if s["scan_mode"] != NOT_SCANNED:
            self.with_sast += 1
            self.sast_loc += s["loc"] or 0
        if s["scan_mode"] == "incremental":
            self.incremental += 1
        self.iac_files += rec["iac"]["files_scanned"] or 0
        self.sca_packages += rec["sca"]["packages"] or 0
        if rec["errors"]:
            self.errors += 1
        if self.languages is not None:
            for lang in s["languages"] or []:
                self.languages[lang["language"]] = self.languages.get(lang["language"], 0) + (lang["loc_scanned"] or 0)
        loc = rec["sizing"]["sizing_loc"]
        if loc is not None:
            key = (rec["project_id"], rec["branch"])
            stamp = parse_ts(rec["created_at"]) or datetime.min.replace(tzinfo=timezone.utc)
            if key not in self._sizing or stamp > self._sizing[key][0]:
                self._sizing[key] = (stamp, loc)
        elif s["scan_mode"] == "incremental":
            self.unsized_incremental += 1

    @property
    def sizing_loc(self):
        return sum(v[1] for v in self._sizing.values())

    def to_dict(self):
        d = {"scans": self.scans, "scans_with_sast": self.with_sast, "incremental_scans": self.incremental,
             "sum_sast_loc": self.sast_loc, "sum_sizing_loc": self.sizing_loc,
             "sizing_basis": "latest scan per project+branch", "unsized_incremental_scans": self.unsized_incremental,
             "iac_files_scanned": self.iac_files, "sca_packages": self.sca_packages,
             "scans_with_errors": self.errors}
        if self.languages is not None:
            d["language_loc_scanned"] = dict(sorted(self.languages.items(), key=lambda kv: -kv[1]))
        return d
