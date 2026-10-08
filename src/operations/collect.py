"""Batched + threaded collection: one record per scan."""
import threading
from collections import deque
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass

from src import model
from src.operations import source_loc
from src.operations.base import Operation
from src.utils.http import ApiError

CHUNK = 50
MAX_ACTIVE = 2 * CHUNK       # per-scan tasks in flight (bounds memory)
BATCH_LOOKAHEAD = 2          # chunks whose batch calls are prefetched
SIZING_MAX_CANDIDATES = 25
HISTORY_MAX_PAGES = 10


@dataclass
class CollectOptions:
    languages: bool = False
    detail: bool = False
    config: bool = False
    iac_detail: bool = False
    sizing: bool = False
    source_loc: bool = False
    keep_source: str = None
    source_workers: int = 2
    workers: int = 8

    def __post_init__(self):
        if self.detail:  # --detail implies the per-scan sections of the report
            self.languages = self.config = self.iac_detail = self.sizing = True


def items_of(resp, *keys):
    """Extract a list of dicts from a response that is a list or wraps one under one of `keys`."""
    if isinstance(resp, list):
        return resp
    if isinstance(resp, dict):
        for k in keys:
            if isinstance(resp.get(k), list):
                return resp[k]
        for v in resp.values():
            if isinstance(v, list) and v and isinstance(v[0], dict):
                return v
    return []


def err_text(endpoint, exc):
    return f"{endpoint}: {exc.status or exc.message}"


def ok(data, endpoint):
    """Validate a payload returned by HttpClient.fetch (which already raises ApiError for HTTP >= 400)."""
    if data is not None and not isinstance(data, (dict, list)):
        raise ApiError(None, "unexpected payload type", endpoint)
    return data


def fetch_sast_metadata(client, scan_ids):
    """Batch sast-metadata (<= 50 ids). Falls back to one call per scan if the batch call fails.
    Returns (meta {id: dict}, missing set, errors {id: [text]})."""
    meta, missing, errors = {}, set(), {}
    try:
        resp = ok(client.fetch("sast-metadata", {"scan-ids": list(scan_ids)}), "sast-metadata")
        for m in items_of(resp, "scans", "scansMetadata", "metadata", "items"):
            if m.get("scanId"):
                meta[m["scanId"]] = m
        if isinstance(resp, dict):
            missing = set(resp.get("missing") or [])
        missing |= {s for s in scan_ids if s not in meta}
        return meta, missing, errors
    except ApiError:
        pass
    meta, missing = {}, set()
    for sid in scan_ids:  # one bad id must not blank the others
        try:
            m = ok(client.fetch(f"sast-metadata/{sid}"), "sast-metadata/{id}")
            if isinstance(m, dict) and m:
                meta[sid] = m
            else:
                missing.add(sid)
        except ApiError as e:
            if e.status == 404:
                missing.add(sid)
            else:
                errors.setdefault(sid, []).append(err_text("sast-metadata", e))
    return meta, missing, errors


class _Once:
    """Thread-safe load-once cache (errors are cached too)."""

    def __init__(self):
        self._lock = threading.Lock()
        self._items = {}

    def get(self, key, loader):
        with self._lock:
            entry = self._items.setdefault(key, {"lock": threading.Lock(), "done": False})
        with entry["lock"]:
            if not entry["done"]:
                try:
                    entry["value"] = loader()
                except Exception as e:  # noqa: BLE001
                    entry["error"] = e
                entry["done"] = True
        if "error" in entry:
            raise entry["error"]
        return entry["value"]


class BatchData:
    def __init__(self):
        self.scans, self.meta, self.versions, self.summaries = {}, {}, {}, {}
        self.missing = set()
        self.errors = {}        # scan id -> [text]
        self.chunk_errors = []  # applies to every scan in the chunk

    def add_error(self, endpoint, exc, ids=None):
        text = err_text(endpoint, exc)
        if ids is None:
            self.chunk_errors.append(text)
        else:
            for i in ids:
                self.errors.setdefault(i, []).append(text)


class CollectScans(Operation):
    def __init__(self, config, auth_manager, client, options, scan_ids, on_record, progress=None):
        super().__init__(config, auth_manager)
        self.client = client
        self.opt = options
        self.scan_ids = list(scan_ids)
        self.on_record = on_record
        self.progress = progress
        self._history = _Once()
        self._meta_cache = {}
        self._meta_lock = threading.Lock()
        self._source_pool = None

    # ------------------------------------------------------------ batch stage
    def _batch(self, chunk):
        """The <= 4 batch calls for up to 50 scans. Never raises."""
        d = BatchData()
        client = self.client
        try:
            resp = ok(client.fetch("scans", {"scan-ids": chunk, "limit": len(chunk)}), "scans")
            for s in items_of(resp, "scans"):
                d.scans[s.get("id")] = s
        except ApiError as e:
            d.add_error("scans", e)
        sast_ids = [i for i in chunk
                    if "sast" in [str(x).lower() for x in (d.scans.get(i) or {}).get("engines", ["sast"])]]
        if sast_ids:
            try:
                d.meta, d.missing, d.errors = fetch_sast_metadata(client, sast_ids)
            except Exception as e:  # noqa: BLE001
                d.add_error("sast-metadata", ApiError(None, str(e)), sast_ids)
            try:
                resp = ok(client.fetch("sast-metadata/engine-version", {"scan-ids": sast_ids}),
                          "sast-metadata/engine-version")
                for v in items_of(resp, "scans", "versions", "engineVersions"):
                    if v.get("scanId"):
                        d.versions[v["scanId"]] = v.get("engineVersion")
            except ApiError as e:
                d.add_error("sast-metadata/engine-version", e, sast_ids)
        try:
            resp = ok(client.fetch("scan-summary", {
                "scan-ids": chunk, "include-queries": False,
                "include-status-counters": True, "include-severity-status": True}), "scan-summary")
            for s in items_of(resp, "scansSummaries"):
                d.summaries[s.get("scanId") or s.get("scanID")] = s
        except ApiError as e:
            d.add_error("scan-summary", e)
        return d

    # ------------------------------------------------------------ per-scan stage
    @staticmethod
    def _call(rec, endpoint, fn):
        try:
            return fn()
        except ApiError as e:
            rec["errors"].append(err_text(endpoint, e))
        except Exception as e:  # noqa: BLE001  a failed sub-call never drops the record
            rec["errors"].append(f"{endpoint}: {type(e).__name__}: {e}")
        return None

    def _one(self, sid, d):
        rec = model.new_record(sid)
        try:
            self._build(rec, sid, d)
        except Exception as e:  # noqa: BLE001
            rec["errors"].append(f"internal: {type(e).__name__}: {e}")
        return model.finalize(rec)

    def _build(self, rec, sid, d):
        client = self.client
        rec["errors"].extend(d.chunk_errors)
        rec["errors"].extend(d.errors.get(sid, []))
        scan = d.scans.get(sid)
        if scan:
            model.apply_scan(rec, scan)
        elif not d.chunk_errors:
            rec["errors"].append("scans: not found")
        sast_known = (not scan) or "sast" in rec["engines"]
        meta = d.meta.get(sid)
        if sast_known and meta:
            model.apply_sast_meta(rec, meta)
            rec["sast"]["engine_version"] = d.versions.get(sid)
            s = rec["sast"]
            if s["is_incremental"] or s["incremental_cancelled"] or self.opt.detail:
                det = self._call(rec, "sast-metadata/{id}",
                                 lambda: ok(client.fetch(f"sast-metadata/{sid}"), "sast-metadata/{id}"))
                if isinstance(det, dict):
                    model.apply_sast_detail(rec, det)
            if self.opt.languages:
                m = self._call(rec, "sast-metadata/{id}/metrics",
                               lambda: ok(client.fetch(f"sast-metadata/{sid}/metrics"), "sast-metadata/{id}/metrics"))
                if isinstance(m, dict):
                    model.apply_metrics(rec, m)
        summary = d.summaries.get(sid)
        if summary:
            model.apply_summary(rec, summary)
        elif scan and not any(e.startswith("scan-summary") for e in rec["errors"]):
            rec["errors"].append("scan-summary: no summary returned")
        if self.opt.config and rec["project_id"]:
            items = self._call(rec, "configuration/scan", lambda: ok(client.fetch(
                "configuration/scan", {"project-id": rec["project_id"], "scan-id": sid}), "configuration/scan"))
            if items is not None:
                model.apply_config(rec, items)
        if self.opt.iac_detail and "kics" in rec["engines"]:
            res = self._call(rec, "kics-results", lambda: list(client.paginate(
                "kics-results", "results", {"scan-id": sid}, limit=1000)))
            if res is not None:
                model.apply_kics_detail(rec, res)
        model.apply_sizing_default(rec, self.opt.sizing)
        if self.opt.sizing and model.is_incremental_mode(rec):
            found = self._call(rec, "sizing", lambda: self._last_full(rec))
            if found is not None:
                model.apply_last_full(rec, found or None)
        if self.opt.source_loc:
            self._source(rec, sid)

    # ------------------------------------------------------------ sizing
    def _history_for(self, project_id, branch):
        def load():
            out = []
            params = {"project-id": project_id, "branch": branch, "statuses": ["Completed"], "sort": "-created_at"}
            for s in self.client.paginate("scans", "scans", params, limit=500, max_pages=HISTORY_MAX_PAGES):
                if s.get("projectId") != project_id or (branch and s.get("branch") != branch):
                    continue
                if "sast" not in [str(e).lower() for e in s.get("engines") or []]:
                    continue
                out.append((s["id"], model.parse_ts(s.get("createdAt"))))
            return out
        return self._history.get((project_id, branch), load)

    def _last_full(self, rec):
        """(scan_id, loc) of the newest older full scan, or () if none within the look-back."""
        created = model.parse_ts(rec["created_at"])
        if created is None:
            return ()
        hist = self._history_for(rec["project_id"], rec["branch"])
        cands = [sid for sid, ts in hist if ts is not None and ts < created][:SIZING_MAX_CANDIDATES]
        if not cands:
            return ()
        with self._meta_lock:
            todo = [c for c in cands if c not in self._meta_cache]
        if todo:
            meta, missing, _errors = fetch_sast_metadata(self.client, todo)
            with self._meta_lock:
                for sid, m in meta.items():
                    full = not m.get("isIncremental") or bool(m.get("isIncrementalCanceled"))
                    self._meta_cache[sid] = (m.get("loc"), full)
                for sid in missing:
                    self._meta_cache[sid] = None
        with self._meta_lock:
            cached = [(c, self._meta_cache.get(c)) for c in cands]
        for sid, entry in cached:  # newest first
            if entry and entry[1] and entry[0] is not None:
                return (sid, int(entry[0]))
        return ()

    # ------------------------------------------------------------ source loc
    def _source(self, rec, sid):
        def run():
            return source_loc.source_loc_for_scan(self.client, sid, self.opt.keep_source)
        result, error = self._source_pool.submit(run).result()
        if error:
            rec["errors"].append(error)
        else:
            rec["source_loc"] = result

    # ------------------------------------------------------------ driver
    def execute(self):
        chunks = [self.scan_ids[i:i + CHUNK] for i in range(0, len(self.scan_ids), CHUNK)]
        if not chunks:
            return
        workers = max(1, min(self.opt.workers, 32))
        self._source_pool = ThreadPoolExecutor(max_workers=max(1, self.opt.source_workers),
                                               thread_name_prefix="source")
        pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="scan")
        batch_pool = ThreadPoolExecutor(max_workers=BATCH_LOOKAHEAD, thread_name_prefix="batch")
        try:
            pending, state, active = deque(), {"next": 0}, set()

            def top_up():
                while len(pending) < BATCH_LOOKAHEAD and state["next"] < len(chunks):
                    chunk = chunks[state["next"]]
                    pending.append((chunk, batch_pool.submit(self._batch, chunk)))
                    state["next"] += 1

            top_up()
            while pending or active:
                while pending and (not active or len(active) + len(pending[0][0]) <= MAX_ACTIVE):
                    chunk, fut = pending.popleft()
                    top_up()
                    data = fut.result()
                    active.update(pool.submit(self._one, sid, data) for sid in chunk)
                done, active = wait(active, return_when=FIRST_COMPLETED)
                for f in done:
                    self.on_record(f.result())
                    if self.progress:
                        self.progress.tick()
        finally:
            batch_pool.shutdown(wait=False, cancel_futures=True)
            pool.shutdown(wait=False, cancel_futures=True)
            self._source_pool.shutdown(wait=False, cancel_futures=True)
