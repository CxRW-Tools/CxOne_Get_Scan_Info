"""Resolve the set of scan ids to collect from the chosen input source."""
import re
import sys
from datetime import datetime

from src.operations.base import Operation
from src.utils import io as cxio
from src.utils.http import ApiError

PROJECT_CHUNK = 50
MAX_LATEST_PAGES = 20  # per 50-project chunk, when hunting for each project's latest matching scan


def _warn(msg):
    print(f"warning: {msg}", file=sys.stderr)


def _date(value, end=False):
    """Accept 2024-01-31 or a full ISO timestamp; returns an ISO string for from-date/to-date."""
    if not value:
        return None
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        return value + ("T23:59:59Z" if end else "T00:00:00Z")
    return value


class SelectScans(Operation):
    def __init__(self, config, auth_manager, client, args):
        super().__init__(config, auth_manager)
        self.client = client
        self.args = args
        self._projects = {}  # cache: project id -> project dict

    # -- projects ------------------------------------------------------
    def _load_projects(self):
        a = self.args
        if a.all_projects:
            for p in self.client.paginate("projects", "projects", {}, limit=500):
                self._projects[p["id"]] = p
            return
        names = list(a.project_names or [])
        if a.projects_file:
            names += cxio.read_names_file(a.projects_file)
        names = list(dict.fromkeys(n for n in names if n))
        found = set()
        for i in range(0, len(names), PROJECT_CHUNK):
            chunk = names[i:i + PROJECT_CHUNK]
            for p in self.client.paginate("projects", "projects", {"names": chunk}, limit=500):
                if p.get("name") in chunk:  # exact match only
                    self._projects[p["id"]] = p
                    found.add(p["name"])
        for n in names:
            if n not in found:
                _warn(f"project not found: {n}")

    # -- scan filters --------------------------------------------------
    def _scan_ok(self, scan, statuses, engine, branch):
        if statuses and scan.get("status") not in statuses:
            return False
        if engine and engine not in [str(e).lower() for e in scan.get("engines") or []]:
            return False
        if branch and scan.get("branch") != branch:
            return False
        return True

    def _list_params(self, chunk_ids, statuses, branch):
        a = self.args
        return {"project-ids": ",".join(chunk_ids), "statuses": statuses or None, "sort": "-created_at",
                "branch": branch, "from-date": _date(a.since), "to-date": _date(a.until, end=True)}

    def _project_scans(self, chunk_ids, statuses, branch, max_pages=None):
        """Scans newest-first for up to 50 projects. project-id filtering is also re-checked client-side."""
        wanted = set(chunk_ids)
        for scan in self.client.paginate("scans", "scans", self._list_params(chunk_ids, statuses, branch),
                                         limit=500, max_pages=max_pages):
            if scan.get("projectId") in wanted:
                yield scan

    def _select_from_projects(self):
        a = self.args
        statuses = [s.strip() for s in a.statuses.split(",") if s.strip()]
        engine = a.engine.lower() if a.engine else None
        self._load_projects()
        ids = list(self._projects)
        selected = []
        for i in range(0, len(ids), PROJECT_CHUNK):
            chunk = ids[i:i + PROJECT_CHUNK]
            if a.mode == "all":
                for scan in self._project_scans(chunk, statuses, a.branch):
                    if self._scan_ok(scan, statuses, engine, a.branch):
                        selected.append(scan["id"])
            else:
                selected.extend(self._latest_per_project(chunk, statuses, engine))
        return selected

    def _latest_per_project(self, chunk, statuses, engine):
        a = self.args
        picks, first_seen = {}, {}
        remaining = set(chunk)
        for scan in self._project_scans(chunk, statuses, a.branch, max_pages=MAX_LATEST_PAGES):
            pid = scan["projectId"]
            if pid in picks or not self._scan_ok(scan, statuses, engine, a.branch):
                continue
            first_seen.setdefault(pid, scan)
            if a.primary_branch:
                main = self._projects[pid].get("mainBranch")
                if main and scan.get("branch") != main:
                    continue
            picks[pid] = scan
            remaining.discard(pid)
            if not remaining:
                break
        if a.primary_branch:  # fall back to the latest scan's branch where mainBranch is unset/unused
            for pid, scan in first_seen.items():
                picks.setdefault(pid, scan)
        for pid in chunk:
            if pid not in picks:
                _warn(f"no matching scan for project {self._projects[pid].get('name', pid)}")
        return [picks[pid]["id"] for pid in chunk if pid in picks]

    # -- entry point ---------------------------------------------------
    def execute(self):
        a = self.args
        if a.scan_ids:
            raw = [t.strip() for chunk in a.scan_ids for t in chunk.split(",") if t.strip()]
        elif a.scan_ids_file:
            raw = cxio.read_scan_ids_file(a.scan_ids_file)
        else:
            try:
                raw = self._select_from_projects()
            except ApiError as e:
                raise RuntimeError(f"could not list scans: {e}") from e
        ids = list(dict.fromkeys(raw))
        print(f"Selected {len(ids)} scan(s)", file=sys.stderr)
        return ids
