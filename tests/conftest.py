import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.utils.http import ApiError, HttpClient  # noqa: E402


def sid(n):
    return f"00000000-0000-0000-0000-{n:012d}"


class FakeClient(HttpClient):
    """Fake HTTP layer: routes are (regex, handler(params, match)); inherits paginate()/encode_params()."""

    def __init__(self):
        self.base_host = "example.ast.checkmarx.net"
        self.routes = []
        self.calls = []

    def route(self, pattern, handler):
        import re
        self.routes.append((re.compile(pattern + "$"), handler))

    def fetch(self, path, params=None, **kw):
        self.calls.append((path, params))
        for rx, handler in self.routes:
            m = rx.match(path)
            if m:
                out = handler(params or {}, m)
                if isinstance(out, Exception):
                    raise out
                return out
        raise ApiError(404, "no route", path)

    def count(self, prefix):
        return sum(1 for p, _ in self.calls if p == prefix)


def scan_payload(i, engines=("sast", "kics"), project="p1", branch="main", created="2024-05-01T10:00:00.1234567Z"):
    return {"id": sid(i), "projectId": project, "projectName": "Proj", "branch": branch, "status": "Completed",
            "createdAt": created, "updatedAt": "2024-05-01T10:05:00.000000000Z", "engines": list(engines),
            "initiator": "u", "sourceType": "zip", "sourceOrigin": "cli",
            "metadata": {"Handler": {"GitHandler": {"repo_url": "https://g/x.git"}}},
            "statusDetails": [{"name": "general", "status": "Completed", "startDate": "2024-05-01T10:00:00Z",
                               "endDate": "2024-05-01T10:04:00Z"},
                              {"name": "sast", "status": "Completed", "startDate": "2024-05-01T10:01:00Z",
                               "endDate": "2024-05-01T10:03:00Z", "loc": 999}]}


def summary_payload(i, kics_total=3, ran=True):
    zero = {"totalCounter": 0, "filesScannedCounter": 0, "severityCounters": [], "statusCounters": []}
    return {"scanId": sid(i),
            "sastCounters": {"totalCounter": 5, "filesScannedCounter": 0,
                             "severityCounters": [{"severity": "HIGH", "counter": 5}],
                             "statusCounters": [{"status": "new", "counter": 5}]},
            "kicsCounters": {"totalCounter": kics_total, "filesScannedCounter": 7,
                             "severityCounters": [{"severity": "LOW", "counter": kics_total}],
                             "platformCounters": [{"platform": "Terraform", "counter": 3}]},
            "scaCounters": dict(zero), "scaPackagesCounters": dict(zero), "containersCounters": dict(zero),
            "microEnginesCounters": dict(zero), "apiSecCounters": dict(zero)}


def install_standard(client, n, engines=("sast", "kics"), incremental=(), loc=1000):
    """Routes for scans sid(1..n)."""
    ids = [sid(i) for i in range(1, n + 1)]
    client.route("scans", lambda p, m: {"scans": [scan_payload(int(s[-12:]), engines) for s in p["scan-ids"]
                                                  if s in ids]})
    client.route("sast-metadata", lambda p, m: {
        "scans": [{"scanId": s, "loc": loc, "fileCount": 10, "queryPreset": "Default",
                   "isIncremental": s in incremental, "isIncrementalCanceled": False}
                  for s in p["scan-ids"] if "sast" in engines], "missing": []})
    client.route("sast-metadata/engine-version", lambda p, m: [{"scanId": s, "engineVersion": "9.7"}
                                                               for s in p["scan-ids"]])
    client.route("scan-summary", lambda p, m: {"scansSummaries": [summary_payload(int(s[-12:]))
                                                                  for s in p["scan-ids"]]})
    return ids
