import pytest
from conftest import FakeClient, install_standard, scan_payload, sid

from src import model
from src.operations.collect import CollectOptions, CollectScans
from src.utils.http import ApiError


def run(client, ids, **opts):
    out = []
    CollectScans(None, None, client, CollectOptions(**opts), ids, out.append).execute()
    return {r["scan_id"]: r for r in out}


@pytest.mark.parametrize("n,batches", [(50, 1), (51, 2)])
def test_chunking_and_calls_per_chunk(n, batches):
    c = FakeClient()
    ids = install_standard(c, n)
    recs = run(c, ids)
    assert len(recs) == n
    for ep in ("scans", "sast-metadata", "sast-metadata/engine-version", "scan-summary"):
        assert c.count(ep) == batches
    assert all(len(p["scan-ids"]) <= 50 for path, p in c.calls)


def test_headline_fields_and_zero_blocks_and_timestamps():
    c = FakeClient()
    ids = install_standard(c, 1)
    r = run(c, ids)[ids[0]]
    assert r["sast"]["loc"] == 1000 and r["sast"]["scan_mode"] == "full"
    assert r["timing"]["duration_s"] == 240.0 and r["timing"]["engines"]["sast"] == 120.0
    assert r["iac"]["files_scanned"] == 7 and r["iac"]["findings"] == 3
    assert "sca" not in r["findings"] and r["sca"]["packages"] is None  # engine did not run -> null, not 0
    assert r["findings"]["sast"]["by_status"] == {"NEW": 5}
    assert r["errors"] == []
    flat = model.flatten(r)
    assert "filesScanned" not in str(flat) and flat["sast_loc"] == 1000


def test_timestamp_nine_fraction_digits():
    assert model.parse_ts("2024-05-01T10:00:00.123456789Z").microsecond == 123456
    assert model.parse_ts("2024-05-01T10:00:00.1234567+00:00") is not None
    assert model.parse_ts("garbage") is None


def test_missing_sast_metadata_is_not_error():
    c = FakeClient()
    ids = install_standard(c, 1, engines=("sca",))
    r = run(c, ids)[ids[0]]
    assert r["sast"]["scan_mode"] == "no SAST" and r["errors"] == []
    assert c.count("sast-metadata") == 0


def test_batch_failure_falls_back_per_scan_one_bad_id():
    c = FakeClient()
    ids = install_standard(c, 3)
    c.routes = [(rx, h) for rx, h in c.routes if rx.pattern != "sast-metadata$"]
    c.route("sast-metadata", lambda p, m: ApiError(500, "boom", "sast-metadata"))

    def single(p, m):
        s = m.group(1)
        if s == ids[1]:
            return ApiError(500, "bad", "x")
        return {"scanId": s, "loc": 42, "fileCount": 1, "queryPreset": "P", "isIncremental": False}
    c.route("sast-metadata/([^/]+)", single)
    recs = run(c, ids)
    assert recs[ids[0]]["sast"]["loc"] == 42 and recs[ids[2]]["sast"]["loc"] == 42
    assert recs[ids[1]]["sast"]["loc"] is None
    assert any(e.startswith("sast-metadata") for e in recs[ids[1]]["errors"])
    assert recs[ids[0]]["errors"] == []


def test_404_recorded_in_errors_and_record_kept():
    c = FakeClient()
    ids = install_standard(c, 1)
    c.routes = [(rx, h) for rx, h in c.routes if rx.pattern != "scan-summary$"]
    r = run(c, ids)[ids[0]]
    assert "scan-summary: 404" in r["errors"] and r["sast"]["loc"] == 1000


def test_metrics_null_failed_loc_dropped():
    c = FakeClient()
    ids = install_standard(c, 1)
    c.route("sast-metadata/[^/]+/metrics", lambda p, m: {
        "totalScannedLoc": 990, "successfullLocPerLanguage": {"Java": 900, "Python": 90},
        "failedLocPerLanguage": {"null": None}, "scannedFilesPerLanguage": {"Java": {"goodFiles": 5}},
        "fileCountOfDetectedButNotScannedLanguages": {"Go": 2}, "memoryPeak": 512.5})
    r = run(c, ids, languages=True)[ids[0]]
    langs = {x["language"]: x for x in r["sast"]["languages"]}
    assert set(langs) == {"Java", "Python"} and langs["Java"]["files_good"] == 5
    assert r["sast"]["scanned_loc"] == 990 and r["sast"]["languages_not_scanned"] == [{"language": "Go", "files": 2}]
    assert model.flatten(r)["languages"] == "Java=900;Python=90"


def test_incremental_walks_back_to_last_full():
    c = FakeClient()
    ids = install_standard(c, 1, incremental={sid(1)}, loc=50)
    c.routes = [(rx, h) for rx, h in c.routes if rx.pattern not in ("scans$",)]
    hist = {sid(1): "2024-05-04T00:00:00Z", sid(2): "2024-05-03T00:00:00Z", sid(3): "2024-05-02T00:00:00Z",
            sid(4): "2024-05-01T00:00:00Z"}

    def scans(p, m):
        if "scan-ids" in p:
            return {"scans": [scan_payload(1, created=hist[sid(1)])]}
        return {"scans": [scan_payload(i, created=hist[sid(i)]) for i in (1, 2, 3, 4)]}
    c.route("scans", scans)
    c.routes.insert(0, (c.routes.pop()[0], scans))

    def meta(p, m):
        full = {sid(4): 7000}
        return {"scans": [{"scanId": s, "loc": full.get(s, 10), "isIncremental": s not in full,
                           "isIncrementalCanceled": False} for s in p["scan-ids"]], "missing": []}
    c.routes = [(rx, h) for rx, h in c.routes if rx.pattern != "sast-metadata$"]
    c.route("sast-metadata", meta)
    c.route("sast-metadata/[^/]+", lambda p, m: {"baseId": sid(4), "addedFilesCount": 1})
    r = run(c, ids, sizing=True)[ids[0]]
    assert r["sast"]["scan_mode"] == "incremental" and r["sast"]["base_scan_id"] == sid(4)
    assert r["sizing"]["last_full_scan_id"] == sid(4) and r["sizing"]["sizing_loc"] == 7000


def test_incremental_no_full_found_notes_undercount():
    c = FakeClient()
    ids = install_standard(c, 1, incremental={sid(1)}, loc=50)
    c.route("sast-metadata/[^/]+", lambda p, m: {})
    r = run(c, ids, sizing=True)[ids[0]]
    # install_standard has no history route for the project listing -> error recorded, still undercount-safe
    assert r["sizing"]["sizing_loc"] is None or r["sizing"]["sizing_note"]


def test_totals_sizing_one_per_project_branch():
    t = model.Totals()
    for i, (ts, loc) in enumerate([("2024-01-01T00:00:00Z", 100), ("2024-02-01T00:00:00Z", 120)]):
        r = model.new_record(sid(i))
        r.update(project_id="p", branch="main", created_at=ts)
        r["sast"].update(scan_mode="full", loc=loc)
        r["sizing"]["sizing_loc"] = loc
        t.add(r)
    assert t.sizing_loc == 120 and t.sast_loc == 220
