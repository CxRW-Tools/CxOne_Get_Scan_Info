import io
import json
import sys
from types import SimpleNamespace

from conftest import FakeClient, scan_payload, sid

from src import model
from src.operations.select_scans import SelectScans
from src.utils import io as cxio

IDS = [sid(1), sid(2), sid(3)]


def write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return str(p)


def test_txt_with_comments(tmp_path):
    p = write(tmp_path, "a.txt", f"# header\n{IDS[0]}\n\n{IDS[1]}  # inline\n")
    assert cxio.read_scan_ids_file(p) == IDS[:2]


def test_csv_named_column_and_first_column(tmp_path):
    assert cxio.read_scan_ids_file(write(tmp_path, "a.csv", f"name,scanId\nx,{IDS[0]}\ny,{IDS[1]}\n")) == IDS[:2]
    assert cxio.read_scan_ids_file(write(tmp_path, "b.csv", f"{IDS[0]},x\n{IDS[1]},y\n")) == IDS[:2]
    assert cxio.read_scan_ids_file(write(tmp_path, "c.csv", f"scan_id\n{IDS[2]}\n")) == [IDS[2]]


def test_json_list_and_objects(tmp_path):
    assert cxio.read_scan_ids_file(write(tmp_path, "a.json", json.dumps(IDS))) == IDS
    assert cxio.read_scan_ids_file(write(tmp_path, "b.json", json.dumps([{"id": IDS[0]}, {"scanId": IDS[1]}]))) == IDS[:2]


def test_stdin(monkeypatch):
    monkeypatch.setattr(sys, "stdin", io.StringIO("\n".join(IDS)))
    assert cxio.read_scan_ids_file("-") == IDS


def test_non_uuid_skipped(tmp_path):
    assert cxio.read_scan_ids_file(write(tmp_path, "a.txt", f"junk\n{IDS[0]}\n")) == [IDS[0]]


def test_scan_ids_arg_dedup():
    args = SimpleNamespace(scan_ids=[f"{IDS[0]},{IDS[1]}", IDS[0]], scan_ids_file=None)
    assert SelectScans(None, None, None, args).execute() == IDS[:2]


def project_args(**kw):
    base = dict(scan_ids=None, scan_ids_file=None, project_names=["P"], projects_file=None, all_projects=False,
                mode="latest", branch=None, primary_branch=False, statuses="Completed", since=None, until=None,
                engine=None)
    base.update(kw)
    return SimpleNamespace(**base)


def test_latest_per_project_uses_sort_and_project_ids_and_primary_branch():
    c = FakeClient()
    c.route("projects", lambda p, m: {"projects": [{"id": "p1", "name": "P", "mainBranch": "main"}]})
    seen = {}

    def scans(p, m):
        seen.update(p)
        return {"scans": [scan_payload(1, branch="dev"), scan_payload(2, branch="main"), scan_payload(3, branch="main")]}
    c.route("scans", scans)
    ids = SelectScans(None, None, c, project_args(primary_branch=True)).execute()
    assert ids == [sid(2)] and seen["sort"] == "-created_at" and seen["project-ids"] == "p1"
    assert "projectId" not in seen


def test_foreign_project_scans_ignored():
    c = FakeClient()
    c.route("projects", lambda p, m: {"projects": [{"id": "p1", "name": "P"}]})
    c.route("scans", lambda p, m: {"scans": [scan_payload(1, project="other"), scan_payload(2)]})
    assert SelectScans(None, None, c, project_args()).execute() == [sid(2)]


def rec(i, loc=10):
    r = model.new_record(sid(i))
    r["sast"].update(scan_mode="full", loc=loc, languages=[{"language": "Java", "loc_scanned": 5}])
    r["errors"] = ["a: 500", "b: 404"]
    return r


def test_resume_skips_done_jsonl_and_csv(tmp_path):
    p = tmp_path / "o.jsonl"
    p.write_text(json.dumps(rec(1)) + "\n" + '{"scan_id": "' + sid(2)[:10], encoding="utf-8")  # truncated last line
    assert cxio.read_done_ids(str(p), "jsonl") == {sid(1)}
    q = tmp_path / "o.csv"
    fields = model.default_fields()
    with cxio.open_output(str(q)) as s:
        w = cxio.make_writer("csv", s, fields)
        w.write(rec(1))
    assert cxio.read_done_ids(str(q), "csv") == {sid(1)}
    assert cxio.csv_header(str(q)) == fields
    with cxio.open_output(str(q), resume=True) as s:  # append without a second header
        cxio.make_writer("csv", s, fields, write_header=False).write(rec(2))
    assert sum(l.startswith("scan_id,") for l in q.read_text().splitlines()) == 1 and cxio.read_done_ids(str(q), "csv") == {sid(1), sid(2)}


def test_csv_flattening():
    flat = model.flatten(rec(1), ["scan_id", "sast_loc", "errors", "languages", "engines"])
    assert flat == {"scan_id": sid(1), "sast_loc": 10, "errors": "a: 500 | b: 404", "languages": "Java=5",
                    "engines": ""}


def test_table_writer_and_totals():
    out = io.StringIO()
    w = cxio.make_writer("table", out, model.default_fields())
    t = model.Totals()
    r = rec(1, 12345)
    r["sizing"]["sizing_loc"] = 12345
    t.add(r)
    w.write(r)
    w.close(t.to_dict())
    text = out.getvalue()
    assert "12,345" in text and "Sum of sizing LOC" in text
