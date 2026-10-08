"""Input readers and streaming output writers."""
import contextlib
import csv
import io
import json
import os
import re
import sys

from src.model import flatten

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
ID_COLUMNS = {"scanid", "id"}
NAME_COLUMNS = {"projectname", "name"}


# All filesystem access to operator-supplied paths goes through these two helpers, which normalise
# the path first. (The paths come from the CLI user; the tool is meant to read/write what they name.)
@contextlib.contextmanager
def _file(path, mode, **kwargs):
    with open(os.path.abspath(os.path.normpath(path)), mode=mode, **kwargs) as f:
        yield f


def _size(path):
    full = os.path.abspath(os.path.normpath(path))
    return os.path.getsize(full) if os.path.isfile(full) else -1  # -1: missing


# ---------------------------------------------------------------- readers
def _read_text(path):
    if path == "-":
        return sys.stdin.read()
    with _file(path, "r", encoding="utf-8-sig") as f:
        return f.read()


def _kind(path, text):
    ext = os.path.splitext(path)[1].lower() if path != "-" else ""
    if ext in (".json", ".csv", ".txt"):
        return ext[1:]
    stripped = text.lstrip()
    if stripped[:1] in ("[", "{"):
        return "json"
    first = stripped.splitlines()[0] if stripped else ""
    if "," in first:
        return "csv"
    return "txt"


def _norm(h):
    return re.sub(r"[^a-z]", "", h.lower())


def _read_values(path, aliases, json_keys, strip_comments):
    text = _read_text(path)
    kind = _kind(path, text)
    out = []
    if kind == "txt":
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip() if strip_comments else line.strip()
            if line and not line.startswith("#"):
                out.append(line)
    elif kind == "csv":
        rows = [r for r in csv.reader(io.StringIO(text)) if r and any(c.strip() for c in r)]
        if rows:
            col = next((i for i, h in enumerate(rows[0]) if _norm(h) in aliases), None)
            if col is not None:
                rows = rows[1:]
            idx = col or 0
            out = [r[idx].strip() for r in rows if len(r) > idx and r[idx].strip()]
    else:
        data = json.loads(text)
        if isinstance(data, dict):
            data = next((v for v in data.values() if isinstance(v, list)), [])
        for item in data:
            if isinstance(item, dict):
                item = next((item[k] for k in json_keys if item.get(k)), None)
            if item:
                out.append(str(item).strip())
    return out


def read_scan_ids_file(path):
    ids = []
    for v in _read_values(path, ID_COLUMNS, ("id", "scanId", "scan_id"), strip_comments=True):
        if UUID_RE.match(v):
            ids.append(v)
        else:
            print(f"warning: skipping non-UUID scan id {v!r}", file=sys.stderr)
    return ids


def read_names_file(path):
    return _read_values(path, NAME_COLUMNS, ("name", "project_name", "projectName"), strip_comments=False)


def read_done_ids(path, fmt):
    """Scan ids already present in a jsonl/csv output (tolerates a truncated last line)."""
    done = set()
    if _size(path) <= 0:
        return done
    with _file(path, "r", encoding="utf-8", newline="") as f:
        if fmt == "jsonl":
            for line in f:
                try:
                    sid = json.loads(line).get("scan_id")
                except (ValueError, AttributeError):
                    continue
                if sid:
                    done.add(sid)
        else:
            for row in csv.DictReader(f):
                if row.get("scan_id"):
                    done.add(row["scan_id"])
    return done


def csv_header(path):
    if _size(path) <= 0:
        return None
    with _file(path, "r", encoding="utf-8", newline="") as f:
        return next(csv.reader(f), None)


def _ensure_trailing_newline(path):
    if _size(path) > 0:
        with _file(path, "rb+") as f:
            f.seek(-1, os.SEEK_END)
            if f.read(1) not in (b"\n", b"\r"):
                f.write(b"\n")


@contextlib.contextmanager
def open_output(path, resume=False):
    """Yield the output stream: stdout, or a file (append when resuming)."""
    if not path:
        yield sys.stdout
        return
    if resume:
        _ensure_trailing_newline(path)
    with _file(path, "a" if resume else "w", encoding="utf-8", newline="") as f:
        yield f


# ---------------------------------------------------------------- writers
class Writer:
    def __init__(self, stream, fields, rows=True):
        self.stream, self.fields, self.rows = stream, fields, rows

    def write(self, rec):
        if self.rows:
            self._write(rec)
            self.stream.flush()

    def _write(self, rec):
        raise NotImplementedError

    def close(self, summary):
        pass

    def _summary_only(self, summary):
        if not self.rows:
            self.stream.write(json.dumps({"summary": summary}, indent=2) + "\n")


class JsonlWriter(Writer):
    def _write(self, rec):
        self.stream.write(json.dumps(rec, ensure_ascii=False) + "\n")

    def close(self, summary):
        self._summary_only(summary)


class CsvWriter(Writer):
    def __init__(self, stream, fields, rows=True, write_header=True):
        super().__init__(stream, fields, rows)
        self._csv = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
        if write_header and rows:
            self._csv.writeheader()

    def _write(self, rec):
        self._csv.writerow(flatten(rec, self.fields))

    def close(self, summary):
        self._summary_only(summary)


class JsonWriter(Writer):
    """Buffers every record: the {"summary", "scans"} document is written at the end."""

    def __init__(self, stream, fields, rows=True):
        super().__init__(stream, fields, rows)
        self.buffer = []
        if rows:
            print("warning: --format json buffers all records in memory; prefer jsonl for large runs",
                  file=sys.stderr)

    def _write(self, rec):
        self.buffer.append(rec)

    def close(self, summary):
        doc = {"summary": summary}
        if self.rows:
            doc["scans"] = self.buffer
        json.dump(doc, self.stream, indent=2, ensure_ascii=False)
        self.stream.write("\n")
        self.stream.flush()


TABLE_COLUMNS = [  # (field, header, width, align)
    ("project_name", "Project", 28, "<"), ("branch", "Branch", 16, "<"), ("scan_id", "Scan", 8, "<"),
    ("created_at", "Date", 10, "<"), ("scan_mode", "Mode", 12, "<"), ("sast_loc", "SAST LOC", 12, ">"),
    ("sast_files", "Files", 8, ">"), ("sizing_loc", "Sizing LOC", 12, ">"),
    ("iac_files_scanned", "IaC files", 9, ">"), ("sca_packages", "SCA pkgs", 8, ">"), ("preset", "Preset", 18, "<"),
]


def _cell(field, value, width, align):
    if isinstance(value, (int, float)):
        text = f"{value:,.0f}" if float(value).is_integer() else f"{value:,.1f}"
    else:
        text = str(value)
        if field == "scan_id":
            text = text[:8]
        elif field == "created_at":
            text = text[:10]
    if len(text) > width:
        text = text[: width - 1] + "~"
    return f"{text:{align}{width}}"


class TableWriter(Writer):
    def __init__(self, stream, fields, rows=True, custom_fields=False, detail=False):
        super().__init__(stream, fields, rows)
        self.detail = detail
        if custom_fields:
            self.columns = [(f, f, max(12, min(len(f), 24)), "<") for f in fields]
        else:
            self.columns = TABLE_COLUMNS
        self.fields = [c[0] for c in self.columns]
        self._header_done = False

    def _write(self, rec):
        if self.detail:
            self.stream.write(render_detail(rec) + "\n")
            return
        if not self._header_done:
            head = " | ".join(f"{h:{a}{w}}" for _, h, w, a in self.columns)
            self.stream.write(head + "\n" + "-+-".join("-" * w for _, _, w, _ in self.columns) + "\n")
            self._header_done = True
        flat = flatten(rec, self.fields)
        self.stream.write(" | ".join(_cell(f, flat[f], w, a) for f, _, w, a in self.columns) + "\n")

    def close(self, summary):
        s = summary
        lines = ["", "Totals", "------",
                 f"Scans:                 {s['scans']:,}",
                 f"Scans with SAST:       {s['scans_with_sast']:,}",
                 f"Incremental scans:     {s['incremental_scans']:,}",
                 f"Sum of SAST LOC:       {s['sum_sast_loc']:,}  (incremental LOC covers re-analysed code only)",
                 f"Sum of sizing LOC:     {s['sum_sizing_loc']:,}  (latest scan per project+branch)"]
        if s["unsized_incremental_scans"]:
            lines.append(f"  note: {s['unsized_incremental_scans']} incremental scan(s) not sized; use --sizing")
        lines += [f"IaC files scanned:     {s['iac_files_scanned']:,}", f"SCA packages:          {s['sca_packages']:,}"]
        if s["scans_with_errors"]:
            lines.append(f"Scans with errors:     {s['scans_with_errors']:,}")
        langs = s.get("language_loc_scanned")
        if langs is not None:
            lines.append("Per-language scanned LOC (sum over listed scans):")
            lines += [f"  {k:<24}{v:>14,}" for k, v in langs.items()]
        self.stream.write("\n".join(lines) + "\n")
        self.stream.flush()


def make_writer(fmt, stream, fields, rows=True, custom_fields=False, detail=False, write_header=True):
    if fmt == "jsonl":
        return JsonlWriter(stream, fields, rows)
    if fmt == "csv":
        return CsvWriter(stream, fields, rows, write_header=write_header)
    if fmt == "json":
        return JsonWriter(stream, fields, rows)
    return TableWriter(stream, fields, rows, custom_fields=custom_fields, detail=detail)


# ---------------------------------------------------------------- detail report
def _kv(d, indent="    "):
    return "\n".join(f"{indent}{k}: {v}" for k, v in (d or {}).items()) or f"{indent}(none)"


def _n(v):
    return f"{v:,}" if isinstance(v, int) else ("-" if v is None else str(v))


def render_detail(r):
    s, z, i, c, k = r["sast"], r["sizing"], r["iac"], r["sca"], r["containers"]
    L = [f"=== Scan {r['scan_id']} ===", "", "[Identity]",
         f"  Project: {r['project_name']} ({r['project_id']})", f"  Branch: {r['branch']}   Commit: {r['commit'] or '-'}",
         f"  Repo: {r['repo_url'] or '-'}", f"  Status: {r['status']}   Created: {r['created_at']}",
         f"  Initiator: {r['initiator']}   Source: {r['source_type']} / {r['source_origin']}",
         f"  Engines: {', '.join(r['engines']) or '-'}", "", "[Engine timeline]",
         f"  total: {_n(r['timing']['duration_s'])}s"]
    L += [f"  {e}: {_n(v)}s" for e, v in r["timing"]["engines"].items()]
    L += ["", "[SAST]", f"  Mode: {s['scan_mode']}   Preset: {s['preset'] or '-'}   Engine version: {s['engine_version'] or '-'}",
          f"  LOC (headline): {_n(s['loc'])}   Successfully parsed LOC: {_n(s['scanned_loc'])}   Files: {_n(s['files'])}",
          f"  Sizing LOC: {_n(z['sizing_loc'])}  last full: {z['last_full_scan_id'] or '-'} ({_n(z['last_full_loc'])})"
          + (f"  [{z['sizing_note']}]" if z["sizing_note"] else ""),
          f"  Base scan: {s['base_scan_id'] or '-'}  added/changed/deleted: {_n(s['files_added'])}/"
          f"{_n(s['files_changed'])}/{_n(s['files_deleted'])}  change %: {_n(s['change_pct'])}",
          f"  Memory peak (MB): {_n(s['memory_peak_mb'])}"]
    if s["languages"] is not None:
        L.append(f"  {'Language':<22}{'LOC ok':>10}{'LOC fail':>10}{'good':>8}{'partial':>9}{'bad':>6}")
        L += [f"  {x['language']:<22}{_n(x['loc_scanned']):>10}{_n(x['loc_failed']):>10}{_n(x['files_good']):>8}"
              f"{_n(x['files_partial']):>9}{_n(x['files_bad']):>6}" for x in s["languages"]]
        if s["languages_not_scanned"]:
            L.append("  Detected, not scanned: " + ", ".join(
                f"{x['language']}({_n(x['files'])})" for x in s["languages_not_scanned"]))
    L += ["", "[IaC (KICS)]", f"  Files scanned: {_n(i['files_scanned'])}   Findings: {_n(i['findings'])}",
          "  By severity:", _kv(i["by_severity"]), "  Platforms:", _kv(i["platforms"])]
    if i["files_with_findings"] is not None:
        L += [f"  Files with findings: {i['files_with_findings']}", "  Top files:", _kv(i["top_files"])]
    L += ["", "[SCA]", f"  Packages: {_n(c['packages'])}   Outdated: {_n(c['outdated'])}   Vulnerabilities: {_n(c['vulnerabilities'])}",
          "  By severity:", _kv(c["by_severity"]), "  Top licenses:", _kv(c["top_licenses"]),
          "", "[Containers]", f"  Packages: {_n(k['packages'])}   Vulnerable images: {_n(k['vulnerable_images'])}   Findings: {_n(k['findings'])}",
          "", "[Findings]"]
    for eng, f in r["findings"].items():
        L.append(f"  {eng:<13}{_n(f['total']):>8}   sev: {f['by_severity']}   status: {f['by_status']}")
    if r["config"] is not None:
        L += ["", "[Configuration]"] + [f"  {kk} = {v['value']}  ({v['origin']})" for kk, v in r["config"].items()]
    if r["source_loc"]:
        so = r["source_loc"]
        L += ["", "[Source LOC - local estimate]", f"  App code LOC: {_n(so.get('app_code_loc'))}   IaC LOC: {_n(so.get('iac_loc'))}"
              f" in {_n(so.get('iac_files'))} files"]
        L += [f"  {x['language']:<22}{x['files']:>7}{x['code']:>10}" for x in so.get("languages", [])]
        L += ["  IaC by platform:", _kv({p: v["loc"] for p, v in (so.get("iac_platforms") or {}).items()})]
    if r["errors"]:
        L += ["", "[Errors]"] + [f"  {e}" for e in r["errors"]]
    return "\n".join(L) + "\n"
