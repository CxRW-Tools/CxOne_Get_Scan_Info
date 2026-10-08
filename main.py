#!/usr/bin/env python3
"""get_scan_info: read-only Checkmarx One scan statistics / LOC tool."""
import argparse
import sys

from src import __version__, model
from src.operations.collect import CollectOptions, CollectScans
from src.operations.select_scans import SelectScans
from src.utils import io as cxio
from src.utils.auth import AuthError, AuthManager
from src.utils.config import Config, ConfigError
from src.utils.http import ApiError, HttpClient
from src.utils.progress import Progress

DETAIL_LIMIT = 50


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Read-only CxOne scan statistics / LOC report")
    a = p.add_argument_group("auth (or CXONE_* env / .env)")
    a.add_argument("--env-file", metavar="PATH", help="Load CXONE_* settings from this file instead of .env")
    a.add_argument("--base-url", help="Region base URL, e.g. https://eu.ast.checkmarx.net")
    a.add_argument("--tenant-name", help="Tenant name")
    a.add_argument("--api-key", help="API key (refresh token)")
    a.add_argument("--iam-url", help="IAM base URL override (single-tenant/custom domains)")
    s = p.add_argument_group("scan selection (exactly one)").add_mutually_exclusive_group(required=True)
    s.add_argument("--scan-ids", nargs="+", metavar="ID", help="Scan ids, comma or space separated")
    s.add_argument("--scan-ids-file", metavar="PATH", help=".txt/.csv/.json file of scan ids, or - for stdin")
    s.add_argument("--project-names", nargs="+", metavar="NAME", help="Exact project names")
    s.add_argument("--projects-file", metavar="PATH", help=".txt/.csv/.json file of project names")
    s.add_argument("--all-projects", action="store_true")
    f = p.add_argument_group("project-based filters")
    f.add_argument("--mode", choices=("latest", "all"), default="latest")
    b = f.add_mutually_exclusive_group()
    b.add_argument("--branch")
    b.add_argument("--primary-branch", action="store_true")
    f.add_argument("--statuses", default="Completed")
    f.add_argument("--since", help="ISO date/time (from-date)")
    f.add_argument("--until", help="ISO date/time (to-date)")
    f.add_argument("--engine", help="Keep scans whose engines contain this (e.g. sast)")
    d = p.add_argument_group("collection")
    d.add_argument("--languages", action="store_true", help="Per-language LOC/file stats (1 call per scan)")
    d.add_argument("--detail", action="store_true", help="Full per-scan report (implies languages/config/iac-detail/sizing)")
    d.add_argument("--config", action="store_true", help="scan.config.* settings that ran")
    d.add_argument("--iac-detail", action="store_true", help="KICS result breakdown")
    d.add_argument("--sizing", action="store_true", help="Walk back to the last full scan for incremental scans")
    d.add_argument("--source-loc", action="store_true", help="Download snapshots and count lines locally (expensive)")
    d.add_argument("--keep-source", metavar="DIR", help="Keep extracted source under DIR")
    d.add_argument("--source-workers", type=int, default=2)
    o = p.add_argument_group("output")
    o.add_argument("--format", choices=("table", "json", "jsonl", "csv"))
    o.add_argument("--output", metavar="PATH")
    o.add_argument("--fields", help="Comma-separated columns for csv/table")
    o.add_argument("--summary-only", action="store_true")
    o.add_argument("--resume", action="store_true", help="Skip scan ids already in a jsonl/csv --output")
    o.add_argument("--force", action="store_true", help=f"Allow --detail for more than {DETAIL_LIMIT} scans")
    r = p.add_argument_group("runtime")
    r.add_argument("--workers", type=int, default=8, help="Threads for per-scan calls (max 32)")
    r.add_argument("--max-rps", type=float, default=None, help="Global request rate limit")
    r.add_argument("--debug", action="store_true")
    p.add_argument("--version", action="version", version=f"get-scan-info {__version__}")
    return p.parse_args(argv)


def fail(msg, code=1):
    print(f"Error: {msg}", file=sys.stderr)
    return code


def main(argv=None):
    args = parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    try:
        config = Config.from_args(args).resolve()
    except ConfigError as e:
        return fail(str(e))
    ok, err = config.validate()
    if not ok:
        return fail(f"configuration: {err}")
    print(f"Tenant: {config.tenant_name}  Base URL: {config.base_url}", file=sys.stderr)

    fmt = args.format or ("table" if sys.stdout.isatty() else "jsonl")
    if args.resume and not (args.output and fmt in ("jsonl", "csv")):
        return fail("--resume needs --output with --format jsonl or csv")
    workers = max(1, min(args.workers, 32))
    options = CollectOptions(languages=args.languages, detail=args.detail, config=args.config,
                             iac_detail=args.iac_detail, sizing=args.sizing, source_loc=args.source_loc,
                             keep_source=args.keep_source, source_workers=args.source_workers, workers=workers)
    if fmt == "table" and args.fields is None:
        fields = model.default_fields()
    elif args.fields:
        fields = [x.strip() for x in args.fields.split(",") if x.strip()]
        bad = [x for x in fields if x not in model.FIELD_PATHS]
        if bad:
            return fail(f"unknown field(s): {', '.join(bad)}")
    else:
        fields = model.default_fields(options.languages, options.config, options.iac_detail, options.source_loc)

    try:
        auth = AuthManager(config.base_url, config.tenant_name, config.api_key, config.iam_url, debug=config.debug)
        auth.ensure_authenticated()
        client = HttpClient(auth, config.base_url, workers=workers + args.source_workers,
                            max_rps=args.max_rps, debug=config.debug)
        scan_ids = SelectScans(config, auth, client, args).execute()
        if args.resume:
            done = cxio.read_done_ids(args.output, fmt)
            scan_ids = [s for s in scan_ids if s not in done]
            print(f"Resume: {len(done)} already present, {len(scan_ids)} to collect", file=sys.stderr)
        if args.detail and fmt == "table" and len(scan_ids) > DETAIL_LIMIT and not args.force:
            return fail(f"--detail is limited to {DETAIL_LIMIT} scans (got {len(scan_ids)}); use --force")

        totals = model.Totals(languages=options.languages)
        header = None
        if args.resume and fmt == "csv":
            header = cxio.csv_header(args.output)
            if header:
                fields = header
        with cxio.open_output(args.output, args.resume) as stream:
            writer = cxio.make_writer(fmt, stream, fields, rows=not args.summary_only,
                                      custom_fields=bool(args.fields), detail=args.detail,
                                      write_header=header is None)

            def on_record(rec):
                totals.add(rec)
                writer.write(rec)

            CollectScans(config, auth, client, options, scan_ids, on_record,
                         Progress(len(scan_ids))).execute()
            summary = totals.to_dict()
            writer.close(summary)
        if fmt in ("jsonl", "csv") and not args.summary_only and args.output:
            print(f"Done: {summary['scans']} scans, {summary['sum_sast_loc']:,} SAST LOC, "
                  f"{summary['sum_sizing_loc']:,} sizing LOC", file=sys.stderr)
        if totals.errors:
            print(f"{totals.errors} scan(s) completed with errors", file=sys.stderr)
            return 2
        return 0
    except (AuthError, ApiError, RuntimeError, OSError, ValueError) as e:
        if config.debug:
            raise
        return fail(str(e))
    except KeyboardInterrupt:
        print("Interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
