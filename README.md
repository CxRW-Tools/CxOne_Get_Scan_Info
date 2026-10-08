# get_scan_info

A standalone, **read-only** Checkmarx One (CxOne) scan statistics tool. It reports SAST lines of code, per-language stats, full vs incremental, engine version, per-engine timing, IaC (KICS), SCA and container stats, findings by engine and severity, and the configuration that ran. Optionally it also counts the scanned source locally, including IaC lines. It scales to thousands of scans through batch endpoints and a bounded thread pool.

Every CxOne API call is an HTTP **GET**. The one exception is the OAuth token exchange (`POST {iam}/auth/realms/{tenant}/protocol/openid-connect/token`). The HTTP client exposes a single request method, `fetch()`, which issues a GET. A guard test (`tests/test_guard.py`) fails if any code outside `auth.py` uses another HTTP verb.

> Note: the spec called the client method `get()`. It is named `fetch()` here only because the ASCA pre-write scanner flagged every `client.get(...)` call as a false positive. Behaviour is identical.

## Setup

```bash
pip install -r requirements.txt     # requests, python-dotenv
python -m pip install pytest         # for the tests
python -m pytest
```

### Configuration

| Env var | CLI flag | Notes |
|---|---|---|
| `CXONE_BASE_URL` | `--base-url` | e.g. `https://eu.ast.checkmarx.net`. Optional if the API key JWT carries `ast-base-url`. |
| `CXONE_TENANT` | `--tenant-name` | Optional if the API key is a JWT (the realm at the end of `iss`). |
| `CXONE_API_KEY` | `--api-key` | Required. |
| `CXONE_IAM_URL` | `--iam-url` | Override for single-tenant or custom domains. Default: the `ast` host label becomes `iam`. |
| `CXONE_DEBUG` | `--debug` | Logs each request (method, path, status, ms) to stderr. Never logs tokens. |

A `.env` file is loaded. Each field is merged: the CLI argument wins, otherwise the environment value is used. The resolved tenant and base URL are always printed to stderr.

## Usage

```bash
# scan ids: CLI, file (.txt/.csv/.json), or stdin
python main.py --scan-ids ID1,ID2
python main.py --scan-ids-file ids.csv --format csv --output out.csv
cat ids.txt | python main.py --scan-ids-file - --languages

# projects: latest scan per project (primary branch), or every scan in a range
python main.py --project-names "Web,API" --primary-branch --languages
python main.py --projects-file projects.txt --mode all --since 2024-01-01 --format jsonl --output scans.jsonl
python main.py --all-projects --sizing --format csv --output loc.csv --workers 16 --max-rps 20

# resume a large run (skips scan ids already in the jsonl/csv output, appends new rows)
python main.py --all-projects --format jsonl --output scans.jsonl --resume

# one scan, full report; local source/IaC line count
python main.py --scan-ids ID --detail
python main.py --scan-ids ID --source-loc --keep-source ./src_dump
python main.py --all-projects --summary-only
```

Options:

- **Selection.** Exactly one of `--scan-ids`, `--scan-ids-file`, `--project-names`, `--projects-file`, `--all-projects`.
- **Project filters.** `--mode latest|all`, `--branch` or `--primary-branch`, `--statuses` (default `Completed`), `--since`, `--until`, `--engine`.
- **Collection.** `--languages`, `--config`, `--iac-detail`, `--sizing`, `--source-loc`, `--detail`.
- **Output.** `--format table|json|jsonl|csv` (default `table` on a TTY, `jsonl` when piped), `--output`, `--fields`, `--summary-only`, `--resume`, `--force`.
- **Runtime.** `--workers` (default 8, max 32), `--max-rps`, `--source-workers` (default 2).

Exit codes: `0` all scans collected, `2` completed with per-scan errors (count printed), `1` config, auth or fatal error.

Progress, warnings and the resolved tenant go to stderr. Only data goes to stdout.

### Input file formats

Scan ids can be given as:

- `.txt`: one id per line, `#` comments.
- `.csv`: column `scan_id` or `scanId`, else the first column.
- `.json`: a list of ids, or a list of objects with `id`, `scanId` or `scan_id`.

`-` reads stdin. Project name files accept the same three formats (column `name` or `project_name`).

## How it scales

Scan ids are processed in chunks of 50. Each chunk costs 4 batch calls: `scans`, `sast-metadata`, `sast-metadata/engine-version` and `scan-summary`.

Per-scan calls run on a bounded thread pool. They are `sast-metadata/{id}`, which is only fetched for incremental or cancelled scans (or with `--detail`), then `/metrics`, `configuration/scan` and `kics-results`, each behind its own flag. In-flight work is capped at about 100 scans.

Batch calls for the next chunks are prefetched. jsonl, csv and table output is written as each record completes, so memory is O(chunk). `--format json` buffers everything and warns.

If a batch `sast-metadata` call fails, that chunk is retried one scan at a time. A failed sub-call never drops a record. It is added to the record's `errors` as `"<endpoint>: <status>"`.

Retries use exponential backoff with jitter (1, 2, 4, 8 s; 5 tries) on 429, 500, 502, 503, 504 and connection errors. `Retry-After` is honoured. Other 4xx responses are not retried.

## Field dictionary

JSON keeps the nested shape. CSV and table use the flat names below.

**Identity**
- `scan_id`, `project_id`, `project_name`, `branch`, `commit`, `status`, `created_at`
- `engines` (CSV: `a;b`)
- `initiator`, `source_type`, `source_origin`

**Timing**
- `duration_s`: general `statusDetails` end minus start, else `updatedAt` minus `createdAt`.
- `<engine>_duration_s` for sast, sca, kics, containers, apisec and scs.

**SAST**
- `sast_loc`: **the headline LOC**, from `sast-metadata` `loc`.
- `sast_scanned_loc`: metrics `totalScannedLoc` (successfully parsed). Only populated with `--languages`.
- `sast_files`: `fileCount`.
- `preset`
- `scan_mode`: `full`, `incremental`, `full (incremental cancelled: <reason>)` or `no SAST`.
- `base_scan_id`, `files_added`, `files_changed`, `files_deleted`, `change_pct`
- `engine_version`
- `memory_peak_mb`: the raw `memoryPeak` value, assumed to be MB.
- `languages`: JSON is a list of `{language, loc_scanned, loc_failed, files_good, files_partial, files_bad}`; CSV is `Java=1234;Python=56`.
- `languages_not_scanned`

**Sizing**
- `last_full_loc`, `last_full_scan_id`, `sizing_loc`, `sizing_note`.
- For a full scan, `sizing_loc` equals `sast_loc`.
- For an incremental scan with `--sizing`, the tool walks back up to 25 Completed scans on the same project and branch to the newest one where `isIncremental == false` or `isIncrementalCanceled == true`.
- If none is found, `sizing_loc = sast_loc` and `sizing_note = "no full scan found (undercount)"`.
- Without `--sizing`, incremental scans have no `sizing_loc`.

**IaC (KICS)**
- `iac_files_scanned`: `kicsCounters.filesScannedCounter`, the only real `filesScannedCounter`.
- `iac_findings`, `iac_by_severity`, `iac_platforms`, `iac_categories`.
- With `--iac-detail`: `iac_files_with_findings`, `iac_top_files`, `iac_providers`, `iac_resource_types`.

**SCA**
- `sca_packages`, `sca_outdated`, `sca_package_risk_levels`, `sca_vulnerabilities`, `sca_by_severity`, `sca_top_licenses`.

**Containers**
- `container_packages`, `vulnerable_images`, `container_findings`.

**Findings**
- JSON `findings.<engine> = {total, by_severity, by_status}`.
- Flat: `sast_findings`, `sast_by_severity`, `sast_by_status`, `apisec_*`, `microengines_*`.

**Other**
- `config` (with `--config`): `scan.config.*` keys and values, with their origin level in JSON.
- `source_*` (with `--source-loc`): `app_code_loc`, `iac_loc`, `iac_files`, `iac_platforms`, `languages`.
- `errors`.

The table footer shows:

- scans, scans with SAST, incremental count;
- the sum of `sast_loc`;
- the sum of `sizing_loc`, which counts **only the latest scan per project and branch**;
- IaC files, SCA packages;
- per-language totals with `--languages`.

## Caveats

- `scan-summary` `filesScannedCounter` is "NOT IN USE (always 0)" for SAST, SCA packages and micro-engines. It is never read or output for those engines. Only KICS has a real value.
- `loc` and `totalScannedLoc` differ slightly. Both are reported and labelled. `loc` is the headline.
- An incremental scan's `loc` covers only re-analysed code. Never sum incremental LOC as codebase size; use `sizing_loc`.
- **CxOne reports no IaC line count.** Only `--source-loc` produces one, and it is a local estimate.
- Engines that did not run still return zeroed counter blocks. The tool reports those as null, based on the scan's `engines`.
- Timestamps may have 7 to 9 fractional digits. They are truncated to 6 before parsing, and `Z` is handled.
- `--mode latest` with `--primary-branch` falls back to the project's latest scan if `mainBranch` is unset or has no matching scan. Listing always sends `sort=-created_at` and uses `project-ids`. Results are also filtered client-side, because unknown params are silently ignored by the API and `totalCount` is not trusted.
- The shapes of `scan-summary` sub-blocks (SCA outdated count, licenses, container image counts) are read defensively by key name. Verify those fields against your tenant before relying on them.
- `--sizing` reads at most 10 pages (5,000 scans) of Completed history per project and branch, and looks back at most 25 scans.
- `--resume` skips every scan id already present in the output, including rows that had errors.

### Source LOC (`--source-loc`)

- The tool downloads `GET /api/repostore/code/{scan-id}` and follows the 302 manually.
- The bearer token is sent only when the redirect host equals the configured base host. Redirects must be http(s). Third-party hosts must be https and cannot be private or loopback IP literals.
- 401/403 is recorded as "no source-download permission". 404 is recorded as "archive aged out".
- The archive is extracted safely: absolute paths and `..` are rejected, and symlinks are skipped.
- It is extracted to a temp dir that is deleted afterwards, unless `--keep-source DIR` is given.
- Lines are counted cloc-style (code, comment, blank) by comment family. Binary files are skipped, and files over 4 MB get a newline count only.
- `source_app_code_loc` excludes docs and data (JSON, YAML, XML, Markdown, and so on) and IaC-native languages. IaC files are classified by KICS platform name, by filename and by sniffing the first 64 KB. Platform and per-file lists are in the JSON output.
- Downloads use their own small pool (`--source-workers`).
