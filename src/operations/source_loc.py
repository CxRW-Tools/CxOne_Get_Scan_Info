"""Optional local line count of a scan's source snapshot, including IaC lines (a local estimate)."""
import contextlib
import ipaddress
import os
import re
import shutil
import stat
import tempfile
import zipfile
from urllib.parse import urlparse

from src.utils.http import ApiError

MAX_COUNT_BYTES = 4 * 1024 * 1024
SNIFF_BYTES = 64 * 1024
MAX_EXTRACT_BYTES = 20 * 1024 ** 3
MAX_REDIRECTS = 5
TOP_IAC_FILES = 10

# ------------------------------------------------------------------ comment families
FAMILIES = {
    "c": (("//",), (("/*", "*/"),)),
    "hash": (("#",), ()),
    "sql": (("--",), (("/*", "*/"),)),
    "markup": ((), (("<!--", "-->"),)),
    "hcl": (("#", "//"), (("/*", "*/"),)),
    "css": ((), (("/*", "*/"),)),
    "php": (("//", "#"), (("/*", "*/"),)),
    "lua": (("--",), (("--[[", "]]"),)),
    "none": ((), ()),
}
_STARTER_RE = {}


def _starters(family):
    if family not in _STARTER_RE:
        line, blocks = FAMILIES[family]
        parts = sorted(list(line) + [b[0] for b in blocks], key=len, reverse=True)
        _STARTER_RE[family] = re.compile("|".join(re.escape(p) for p in parts)) if parts else None
    return _STARTER_RE[family]


# extension -> (language, family)
EXTENSIONS = {}
for _lang, _fam, _exts in [
    ("C", "c", "c h"), ("C++", "c", "cpp cc cxx hpp hh hxx"), ("C#", "c", "cs"), ("Java", "c", "java"),
    ("JavaScript", "c", "js jsx mjs cjs"), ("TypeScript", "c", "ts tsx"), ("Go", "c", "go"), ("Rust", "c", "rs"),
    ("Swift", "c", "swift"), ("Kotlin", "c", "kt kts"), ("Scala", "c", "scala"), ("Dart", "c", "dart"),
    ("Objective-C", "c", "m mm"), ("Groovy", "c", "groovy gradle"), ("Apex", "c", "cls trigger"),
    ("PHP", "php", "php"), ("CSS", "css", "css"), ("SCSS", "c", "scss less"),
    ("Python", "hash", "py"), ("Ruby", "hash", "rb"), ("Shell", "hash", "sh bash zsh"), ("Perl", "hash", "pl pm"),
    ("R", "hash", "r"), ("PowerShell", "hash", "ps1 psm1"), ("Makefile", "hash", "mk"),
    ("YAML", "hash", "yaml yml"), ("TOML", "hash", "toml"), ("INI", "hash", "ini cfg conf"),
    ("SQL", "sql", "sql"), ("Lua", "lua", "lua"),
    ("HTML", "markup", "html htm xhtml vue svelte"), ("XML", "markup", "xml xsd xsl xslt svg csproj"),
    ("Terraform", "hcl", "tf tfvars hcl"), ("Bicep", "c", "bicep"), ("Protocol Buffers", "c", "proto"),
    ("JSON", "none", "json"), ("Markdown", "none", "md markdown"), ("Text", "none", "txt rst"),
    ("CSV", "none", "csv tsv"),
]:
    for _e in _exts.split():
        EXTENSIONS[_e] = (_lang, _fam)
FILENAMES = {"dockerfile": ("Dockerfile", "hash"), "containerfile": ("Dockerfile", "hash"),
             "makefile": ("Makefile", "hash"), "jenkinsfile": ("Groovy", "c"), "rakefile": ("Ruby", "hash")}

# Languages that are not application code: docs/data and IaC-native languages.
NON_APP_LANGUAGES = {"JSON", "YAML", "TOML", "INI", "XML", "Markdown", "Text", "CSV",
                     "Terraform", "Bicep", "Dockerfile", "Protocol Buffers"}


def language_of(rel_path):
    base = os.path.basename(rel_path).lower()
    if base in FILENAMES:
        return FILENAMES[base]
    if base.startswith("dockerfile.") or base.endswith(".dockerfile"):
        return FILENAMES["dockerfile"]
    if base.endswith(".tf.json"):
        return ("JSON", "none")
    ext = base.rsplit(".", 1)[-1] if "." in base else ""
    return EXTENSIONS.get(ext)


# ------------------------------------------------------------------ line counting
def count_text(text, family):
    """cloc-style (code, comment, blank) for one file's text, using the comment syntax of a family."""
    line_prefixes, blocks = FAMILIES[family]
    starters = _starters(family)
    block_starts = {b[0] for b in blocks}
    code = comment = blank = 0
    end = None  # closing token of the block comment we are inside
    for raw in text.splitlines():
        s = raw.strip()
        if not s:
            blank += 1
            continue
        if starters is None:
            code += 1
            continue
        has_code = has_comment = False
        i, n = 0, len(s)
        while i < n:
            if end is not None:
                has_comment = True
                j = s.find(end, i)
                if j < 0:
                    break
                i, end = j + len(end), None
                continue
            if s[i].isspace():
                i += 1
                continue
            m = starters.match(s, i)
            if m is None:
                has_code = True
                m = starters.search(s, i)
                if m is None:
                    break
                i = m.start()
                continue
            tok = m.group(0)
            has_comment = True
            if tok in block_starts:
                end = next(be for bs, be in blocks if bs == tok)
                i = m.end()
                continue
            break  # line comment: rest of the line
        if has_code:
            code += 1
        elif has_comment:
            comment += 1
        else:
            blank += 1
    return code, comment, blank


def _is_binary(head):
    return b"\0" in head


# ------------------------------------------------------------------ IaC classification
_YAML_EXT = {"yaml", "yml"}
_SNIFF_EXT = {"yaml", "yml", "json", "template", "tmpl", "tpl", "txt"}
_RE_K8S_API = re.compile(r"^\s*[\"']?apiVersion[\"']?\s*:", re.M)
_RE_K8S_KIND = re.compile(r"^\s*[\"']?kind[\"']?\s*:", re.M)
_RE_OPENAPI = re.compile(r"^\s*[\"']?(openapi|swagger)[\"']?\s*:", re.M)
_RE_ARM = re.compile(r"[\"']\$schema[\"']\s*:\s*[\"'][^\"']*deploymentTemplate", re.I)
_RE_ANSIBLE = re.compile(r"^\s*-\s*hosts\s*:", re.M)
_RE_GDM_RES = re.compile(r"^\s*resources\s*:", re.M)


def classify_by_name(rel_path, chart_dirs=frozenset()):
    """Platform from the path alone, or None. rel_path uses forward slashes."""
    p = rel_path.replace("\\", "/")
    low = p.lower()
    base = low.rsplit("/", 1)[-1]
    ext = base.rsplit(".", 1)[-1] if "." in base else ""
    if base in ("dockerfile", "containerfile") or base.startswith("dockerfile.") or base.endswith(".dockerfile"):
        return "Dockerfile"
    if ext in _YAML_EXT and (base.startswith("docker-compose") or base.startswith("compose")):
        return "DockerCompose"
    if base.endswith(".tf") or base.endswith(".tfvars") or base.endswith(".tf.json"):
        return "Terraform"
    if ext == "bicep":
        return "Bicep"
    if base in ("serverless.yml", "serverless.yaml"):
        return "ServerlessFW"
    if ext in _YAML_EXT and base.startswith("pulumi"):
        return "Pulumi"
    if ext in _YAML_EXT and (low.startswith(".github/workflows/") or "/.github/workflows/" in low):
        return "CICD"
    if ext == "proto":
        return "GRPC"
    if chart_dirs:
        d = os.path.dirname(p)
        while True:
            if d in chart_dirs:
                return "Helm"
            if not d:
                break
            d = os.path.dirname(d)
    parts = low.split("/")
    if ext in _YAML_EXT and "roles" in parts:
        k = parts.index("roles")
        if len(parts) >= k + 4 and parts[k + 2] in ("tasks", "handlers"):
            return "Ansible"
    return None


def classify_by_content(rel_path, head):
    """Sniff the first 64 KB of yaml/json/template files. Returns a platform or None."""
    base = rel_path.lower().rsplit("/", 1)[-1]
    ext = base.rsplit(".", 1)[-1] if "." in base else ""
    if ext not in _SNIFF_EXT:
        return None
    if "AWSTemplateFormatVersion" in head or re.search(r"[\"']?Type[\"']?\s*:\s*[\"']?AWS::", head):
        return "CloudFormation"
    if _RE_ARM.search(head):
        return "AzureResourceManager"
    if _RE_OPENAPI.search(head):
        return "OpenAPI"
    if "crossplane.io" in head:
        return "Crossplane"
    if "knative.dev" in head:
        return "Knative"
    if _RE_K8S_API.search(head) and _RE_K8S_KIND.search(head):
        return "Kubernetes"
    if _RE_ANSIBLE.search(head):
        return "Ansible"
    if _RE_GDM_RES.search(head) and re.search(r"type\s*:\s*compute\.v1", head):
        return "GoogleDeploymentManager"
    return None


# ------------------------------------------------------------------ zip extraction
def safe_extract(zip_path, dest):
    """Extract rejecting absolute / '..' members and skipping symlinks. Returns the skipped count."""
    skipped, total = 0, 0
    dest_real = os.path.realpath(dest)
    with zipfile.ZipFile(zip_path) as zf:
        for info in zf.infolist():
            name = info.filename.replace("\\", "/")
            parts = [x for x in name.split("/") if x not in ("", ".")]
            mode = (info.external_attr >> 16) & 0o170000
            if (name.startswith("/") or re.match(r"^[A-Za-z]:", name) or ".." in parts or not parts
                    or mode == stat.S_IFLNK):
                skipped += 1
                continue
            target = os.path.realpath(os.path.join(dest_real, *parts))
            if os.path.commonpath([dest_real, target]) != dest_real:
                skipped += 1
                continue
            if info.is_dir():
                os.makedirs(target, exist_ok=True)
                continue
            total += info.file_size
            if total > MAX_EXTRACT_BYTES:
                raise ValueError("archive too large to extract")
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with zf.open(info) as src, open(target, mode="wb") as out:
                shutil.copyfileobj(src, out)
    return skipped


# ------------------------------------------------------------------ analysis
def analyze_tree(root, top_n=TOP_IAC_FILES):
    """Count a source tree. Returns the source_loc dict (a local estimate, not CxOne data)."""
    files = []
    chart_dirs = set()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != ".git"]
        rel_dir = os.path.relpath(dirpath, root).replace("\\", "/")
        rel_dir = "" if rel_dir == "." else rel_dir
        for fn in filenames:
            files.append((os.path.join(dirpath, fn), f"{rel_dir}/{fn}" if rel_dir else fn))
            if fn == "Chart.yaml":
                chart_dirs.add(rel_dir)
    langs, platforms, iac_files = {}, {}, []
    app_loc = iac_loc = 0
    for full, rel in files:
        if os.path.islink(full):
            continue
        info = language_of(rel)
        size = os.path.getsize(full)
        with open(full, mode="rb") as f:
            head = f.read(SNIFF_BYTES)
            if _is_binary(head[:8192]):
                continue
            data = head if size <= SNIFF_BYTES else None
            if data is None and size <= MAX_COUNT_BYTES:
                data = head + f.read()
            elif data is None:  # too large to parse: newline count only
                nl = head.count(b"\n") + sum(chunk.count(b"\n") for chunk in iter(lambda: f.read(1 << 20), b""))
        platform = classify_by_name(rel, chart_dirs) or classify_by_content(rel, head.decode("utf-8", "replace"))
        if data is None:
            code, comment, blank = nl, 0, 0
        else:
            family = info[1] if info else "none"
            code, comment, blank = count_text(data.decode("utf-8", "replace"), family)
        lang = info[0] if info else ("Other" if platform is None else platform)
        row = langs.setdefault(lang, {"language": lang, "files": 0, "code": 0, "comment": 0, "blank": 0})
        row["files"] += 1
        row["code"] += code
        row["comment"] += comment
        row["blank"] += blank
        if platform:
            iac_loc += code
            p = platforms.setdefault(platform, {"files": 0, "loc": 0})
            p["files"] += 1
            p["loc"] += code
            iac_files.append({"path": rel, "platform": platform, "loc": code})
        elif lang not in NON_APP_LANGUAGES and lang != "Other":
            app_loc += code
    iac_files.sort(key=lambda x: -x["loc"])
    return {
        "note": "local estimate from the downloaded snapshot; CxOne reports no IaC line count",
        "app_code_loc": app_loc,
        "languages": sorted(langs.values(), key=lambda r: -r["code"]),
        "iac_loc": iac_loc,
        "iac_files": len(iac_files),
        "iac_platforms": dict(sorted(platforms.items(), key=lambda kv: -kv[1]["loc"])),
        "top_iac_files": iac_files[:top_n],
        "total_files": len(files),
    }


# ------------------------------------------------------------------ download
def _redirect_allowed(url, base_host):
    """Validate a server-supplied redirect target before requesting it."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return False
    host = parsed.hostname.lower()
    if host == base_host:
        return True
    if parsed.scheme != "https":  # third-party archive hosts must use TLS
        return False
    try:  # refuse private / loopback / link-local IP literals
        ip = ipaddress.ip_address(host)
        return ip.is_global
    except ValueError:
        return host != "localhost"


def _download(client, scan_id, zip_path):
    """GET /api/repostore/code/{id} (302 -> archive), then stream the archive to disk."""
    resp = client.fetch(f"repostore/code/{scan_id}", raw=True, allow_redirects=False)
    hops = 0
    while resp.status_code in (301, 302, 303, 307, 308):
        url = client.resolve_location(resp)
        resp.close()
        hops += 1
        if not url or hops > MAX_REDIRECTS or not _redirect_allowed(url, client.base_host):
            raise ApiError(None, "unusable redirect from repostore", "repostore/code")
        # the client only attaches the bearer token when the host equals the configured base host
        resp = client.fetch(url, raw=True, stream=True, allow_redirects=False, allow_absolute=True)
    if resp.status_code != 200:
        status = resp.status_code
        resp.close()
        raise ApiError(status, f"unexpected status {status}", "repostore/code")
    try:
        with open(os.path.abspath(os.path.normpath(zip_path)), mode="wb") as out:
            for chunk in resp.iter_content(chunk_size=1 << 20):
                out.write(chunk)
    finally:
        resp.close()


def source_loc_for_scan(client, scan_id, keep_dir=None):
    """Returns (result_dict | None, error_str | None)."""
    work = tempfile.mkdtemp(prefix="getscaninfo_")
    try:
        zip_path = os.path.join(work, "src.zip")
        try:
            _download(client, scan_id, zip_path)
        except ApiError as e:
            if e.status in (401, 403):
                return None, f"repostore/code: {e.status} no source-download permission"
            if e.status == 404:
                return None, "repostore/code: 404 archive aged out"
            return None, f"repostore/code: {e.status or e.message}"
        dest = os.path.join(keep_dir, scan_id) if keep_dir else os.path.join(work, "tree")
        os.makedirs(dest, exist_ok=True)
        try:
            skipped = safe_extract(zip_path, dest)
        except (zipfile.BadZipFile, ValueError) as e:
            return None, f"repostore/code: bad archive ({e})"
        result = analyze_tree(dest)
        if skipped:
            result["skipped_unsafe_members"] = skipped
        if keep_dir:
            result["kept_at"] = dest
        return result, None
    finally:
        with contextlib.suppress(OSError):
            shutil.rmtree(work, ignore_errors=True)
