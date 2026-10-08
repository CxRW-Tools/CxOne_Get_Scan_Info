import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
PATTERN = re.compile(r"\.(post|put|patch|delete|head|options|request)\s*\(|requests\.(post|put|patch|delete)\b", re.I)


def test_only_get_outside_auth():
    offenders = []
    files = [ROOT / "main.py"] + list((ROOT / "src").rglob("*.py"))
    for f in files:
        if f.name == "auth.py":  # the OAuth token exchange is the single allowed POST
            continue
        for n, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
            if PATTERN.search(line) and not line.strip().startswith("#"):
                offenders.append(f"{f.relative_to(ROOT)}:{n}: {line.strip()}")
    assert not offenders, offenders


def test_client_exposes_only_fetch():
    from src.utils.http import HttpClient
    public = {n for n in dir(HttpClient) if not n.startswith("_") and callable(getattr(HttpClient, n))}
    assert not public & {"post", "put", "patch", "delete"}
    assert "fetch" in public
