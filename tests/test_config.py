from types import SimpleNamespace

import pytest

from src.utils.config import Config, ConfigError


def args(**kw):
    base = dict(base_url=None, tenant_name=None, api_key=None, iam_url=None, debug=False, env_file=None)
    base.update(kw)
    return SimpleNamespace(**base)


def test_env_file_loaded_and_cli_overrides(tmp_path, monkeypatch):
    monkeypatch.setenv("CXONE_TENANT", "stale")
    f = tmp_path / ".env-prod"
    f.write_text("CXONE_API_KEY=k\nCXONE_BASE_URL=https://eu.ast.checkmarx.net\nCXONE_TENANT=prod\n")
    c = Config.from_args(args(env_file=str(f))).resolve()
    assert (c.api_key, c.tenant_name, c.iam_url) == ("k", "prod", "https://eu.iam.checkmarx.net")
    c = Config.from_args(args(env_file=str(f), tenant_name="cli")).resolve()
    assert c.tenant_name == "cli"


def test_missing_env_file_errors(tmp_path):
    with pytest.raises(ConfigError):
        Config.from_args(args(env_file=str(tmp_path / "nope")))
