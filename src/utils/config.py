import base64
import json
import os
from urllib.parse import urlparse

from dotenv import load_dotenv


class ConfigError(Exception):
    """Raised for invalid or incomplete configuration."""


def decode_jwt_payload(token):
    """Decode a JWT payload WITHOUT verifying it. Returns {} if not a JWT."""
    try:
        part = token.split(".")[1]
        part += "=" * (-len(part) % 4)
        data = json.loads(base64.urlsafe_b64decode(part.encode("ascii")))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def normalize_base_url(url):
    if not url:
        return url
    url = url.strip().rstrip("/")
    if "://" not in url:
        url = "https://" + url
    if url.endswith("/api"):
        url = url[:-4]
    return url


def derive_iam_url(base_url):
    """eu.ast.checkmarx.net -> eu.iam.checkmarx.net (replaces the 'ast' host label)."""
    if not base_url:
        return None
    parsed = urlparse(base_url)
    labels = (parsed.hostname or "").split(".")
    if "ast" not in labels:
        return None
    labels[labels.index("ast")] = "iam"
    host = ".".join(labels)
    if parsed.port:
        host += f":{parsed.port}"
    return f"{parsed.scheme}://{host}"


class Config:
    def __init__(self):
        self.base_url = None
        self.tenant_name = None
        self.api_key = None
        self.iam_url = None
        self.debug = False

    @classmethod
    def from_env(cls, env_file=None):
        """Load `env_file` (explicit; overrides existing variables) or the default .env lookup."""
        env_file = env_file or os.getenv("CXONE_ENV_FILE")
        if env_file:
            path = os.path.abspath(os.path.normpath(env_file))
            if not os.path.isfile(path):
                raise ConfigError(f"env file not found: {env_file}")
            load_dotenv(path, override=True)
        else:
            load_dotenv()
        config = cls()
        config.base_url = os.getenv("CXONE_BASE_URL") or None
        config.tenant_name = os.getenv("CXONE_TENANT") or None
        config.api_key = os.getenv("CXONE_API_KEY") or None
        config.iam_url = os.getenv("CXONE_IAM_URL") or None
        config.debug = os.getenv("CXONE_DEBUG", "").lower() == "true"
        return config

    @classmethod
    def from_args(cls, args, env_config=None):
        """Merge per field: CLI arg if given, else the environment value."""
        env = env_config or cls.from_env(getattr(args, "env_file", None))
        config = cls()
        config.base_url = getattr(args, "base_url", None) or env.base_url
        config.tenant_name = getattr(args, "tenant_name", None) or env.tenant_name
        config.api_key = getattr(args, "api_key", None) or env.api_key
        config.iam_url = getattr(args, "iam_url", None) or env.iam_url
        config.debug = bool(getattr(args, "debug", False)) or env.debug
        return config

    def resolve(self):
        """Fill tenant/base/IAM URLs from the API key JWT and normalise them."""
        claims = decode_jwt_payload(self.api_key or "")
        iss = claims.get("iss") or ""
        if not self.tenant_name and "/realms/" in iss:
            self.tenant_name = iss.rstrip("/").rsplit("/", 1)[-1]
        if not self.base_url:
            self.base_url = claims.get("ast-base-url")
            if not self.base_url and iss:
                host = urlparse(iss).hostname or ""
                labels = host.split(".")
                if "iam" in labels:
                    labels[labels.index("iam")] = "ast"
                    self.base_url = f"https://{'.'.join(labels)}"
        self.base_url = normalize_base_url(self.base_url)
        if self.iam_url:
            self.iam_url = self.iam_url.strip().rstrip("/")
        else:
            self.iam_url = derive_iam_url(self.base_url)
            if not self.iam_url and "/auth/realms/" in iss:
                self.iam_url = iss.split("/auth/realms/")[0]
        return self

    def validate(self):
        """Returns (is_valid, error_message)."""
        if not self.base_url:
            return False, "Base URL is required (--base-url / CXONE_BASE_URL, or an API key carrying ast-base-url)"
        if not self.tenant_name:
            return False, "Tenant name is required (--tenant-name / CXONE_TENANT, or a JWT API key)"
        if not self.api_key:
            return False, "API key is required (--api-key / CXONE_API_KEY)"
        if not self.iam_url:
            return False, "Cannot derive the IAM URL from the base URL; pass --iam-url / CXONE_IAM_URL"
        return True, None
