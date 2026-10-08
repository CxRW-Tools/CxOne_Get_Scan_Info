"""GET-only HTTP client for the CxOne API (session, retries, rate limit, pagination)."""
import random
import sys
import threading
import time
from email.utils import parsedate_to_datetime
from urllib.parse import urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter

from src import __version__
from src.utils.auth import AuthError

RETRY_STATUSES = {429, 500, 502, 503, 504}
MAX_TRIES = 5
BACKOFF = (1, 2, 4, 8)
MAX_RETRY_AFTER = 300
# Endpoints whose array params are comma-joined (explode: false); all others repeat the param.
COMMA_JOIN_PATHS = {"sast-metadata", "sast-metadata/engine-version"}


class ApiError(Exception):
    """Typed HTTP/transport error so callers can record it per scan."""

    def __init__(self, status, message, path=""):
        super().__init__(f"{path}: {status or message}")
        self.status = status
        self.message = message
        self.path = path


class RateLimiter:
    """Token bucket shared by all threads."""

    def __init__(self, rate, clock=time.monotonic, sleep=time.sleep):
        self.rate = float(rate)
        self.capacity = max(1.0, self.rate)
        self.tokens = self.capacity
        self._clock, self._sleep = clock, sleep
        self._last = clock()
        self._lock = threading.Lock()

    def acquire(self):
        with self._lock:
            now = self._clock()
            self.tokens = min(self.capacity, self.tokens + (now - self._last) * self.rate)
            self._last = now
            self.tokens -= 1
            wait = -self.tokens / self.rate if self.tokens < 0 else 0
        if wait > 0:
            self._sleep(wait)


def normalize_path(path):
    p = path.lstrip("/")
    return p[4:] if p.startswith("api/") else p


def _retry_after(resp):
    value = resp.headers.get("Retry-After") if resp is not None else None
    if not value:
        return None
    try:
        return min(max(float(value), 0), MAX_RETRY_AFTER)
    except ValueError:
        try:
            delta = parsedate_to_datetime(value).timestamp() - time.time()
            return min(max(delta, 0), MAX_RETRY_AFTER)
        except (TypeError, ValueError):
            return None


class HttpClient:
    """Exposes only fetch() (an HTTP GET). The OAuth token POST lives in AuthManager."""

    def __init__(self, auth, base_url, workers=8, max_rps=None, debug=False,
                 timeout=(10, 60), session=None, sleep=time.sleep):
        self.auth = auth
        self.base_url = base_url.rstrip("/")
        self.api_root = self.base_url + "/api/"
        self.base_host = (urlparse(self.base_url).hostname or "").lower()
        self.debug = debug
        self.timeout = timeout
        self._sleep = sleep
        self.limiter = RateLimiter(max_rps, sleep=sleep) if max_rps else None
        if session is None:
            session = requests.Session()
            size = workers + 8
            adapter = HTTPAdapter(pool_connections=size, pool_maxsize=size, max_retries=0)
            session.mount("https://", adapter)
            session.mount("http://", adapter)
        self.session = session

    # -- helpers -------------------------------------------------------
    @staticmethod
    def encode_params(path, params):
        comma = normalize_path(path).rstrip("/") in COMMA_JOIN_PATHS
        out = []
        for key, value in (params or {}).items():
            if value is None:
                continue
            if isinstance(value, bool):
                value = "true" if value else "false"
            if isinstance(value, (list, tuple, set)):
                items = [str(v) for v in value]
                if comma:
                    out.append((key, ",".join(items)))
                else:
                    out.extend((key, v) for v in items)
            else:
                out.append((key, value))
        return out

    def _log(self, path, status, started):
        if self.debug:
            ms = int((time.monotonic() - started) * 1000)
            print(f"[debug] GET {path} -> {status} {ms}ms", file=sys.stderr)

    @staticmethod
    def _backoff(attempt, resp=None):
        base = BACKOFF[min(attempt, len(BACKOFF)) - 1]
        delay = base * random.uniform(0.75, 1.25)
        ra = _retry_after(resp)
        return ra if ra is not None else delay

    # -- the only request method --------------------------------------
    def fetch(self, path, params=None, *, raw=False, stream=False, allow_redirects=True, allow_absolute=False):
        """GET {base}/api/{path} (or an absolute URL). Returns parsed JSON (None if empty);
        with raw=True returns the Response (2xx/3xx). Bearer token is only sent to the base host."""
        absolute = "://" in path
        if absolute and not allow_absolute:
            raise ApiError(None, "absolute URLs are not allowed here", path)
        url = path if absolute else self.api_root + normalize_path(path)
        label = urlparse(url).path if absolute else normalize_path(path)
        query = self.encode_params(label, params)
        same_host = (urlparse(url).hostname or "").lower() == self.base_host
        refreshed = False
        attempt = 0
        while True:
            attempt += 1
            if self.limiter:
                self.limiter.acquire()
            headers = {"Accept": "application/json", "User-Agent": f"get-scan-info/{__version__}"}
            token = None
            if same_host:
                try:
                    token = self.auth.ensure_authenticated()
                except AuthError as e:
                    raise ApiError(None, str(e), label) from e
                headers["Authorization"] = f"Bearer {token}"
            started = time.monotonic()
            try:
                resp = self.session.get(url, params=query or None, headers=headers, timeout=self.timeout,
                                        allow_redirects=allow_redirects, stream=stream)
            except (requests.ConnectionError, requests.Timeout) as e:
                self._log(label, type(e).__name__, started)
                if attempt < MAX_TRIES:
                    self._sleep(self._backoff(attempt))
                    continue
                raise ApiError(None, f"connection error: {e}", label) from e
            except requests.RequestException as e:
                raise ApiError(None, str(e), label) from e
            self._log(label, resp.status_code, started)
            status = resp.status_code
            if status == 401 and same_host and not refreshed:
                refreshed = True
                attempt -= 1
                self.auth.invalidate(token)
                resp.close()
                continue
            if status in RETRY_STATUSES and attempt < MAX_TRIES:
                delay = self._backoff(attempt, resp)
                resp.close()
                self._sleep(delay)
                continue
            if status >= 400:
                text = ""
                try:
                    text = resp.text[:200]
                except Exception:
                    pass
                resp.close()
                raise ApiError(status, text or f"HTTP {status}", label)
            if raw:
                return resp
            if not resp.content:
                return None
            try:
                return resp.json()
            except ValueError as e:
                raise ApiError(status, "invalid JSON in response", label) from e

    def resolve_location(self, resp):
        loc = resp.headers.get("Location")
        return urljoin(resp.url or self.api_root, loc) if loc else None

    def paginate(self, path, key, params=None, limit=500, max_pages=None):
        """Yield items page by page. offset is a record count; stops on a short page.
        totalCount is deliberately ignored (it can ignore filters)."""
        offset, pages = 0, 0
        while True:
            q = dict(params or {})
            q.update(limit=limit, offset=offset)
            data = self.fetch(path, q)
            if isinstance(data, list):
                items = data
            else:
                items = (data or {}).get(key) or []
            yield from items
            pages += 1
            if len(items) < limit or (max_pages and pages >= max_pages):
                return
            offset += len(items)
