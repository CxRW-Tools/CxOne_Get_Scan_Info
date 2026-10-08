import threading
import time

import requests


class AuthError(Exception):
    """Raised when the OAuth token exchange fails."""


class AuthManager:
    """Thread-safe token cache. The token POST below is the ONLY non-GET request in the tool."""

    def __init__(self, base_url, tenant_name, api_key, iam_url, debug=False, timeout=(10, 60)):
        self.base_url = base_url
        self.tenant_name = tenant_name
        self.api_key = api_key
        self.iam_base_url = iam_url.rstrip("/")
        self.debug = debug
        self.timeout = timeout
        self.auth_token = None
        self.token_expiration = 0
        self._lock = threading.Lock()
        self.auth_url = f"{self.iam_base_url}/auth/realms/{self.tenant_name}/protocol/openid-connect/token"

    def _valid(self):
        return self.auth_token is not None and time.time() < self.token_expiration - 60

    def ensure_authenticated(self):
        if not self._valid():
            with self._lock:
                if not self._valid():  # double-checked
                    self._authenticate()
        return self.auth_token

    def invalidate(self, stale_token=None):
        """Drop the cached token (e.g. after a 401) unless another thread already refreshed it."""
        with self._lock:
            if stale_token is None or self.auth_token == stale_token:
                self.token_expiration = 0

    def _authenticate(self):
        data = {"grant_type": "refresh_token", "client_id": "ast-app", "refresh_token": self.api_key}
        try:
            response = requests.post(
                self.auth_url,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                data=data,
                timeout=self.timeout,
            )
            response.raise_for_status()
            body = response.json()
        except requests.exceptions.RequestException as e:
            raise AuthError(f"Authentication failed: {e}") from e
        except ValueError as e:
            raise AuthError(f"Authentication failed: invalid response ({e})") from e
        token = body.get("access_token")
        if not token:
            raise AuthError("Authentication failed: no access token in response")
        self.auth_token = token
        self.token_expiration = time.time() + float(body.get("expires_in", 600))

    def get_headers(self):
        return {"Authorization": f"Bearer {self.ensure_authenticated()}"}
