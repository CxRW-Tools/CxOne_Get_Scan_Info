import requests

from src.utils.http import ApiError, HttpClient
import pytest


class Resp:
    def __init__(self, status, body=b"{}", headers=None):
        self.status_code, self.content, self.headers = status, body, headers or {}
        self.text = body.decode() if isinstance(body, bytes) else body
        self.url = "https://x"

    def json(self):
        import json
        return json.loads(self.content)

    def close(self):
        pass


class Auth:
    def ensure_authenticated(self):
        return "tok"

    def invalidate(self, t=None):
        pass


class Sess:
    def __init__(self, outcomes):
        self.outcomes, self.requests = list(outcomes), []

    def get(self, url, params=None, headers=None, **kw):
        self.requests.append((url, params, headers))
        o = self.outcomes.pop(0)
        if isinstance(o, Exception):
            raise o
        return o


def client(outcomes, sleeps):
    return HttpClient(Auth(), "https://eu.ast.checkmarx.net", session=Sess(outcomes), sleep=sleeps.append)


def test_429_retry_after_honored_then_success():
    sleeps = []
    c = client([Resp(429, headers={"Retry-After": "7"}), Resp(200, b'{"a":1}')], sleeps)
    assert c.fetch("scans") == {"a": 1}
    assert sleeps == [7.0]


def test_5xx_retried_up_to_five_tries():
    sleeps = []
    c = client([Resp(503)] * 5, sleeps)
    with pytest.raises(ApiError) as e:
        c.fetch("scans")
    assert e.value.status == 503 and len(sleeps) == 4


def test_connection_error_retried():
    sleeps = []
    c = client([requests.ConnectionError("x"), Resp(200, b"")], sleeps)
    assert c.fetch("scans") is None and len(sleeps) == 1


def test_404_not_retried():
    sleeps = []
    c = client([Resp(404, b"nope")], sleeps)
    with pytest.raises(ApiError) as e:
        c.fetch("scans")
    assert e.value.status == 404 and sleeps == []


def test_param_encoding_repeat_vs_comma():
    assert HttpClient.encode_params("scans", {"scan-ids": ["a", "b"]}) == [("scan-ids", "a"), ("scan-ids", "b")]
    assert HttpClient.encode_params("sast-metadata", {"scan-ids": ["a", "b"]}) == [("scan-ids", "a,b")]
    assert HttpClient.encode_params("/api/sast-metadata/engine-version", {"scan-ids": ["a", "b"]}) == [("scan-ids", "a,b")]


def test_token_only_sent_to_base_host_and_absolute_needs_opt_in():
    c = client([Resp(200, b"{}")], [])
    with pytest.raises(ApiError):
        c.fetch("https://evil.example/x")
    c.fetch("https://s3.amazonaws.com/x", allow_absolute=True)
    assert "Authorization" not in c.session.requests[0][2]
    c2 = client([Resp(200, b"{}")], [])
    c2.fetch("scans")
    assert c2.session.requests[0][2]["Authorization"] == "Bearer tok"


def test_paginate_stops_on_short_page_ignores_total_count():
    pages = [Resp(200, b'{"scans":[1,2],"totalCount":999}'), Resp(200, b'{"scans":[3],"totalCount":999}')]
    c = client(pages, [])
    assert list(c.paginate("scans", "scans", limit=2)) == [1, 2, 3]
    assert c.session.requests[1][1][-1] == ("offset", 2)
