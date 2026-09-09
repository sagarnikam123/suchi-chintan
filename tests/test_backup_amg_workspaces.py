#!/usr/bin/env python3
"""Offline self-check for backup_amg_workspaces selection + URL logic.
Run: python3 tests/test_backup_amg_workspaces.py  (no AWS/network needed)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import tools.backup_amg_workspaces as amg
from tools.backup_amg_workspaces import (
    _select_workspaces,
    _grafana_base_url,
    _api_get_paginated,
    _backup_simple,
    _NotFound,
)

WS = [
    {"id": "g-aaa", "grafana_version": "9.4"},
    {"id": "g-bbb", "grafana_version": "10.4"},
    {"id": "g-ccc", "grafana_version": "9.4"},
]


def test_select_workspaces():
    # version filter isolates only the 9.4 upgrade candidates
    only_94 = _select_workspaces(WS, None, "9.4")
    assert {w["id"] for w in only_94} == {"g-aaa", "g-ccc"}, only_94

    # explicit id filter
    by_id = _select_workspaces(WS, ["g-bbb"], None)
    assert [w["id"] for w in by_id] == ["g-bbb"], by_id

    # id + version combined (g-bbb is 10.4, so 9.4 filter drops it -> empty)
    combined = _select_workspaces(WS, ["g-bbb"], "9.4")
    assert combined == [], combined

    # no filters returns all
    assert len(_select_workspaces(WS, None, None)) == 3


def test_grafana_base_url():
    # endpoint -> https URL, scheme preserved if present, trailing slash trimmed
    assert _grafana_base_url("g-x.grafana-workspace.us-east-1.amazonaws.com/") \
        == "https://g-x.grafana-workspace.us-east-1.amazonaws.com"
    assert _grafana_base_url("https://already.example.com") == "https://already.example.com"


def test_api_get_paginated():
    _pages = {
        1: [{"uid": "a"}, {"uid": "b"}],
        2: [{"uid": "c"}, {"uid": "d"}],
        3: [{"uid": "e"}]
    }

    def _fake_get(base_url, path, token):
        page = int(path.split("page=")[1])
        return _pages.get(page, [])

    _orig_get = amg._api_get
    amg._api_get = _fake_get
    try:
        paged = _api_get_paginated("https://x", "/api/search?type=dash-db", "tok", page_size=2)
        assert [i["uid"] for i in paged] == ["a", "b", "c", "d", "e"], paged
    finally:
        amg._api_get = _orig_get


def test_backup_simple_404_and_error():
    import tempfile
    errs = []

    def _raise_404(base_url, path, token):
        raise _NotFound(path)

    _orig_get = amg._api_get
    amg._api_get = _raise_404
    try:
        with tempfile.TemporaryDirectory() as d:
            out = amg._backup_simple("https://x", "tok", "/api/v1/provisioning/mute-timings",
                                     Path(d) / "mute.json", errs)
        assert out == [], out
        assert errs == [], errs  # 404 must NOT be recorded as an error
    finally:
        amg._api_get = _orig_get

    # Non-404 errors ARE recorded
    errs2 = []

    def _raise_boom(base_url, path, token):
        raise RuntimeError("boom")

    amg._api_get = _raise_boom
    try:
        with tempfile.TemporaryDirectory() as d:
            amg._backup_simple("https://x", "tok", "/api/folders", Path(d) / "f.json", errs2)
        assert len(errs2) == 1 and "boom" in errs2[0], errs2
    finally:
        amg._api_get = _orig_get


if __name__ == "__main__":
    test_select_workspaces()
    test_grafana_base_url()
    test_api_get_paginated()
    test_backup_simple_404_and_error()
    print("OK: all backup_amg_workspaces self-checks passed")
