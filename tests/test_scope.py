"""
Unit tests for PrismRedline scope matching.

These are pure-logic tests: no network, no Kali tools, no Ollama required.
"""

import pytest

import agent


# --------------------------------------------------------------------------- #
# _host_from_target: normalize URLs / IP:port down to a bare host
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "target,expected",
    [
        ("10.0.0.5", "10.0.0.5"),
        ("http://target.local:8080/app", "target.local"),
        ("https://api.target.local", "api.target.local"),
        ("target.local:443", "target.local"),
        ("  192.168.1.10  ", "192.168.1.10"),
    ],
)
def test_host_from_target(target, expected):
    assert agent._host_from_target(target) == expected


# --------------------------------------------------------------------------- #
# _matches_entry: CIDR, single IP, hostname/subdomain
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "host,entry,expected",
    [
        # CIDR ranges
        ("10.5.4.3", "10.0.0.0/8", True),
        ("192.168.1.50", "192.168.1.0/24", True),
        ("192.168.2.50", "192.168.1.0/24", False),
        # substring false-positive guard (the pre-fix bug)
        ("110.0.0.10", "10.0.0.0/8", False),
        # single IP equality
        ("10.0.0.1", "10.0.0.1", True),
        ("10.0.0.2", "10.0.0.1", False),
        # hostname exact + subdomain
        ("target.local", "target.local", True),
        ("api.target.local", "target.local", True),
        ("eviltarget.local", "target.local", False),
        ("evil.com", "target.local", False),
        # a name can never match a network entry
        ("target.local", "10.0.0.0/8", False),
    ],
)
def test_matches_entry(host, entry, expected):
    assert agent._matches_entry(host, entry) is expected


# --------------------------------------------------------------------------- #
# in_scope: end-to-end against a temp scope.json
# --------------------------------------------------------------------------- #
@pytest.fixture
def temp_scope(tmp_path, monkeypatch):
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(
        '{"name": "t", "allowed": ["10.0.0.0/8", "192.168.1.0/24", "target.local"]}'
    )
    monkeypatch.setattr(agent, "SCOPE_FILE", scope_file)
    return scope_file


@pytest.mark.parametrize(
    "target,expected",
    [
        ("10.5.4.3", True),
        ("http://target.local:8080/app", True),
        ("api.target.local", True),
        ("192.168.2.50", False),
        ("evil.com", False),
        ("110.0.0.10", False),
    ],
)
def test_in_scope(temp_scope, target, expected):
    assert agent.in_scope(target) is expected


def test_in_scope_no_scope_file(tmp_path, monkeypatch):
    monkeypatch.setattr(agent, "SCOPE_FILE", tmp_path / "missing.json")
    assert agent.in_scope("10.0.0.1") is False
