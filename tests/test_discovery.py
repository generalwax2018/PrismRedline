"""Tests for nmap report-line parsing used by --target discovery."""

import pytest

import agent


@pytest.mark.parametrize(
    "line,expected",
    [
        ("Nmap scan report for 10.0.0.5", "10.0.0.5"),
        ("Nmap scan report for dc01.acme.local (10.0.0.5)", "10.0.0.5"),
        ("Nmap scan report for host.example.com", "host.example.com"),
    ],
)
def test_parse_report_host(line, expected):
    assert agent._parse_report_host(line) == expected
