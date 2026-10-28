"""Parser tests for the expanded external-tool registry."""

from __future__ import annotations

import json
from pathlib import Path

from coldtrail.integrations import TOOLS


def test_amass_parser():
    parsed = TOOLS["amass"].parse("a.example.com\nb.example.com\n", "example.com", Path("."))
    assert {entity.value for entity in parsed.entities} == {"a.example.com", "b.example.com"}


def test_nuclei_parser():
    stdout = json.dumps(
        {
            "template-id": "CVE-2024-0001",
            "matched-at": "https://example.com/x",
            "info": {"severity": "high"},
        }
    )
    parsed = TOOLS["nuclei"].parse(stdout, "example.com", Path("."))
    assert parsed.entities[0].kind == "vulnerability"
    assert parsed.entities[0].value == "CVE-2024-0001"
    assert "high" in parsed.entities[0].context


def test_naabu_parser():
    parsed = TOOLS["naabu"].parse("example.com:443\nexample.com:80\n", "example.com", Path("."))
    assert [entity.value for entity in parsed.entities] == ["example.com:443", "example.com:80"]


def test_gitleaks_parser_does_not_store_secret_value():
    stdout = json.dumps(
        [{"RuleID": "aws-key", "File": "config.py", "StartLine": 12, "Secret": "AKIA...SECRET"}]
    )
    parsed = TOOLS["gitleaks"].parse(stdout, "repo", Path("."))
    assert parsed.entities[0].value == "aws-key @ config.py:12"
    assert "AKIA" not in parsed.entities[0].value


def test_phoneinfoga_parser():
    parsed = TOOLS["phoneinfoga"].parse(
        "Carrier: Example\nCountry: US\n", "+14155552671", Path(".")
    )
    assert parsed.profiles[0].source == "phoneinfoga"
    assert parsed.entities[0].kind == "phone"
