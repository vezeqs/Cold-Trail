from __future__ import annotations

from larpharvester.utils import host_of, norm, norm_url, strip_html


def test_strip_html():
    assert strip_html("<p>Hello <b>world</b></p>") == "Hello world"
    assert strip_html("") is None
    assert strip_html(None) is None


def test_norm_collapses_case_and_whitespace():
    assert norm("  Hello   World ") == "hello world"
    assert norm(None) == ""


def test_norm_url_ignores_scheme_www_query_and_trailing_slash():
    assert norm_url("https://www.Example.com/path/?utm=1") == "example.com/path"
    assert norm_url("http://example.com/path") == "example.com/path"
    assert norm_url(None) == ""


def test_host_of():
    assert host_of("https://www.example.com/a/b") == "example.com"
    assert host_of("") == ""
