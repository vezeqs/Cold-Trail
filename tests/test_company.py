"""Corporate/sanctions provider tests."""

from __future__ import annotations

import httpx
import pytest
import respx

from coldtrail.company import company_search
from coldtrail.config import Settings
from coldtrail.http import Fetcher


@pytest.fixture
def settings(tmp_path):
    return Settings(db_path=tmp_path / "t.db", requests_per_second=0, jitter=0)


@respx.mock
async def test_opensanctions(settings):
    settings.opensanctions_api_key = "key"
    respx.get(
        "https://api.opensanctions.org/search/default",
        headers={"Authorization": "ApiKey key"},
    ).mock(
        return_value=httpx.Response(
            200,
            json={
                "results": [
                    {
                        "caption": "Acme Ltd",
                        "id": "Q1",
                        "schema": "Company",
                        "datasets": ["us_ofac"],
                        "score": 0.9,
                    }
                ]
            },
        )
    )
    async with Fetcher(settings) as fetcher:
        rows = await company_search(fetcher, "acme", settings)
    assert rows[0]["provider"] == "opensanctions"
    assert rows[0]["name"] == "Acme Ltd"


@respx.mock
async def test_opencorporates(settings):
    settings.opencorporates_api_key = "key"
    respx.get("https://api.opencorporates.com/v0.4/companies/search").mock(
        return_value=httpx.Response(
            200,
            json={
                "results": {
                    "companies": [
                        {
                            "company": {
                                "name": "Acme Ltd",
                                "jurisdiction_code": "gb",
                                "company_number": "123",
                                "current_status": "Active",
                            }
                        }
                    ]
                }
            },
        )
    )
    async with Fetcher(settings) as fetcher:
        rows = await company_search(fetcher, "acme", settings, provider="opencorporates")
    assert rows[0]["number"] == "123"
    assert rows[0]["jurisdiction"] == "gb"
