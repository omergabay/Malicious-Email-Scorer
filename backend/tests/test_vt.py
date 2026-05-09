"""
Live integration tests for VirusTotalClient.

These tests make real network requests and require VT_API_KEY to be set.
They are skipped automatically when the key is absent to keep CI green.
"""
import os
import pytest
from core.vt_client import VirusTotalClient

VT_API_KEY = os.getenv("VT_API_KEY")
requires_vt = pytest.mark.skipif(not VT_API_KEY, reason="VT_API_KEY not set")


@requires_vt
@pytest.mark.asyncio
async def test_live_domain_report_returns_data():
    """A live VT domain lookup for a known-clean domain should return stats."""
    client = VirusTotalClient(api_key=VT_API_KEY)
    report = await client.get_domain_report("github.com")

    assert report is not None, "Expected a report dict, got None"
    assert "data" in report, "Report missing 'data' key"
    stats = report["data"]["attributes"]["last_analysis_stats"]
    assert "malicious" in stats, "Stats missing 'malicious' key"


@requires_vt
@pytest.mark.asyncio
async def test_domain_report_is_cached_on_second_call():
    """The second call for the same domain should hit the TTL cache (no network request)."""
    client = VirusTotalClient(api_key=VT_API_KEY)

    first = await client.get_domain_report("github.com")
    assert first is not None

    # Populate cache, then verify cache hit path returns the same object
    second = await client.get_domain_report("github.com")
    assert second is first, "Second call should return the same cached object"
