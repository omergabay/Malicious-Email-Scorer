import pytest
from core.heuristics.link_mismatch import LinkMismatchHeuristic

# --- 1. The Mock Client ---
class MockVirusTotalClient:
    async def get_domain_report(self, domain: str) -> dict:
        # Simulate hitting a known bad domain hiding behind a mismatch
        if domain == "evil-phishing-site.com":
            return {
                "data": {"attributes": {"last_analysis_stats": {"malicious": 8}}}
            }
        # Simulate a clean response for a URL shortener
        return {
            "data": {"attributes": {"last_analysis_stats": {"malicious": 0}}}
        }

# --- 2. The Test ---
@pytest.mark.asyncio
async def test_link_mismatch_engine():
    # Arrange: Initialize the heuristic with our mock VT client
    mock_vt = MockVirusTotalClient()
    heuristic = LinkMismatchHeuristic(vt_client=mock_vt)

    # A carefully crafted HTML payload to test all edge cases
    test_email = {
        "body_html": """
        <html>
            <body>
                <p>Hello, your account has an issue.</p>
                
                <p>Please log in here: 
                   <a href="https://evil-phishing-site.com/login">https://www.paypal.com/secure</a>
                </p>
                
                <p>Track your shipment: 
                   <a href="http://bit.ly/xyz123">Click Here</a>
                </p>
                
                <p>Read our privacy policy: 
                   <a href="https://google.com/privacy">Google Privacy</a>
                </p>
            </body>
        </html>
        """
    }

    # Act: Run the analysis
    result = await heuristic.evaluate(test_email)
    details = result["details"]

    # Assert: Verify the engine logic
    # 1. Did it catch the mismatch?
    assert details["mismatch_found"] is True, "Failed to detect the HTML mismatch"
    assert details["mismatch_count"] == 1, "Should only find 1 mismatch"
    assert details["mismatched_links"][0]["actual_href"] == "https://evil-phishing-site.com/login"

    # 2. Did the prioritized queue work? (It should scan both, but order matters internally)
    scanned_domains = details["vt_domains_scanned"]
    assert len(scanned_domains) == 2, "Should have scanned the mismatch and the shortener"
    assert "evil-phishing-site.com" in scanned_domains
    assert "bit.ly" in scanned_domains

    # 3. Did it score correctly? (Mismatch + Malicious VT hit = 50 points)
    assert details["vt_malicious_hits"] == 1, "Failed to parse the malicious VT hit"
    assert result["score"] == 50, f"Expected critical score of 50, got {result['score']}"