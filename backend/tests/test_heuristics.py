import pytest
from core.heuristics.engine import HeuristicEngine

# --- 1. The Mock Client ---
class MockVirusTotalClient:
    """
    A fake VT client that simulates the exact JSON response 
    of a malicious domain report without using real API calls.
    """
    async def get_domain_report(self, domain: str) -> dict:
        # Simulate hitting a known bad domain
        if domain == "hacked-server.ru":
            return {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 5,  # 5 engines flagged it as malicious
                            "suspicious": 2,
                            "harmless": 80,
                            "undetected": 5
                        }
                    }
                }
            }
        # Default clean response for any other domain
        return {
            "data": {"attributes": {"last_analysis_stats": {"malicious": 0}}}
        }

# --- 2. The Test ---
@pytest.mark.asyncio
async def test_engine_catches_bilingual_phishing_with_vt():
    # Arrange: Initialize the engine with our fake VT client
    mock_vt = MockVirusTotalClient()
    engine = HeuristicEngine(vt_client=mock_vt)

    # Simulated Email Data from the Gmail Add-on
    test_email = {
        "sender_address": "support@paypal-security-update.com",
        "return_path": "bounces@hacked-server.ru",
        "reply_to": "scammer123@gmail.com",
        "authentication_results": "spf=fail dkim=fail dmarc=fail",
        "body_plain": "החשבון שלך הושעה. אנא אפס סיסמה באופן מיידי. If you do not verify account, it will be closed. payment overdue."
    }

    # Act: Run the analysis
    result = await engine.analyze(test_email)

    # Assert: Verify the high-level engine logic
    assert result["verdict"] == "malicious", "Engine failed to flag a highly malicious email"
    assert result["total_score"] >= 80, f"Expected score >= 80, got {result['total_score']}"
    
    # 1. Verify Sender Identity caught the spoofing AND the VT Enrichment
    sender_details = result["analysis"]["sender_identity"]
    assert sender_details["auth_failed"] is True, "SPF/DKIM failure was not detected"
    assert sender_details["domain_mismatch"] is True, "Domain mismatch was not detected"
    assert sender_details["return_path_reputation"] == "malicious", "Failed to parse VT enrichment data"
    
    # 2. Verify Social Engineering caught the lethal combo in both languages
    # Using .get() gracefully handles either naming convention we discussed
    se_details = result["analysis"].get("social_engineering_language", result["analysis"].get("phishing_intent"))
    assert se_details is not None, "Social engineering details missing from analysis"
    
    categories = se_details