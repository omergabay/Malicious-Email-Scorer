import pytest
from core.heuristics.engine import HeuristicEngine


class MockVirusTotalClient:
    """Fake VT client that simulates a malicious domain report without live API calls."""

    async def get_domain_report(self, domain: str) -> dict:
        if domain == "hacked-server.ru":
            return {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 5,
                            "suspicious": 2,
                            "harmless": 80,
                            "undetected": 5
                        }
                    }
                }
            }
        return {"data": {"attributes": {"last_analysis_stats": {"malicious": 0}}}}

    async def get_file_hash_report(self, file_hash: str) -> dict:
        return {"data": {"attributes": {"last_analysis_stats": {"malicious": 0}}}}


@pytest.mark.asyncio
async def test_engine_catches_bilingual_phishing_with_vt():
    mock_vt = MockVirusTotalClient()
    engine = HeuristicEngine(vt_client=mock_vt)

    test_email = {
        "sender_address": "support@paypal-security-update.com",
        "return_path": "bounces@hacked-server.ru",
        "reply_to": "scammer123@gmail.com",
        "authentication_results": "spf=fail dkim=fail dmarc=fail",
        "body_plain": "החשבון שלך הושעה. אנא אפס סיסמה באופן מיידי. If you do not verify account, it will be closed. payment overdue.",
        "body_html": "",
        "attachments": []
    }

    result = await engine.analyze(test_email)

    assert result["verdict"] == "Malicious", f"Expected 'Malicious', got '{result['verdict']}'"
    assert result["total_score"] >= 80, f"Expected score >= 80, got {result['total_score']}"

    sender_details = result["analysis"]["sender_identity"]
    assert sender_details["auth_failed"] is True, "SPF/DKIM failure was not detected"
    assert sender_details["domain_mismatch"] is True, "Domain mismatch was not detected"
    assert sender_details["return_path_reputation"] == "malicious", "VT enrichment data was not parsed"

    se_details = result["analysis"]["social_engineering"]
    assert se_details is not None, "Social engineering details missing from analysis"
    assert isinstance(se_details["categories_triggered"], dict), "categories_triggered should be a dict"
    assert len(se_details["categories_triggered"]) > 0, "No social engineering categories were triggered"

    assert "link_target_mismatch" in result["analysis"], "link_target_mismatch missing from analysis"
    assert "attachment_scan" in result["analysis"], "attachment_scan missing from analysis"

    assert len(result["analyst_report"]) > 0, "Analyst report should not be empty for a malicious email"


@pytest.mark.asyncio
async def test_engine_returns_safe_for_clean_email():
    engine = HeuristicEngine(vt_client=None)

    clean_email = {
        "sender_address": "newsletter@google.com",
        "return_path": "bounces@google.com",
        "reply_to": None,
        "authentication_results": "spf=pass dkim=pass dmarc=pass",
        "body_plain": "Thank you for using Google services.",
        "body_html": "",
        "attachments": []
    }

    result = await engine.analyze(clean_email)

    assert result["verdict"] == "Safe", f"Expected 'Safe', got '{result['verdict']}'"
    assert result["total_score"] < 20, f"Expected score < 20, got {result['total_score']}"


@pytest.mark.asyncio
async def test_engine_handles_heuristic_failure_gracefully():
    """Engine should degrade gracefully when a heuristic raises an exception."""

    class BrokenVTClient:
        async def get_domain_report(self, domain: str):
            raise ConnectionError("Simulated network failure")

        async def get_file_hash_report(self, file_hash: str):
            raise ConnectionError("Simulated network failure")

    engine = HeuristicEngine(vt_client=BrokenVTClient())

    test_email = {
        "sender_address": "test@example.com",
        "return_path": "test@example.com",
        "reply_to": None,
        "authentication_results": "spf=pass",
        "body_plain": "Hello world.",
        "body_html": "",
        "attachments": []
    }

    result = await engine.analyze(test_email)
    assert "verdict" in result
    assert "total_score" in result
