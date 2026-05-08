import pytest
from core.heuristics.scan_attachments import AttachmentHeuristic

# --- 1. The Mock Client ---
class MockVTClient:
    async def get_file_hash_report(self, file_hash: str) -> dict:
        # Simulate a known malicious payload
        if file_hash == "malicious_hash_123":
            return {"data": {"attributes": {"last_analysis_stats": {"malicious": 15}}}}
        
        # Everything else returns clean to test our offline heuristic scores
        return {"data": {"attributes": {"last_analysis_stats": {"malicious": 0}}}}


# --- 2. The Tests ---

@pytest.mark.asyncio
async def test_attachment_critical_vt_hit():
    """Proves that a known malicious hash instantly triggers a 100-point failure."""
    heuristic = AttachmentHeuristic(vt_client=MockVTClient())

    test_payload = {
        "attachments": [
            {"filename": "normal_invoice.pdf", "sha256": "malicious_hash_123"}
        ]
    }

    result = await heuristic.evaluate(test_payload)
    
    assert result["score"] == 100, "Failed to score 100 on a confirmed VT malicious hit"
    assert result["details"]["vt_malicious_hits"] == 1


@pytest.mark.asyncio
async def test_attachment_prioritization_and_rate_limit():
    """
    Proves the engine prioritizes Double Extensions > Dangerous Exts > Others,
    AND respects the 4-request rate limit cap.
    """
    heuristic = AttachmentHeuristic(vt_client=MockVTClient())

    # We throw 6 attachments at the engine.
    test_payload = {
        "attachments": [
            {"filename": "safe_photo1.jpg", "sha256": "hash_safe_1"},      # Priority 3
            {"filename": "safe_photo2.png", "sha256": "hash_safe_2"},      # Priority 3
            {"filename": "sneaky.pdf.exe", "sha256": "hash_double_1"},     # Priority 1 (Double Ext)
            {"filename": "script.ps1", "sha256": "hash_danger_1"},         # Priority 2 (Dangerous)
            {"filename": "hidden.txt.vbs", "sha256": "hash_double_2"},     # Priority 1 (Double Ext)
            {"filename": "registry.reg", "sha256": "hash_danger_2"}        # Priority 2 (Dangerous)
        ]
    }

    result = await heuristic.evaluate(test_payload)
    scanned_hashes = result["details"]["vt_hashes_scanned"]

    # 1. Did it respect the rate limit?
    assert len(scanned_hashes) == 4, "Engine failed to cap the VT scans at 4"

    # 2. Did it prioritize correctly? (Safe hashes should NOT be in the scanned list)
    assert "hash_double_1" in scanned_hashes, "Failed to prioritize double extension"
    assert "hash_double_2" in scanned_hashes, "Failed to prioritize double extension"
    assert "hash_danger_1" in scanned_hashes, "Failed to prioritize dangerous extension"
    assert "hash_danger_2" in scanned_hashes, "Failed to prioritize dangerous extension"
    assert "hash_safe_1" not in scanned_hashes, "Scanned a safe file instead of a dangerous one!"


@pytest.mark.asyncio
async def test_attachment_offline_scoring():
    """Proves the engine still flags dangerous files even if VT says they are clean."""
    heuristic = AttachmentHeuristic(vt_client=MockVTClient())

    test_payload = {
        "attachments": [
            {"filename": "clean_but_double.pdf.scr", "sha256": "clean_hash_1"}
        ]
    }
    
    result_double = await heuristic.evaluate(test_payload)
    
    # VT is mocked to return clean for "clean_hash_1", so it relies purely on the double-extension logic
    assert result_double["score"] == 40, "Failed to score 40 for a clean double extension"

    test_payload_danger = {
        "attachments": [
            {"filename": "clean_but_dangerous.lnk", "sha256": "clean_hash_2"}
        ]
    }
    
    result_danger = await heuristic.evaluate(test_payload_danger)
    
    # VT is clean, but .lnk is in your new dangerous extensions list
    assert result_danger["score"] == 25, "Failed to score 25 for a clean but dangerous extension"