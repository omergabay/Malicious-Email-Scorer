import logging
from typing import List, Dict, Any
from core.vt_client import VirusTotalClient
from .base import BaseHeuristic
from .social_engineering import SocialEngineeringHeuristic
from .sender_identity import SenderIdentityHeuristic
from .link_mismatch import LinkMismatchHeuristic
from .scan_attachments import AttachmentHeuristic

logger = logging.getLogger(__name__)

class HeuristicEngine:
    def __init__(self, vt_client: VirusTotalClient = None) -> None:
        self.heuristics: List[BaseHeuristic] = [
            SenderIdentityHeuristic(vt_client=vt_client),
            SocialEngineeringHeuristic(),
            LinkMismatchHeuristic(vt_client=vt_client),
            AttachmentHeuristic(vt_client=vt_client)
        ]

    async def analyze(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        total_score = 0
        breakdown = {}

        for heuristic in self.heuristics:
            try:
                result = await heuristic.evaluate(email_data)
                total_score += result["score"]
                breakdown[heuristic.name] = result["details"]
            except Exception as e:
                logger.error(f"Heuristic {heuristic.name} failed: {str(e)}")
                breakdown[heuristic.name] = {"error": "Analysis failed"}

        # --- Verdict Calculation ---
        # Cap the final score at 100
        final_score = min(total_score, 100)
        
        if final_score >= 50:
            verdict = "Malicious"
        elif final_score >= 20:
            verdict = "Suspicious"
        else:
            verdict = "Safe"

        return {
            "verdict": verdict,
            "total_score": final_score,
            "analysis": breakdown
        }