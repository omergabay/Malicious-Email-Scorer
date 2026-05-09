import logging
import asyncio
from typing import List, Dict, Any
from core.vt_client import VirusTotalClient
from .base import BaseHeuristic
from .social_engineering import SocialEngineeringHeuristic
from .sender_identity import SenderIdentityHeuristic
from .link_mismatch import LinkMismatchHeuristic
from .scan_attachments import AttachmentHeuristic

logger = logging.getLogger(__name__)

class HeuristicEngine:
    """Orchestrates all heuristics, aggregates scores, and produces a threat report."""

    def __init__(self, vt_client: VirusTotalClient = None) -> None:
        """
        Args:
            vt_client: Optional VirusTotal client. When None, VT enrichment is skipped.
        """
        self.heuristics: List[BaseHeuristic] = [
            SenderIdentityHeuristic(vt_client=vt_client),
            SocialEngineeringHeuristic(),
            LinkMismatchHeuristic(vt_client=vt_client),
            AttachmentHeuristic(vt_client=vt_client)
        ]

    async def analyze(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Runs all heuristics concurrently and returns a structured threat report.

        Args:
            email_data: Parsed email payload dict matching EmailPayload schema.

        Returns:
            Dict with keys: verdict, total_score, analysis, analyst_report.
        """
        tasks = [h.evaluate(email_data) for h in self.heuristics]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        breakdown = {}
        critical_threat_found = False

        for i, heuristic in enumerate(self.heuristics):
            res = results[i]
            if isinstance(res, Exception):
                logger.error(f"Heuristic {heuristic.name} failed: {str(res)}")
                breakdown[heuristic.name] = {"error": "Analysis failed", "_raw_score": 0}
                continue

            if res["score"] >= 100:
                critical_threat_found = True

            breakdown[heuristic.name] = res["details"]
            breakdown[heuristic.name]["_raw_score"] = res["score"]

        sender_ctx = breakdown.get("sender_identity", {})
        soc_eng_ctx = breakdown.get("social_engineering", {})

        if sender_ctx.get("is_allowlisted", False):
            logger.info("Verified Allowlist Sender: Dampening Social Engineering score.")
            soc_eng_ctx["_raw_score"] = int(soc_eng_ctx.get("_raw_score", 0) * 0.2)

        is_spoofed = sender_ctx.get("domain_mismatch", False)
        has_phishing_intent = soc_eng_ctx.get("_raw_score", 0) > 10

        spear_phishing_multiplier = 1.0
        if is_spoofed and has_phishing_intent:
            logger.warning("COMPOUND THREAT: Spoofed Identity + Phishing Language detected.")
            spear_phishing_multiplier = 1.5

        total_score = sum(h.get("_raw_score", 0) for h in breakdown.values() if isinstance(h, dict))
        total_score = int(total_score * spear_phishing_multiplier)

        for h in breakdown.values():
            if isinstance(h, dict):
                h.pop("_raw_score", None)

        final_score = min(total_score, 100)

        if critical_threat_found:
            verdict = "Malicious"
            final_score = 100
        elif final_score >= 50:
            verdict = "Malicious"
        elif final_score >= 20:
            verdict = "Suspicious"
        else:
            verdict = "Safe"

        return {
            "verdict": verdict,
            "total_score": final_score,
            "analysis": breakdown,
            "analyst_report": self._generate_analyst_report(breakdown, final_score)
        }

    def _generate_analyst_report(self, breakdown: Dict[str, Any], final_score: int) -> List[str]:
        """Produces human-readable threat findings from the heuristic breakdown.

        Args:
            breakdown: Heuristic result dicts keyed by heuristic name.
            final_score: Capped aggregate score (0–100).

        Returns:
            List of HTML-formatted finding strings (may include emoji indicators).
        """
        report = []
        sender_ctx = breakdown.get("sender_identity", {})
        soc_eng_ctx = breakdown.get("social_engineering", {})
        link_ctx = breakdown.get("link_target_mismatch", {})
        att_ctx = breakdown.get("attachment_scan", {})

        if sender_ctx.get("is_allowlisted"):
            report.append(f"🟢 <b>Trusted Sender:</b> Email originates from a verified enterprise domain ({sender_ctx.get('domains', {}).get('from')}).")
        elif sender_ctx.get("domain_mismatch"):
            report.append(f"🔴 <b>Spoofed Sender:</b> Visible address ({sender_ctx.get('domains', {}).get('from')}) does not match the actual routing domain ({sender_ctx.get('domains', {}).get('return_path')}).")

        if sender_ctx.get("auth_failed"):
            report.append("🔴 <b>Auth Failed:</b> SPF/DKIM signatures are invalid or missing.")

        if sender_ctx.get("return_path_reputation") == "malicious":
            report.append("🔴 <b>Malicious Infra:</b> Sender domain flagged by VirusTotal.")

        if soc_eng_ctx.get("categories_triggered"):
            hits = []
            for cat, words in soc_eng_ctx["categories_triggered"].items():
                clean_cat = cat.replace('_', ' ').title()
                hits.append(f"{clean_cat} ('{', '.join(words)}')")
            report.append(f"🟠 <b>Suspicious Text:</b> Detected high-risk phrasing: {'; '.join(hits)}.")

        if link_ctx.get("vt_malicious_hits", 0) >= 1:
            report.append("🔴 <b>Malicious Links:</b> VirusTotal confirmed link(s) point to malware/phishing sites.")
        elif link_ctx.get("mismatch_found"):
            mismatches = link_ctx.get("mismatched_links", [])
            examples = [f"'{m['display']}' redirects to '{m['actual_href']}'" for m in mismatches[:1]]
            count = link_ctx.get('mismatch_count')
            report.append(f"🟠 <b>Deceptive Links:</b> Found {count} link(s) masking their true destination. (e.g., {examples[0]})")
        if link_ctx.get("is_shortener"):
            report.append("🟠 <b>Obfuscation:</b> Uses URL shorteners to hide final destinations.")

        if att_ctx.get("vt_malicious_hits", 0) > 0:
            report.append("🔴 <b>Malware:</b> VirusTotal confirmed attachment contains malware.")
        elif att_ctx.get("findings"):
            for file in att_ctx.get("findings", []):
                if file.get("is_dangerous"):
                    report.append(f"🟠 <b>Dangerous File:</b> '{file.get('filename')}' uses a high-risk executable extension.")
                if file.get("is_double_extension"):
                    report.append(f"🟠 <b>Suspicious File:</b> '{file.get('filename')}' uses a deceptive double extension.")

        if not report and final_score < 20:
            report.append("🟢 <b>Clean:</b> No suspicious indicators found across standard heuristics.")

        return report
