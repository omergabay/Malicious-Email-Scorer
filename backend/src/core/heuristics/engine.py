import logging
import asyncio # NEW: Required for concurrent execution
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
        # 1. Fire all heuristics CONCURRENTLY
        # Instead of 'await' inside a loop, we create a list of tasks
        tasks = [h.evaluate(email_data) for h in self.heuristics]
        
        # 2. Wait for all tasks to complete in parallel
        # results will be a list containing the output of each heuristic in order
        results = await asyncio.gather(*tasks, return_exceptions=True)

        breakdown = {}
        critical_threat_found = False

        # 3. Process the results back into the breakdown dictionary
        for i, heuristic in enumerate(self.heuristics):
            res = results[i]
            
            # Error handling for individual heuristic failures
            if isinstance(res, Exception):
                logger.error(f"Heuristic {heuristic.name} failed: {str(res)}")
                breakdown[heuristic.name] = {"error": "Analysis failed", "_raw_score": 0}
                continue

            # CRITICAL OVERRIDE: If VT found malware, skip the math and lock it down.
            if res["score"] >= 100:
                critical_threat_found = True
                
            breakdown[heuristic.name] = res["details"]
            breakdown[heuristic.name]["_raw_score"] = res["score"]

        # --- Extract Context for Inter-Heuristic Logic ---
        sender_ctx = breakdown.get("sender_identity", {})
        soc_eng_ctx = breakdown.get("social_engineering", {})
        
        # --- 4. Dampening (False Positive Reduction) ---
        if sender_ctx.get("is_allowlisted", False):
            logger.info("Verified Allowlist Sender: Dampening Social Engineering score.")
            current_se_score = soc_eng_ctx.get("_raw_score", 0)
            soc_eng_ctx["_raw_score"] = int(current_se_score * 0.2)
            
        # --- 5. Compound Multipliers (False Negative Reduction) ---
        is_spoofed = sender_ctx.get("domain_mismatch", False)
        has_phishing_intent = soc_eng_ctx.get("_raw_score", 0) > 10
        
        spear_phishing_multiplier = 1.0
        if is_spoofed and has_phishing_intent:
            logger.warning("COMPOUND THREAT: Spoofed Identity + Phishing Language detected.")
            spear_phishing_multiplier = 1.5

        # --- Final Math Calculation ---
        total_score = sum(h.get("_raw_score", 0) for h in breakdown.values() if isinstance(h, dict))
        total_score = int(total_score * spear_phishing_multiplier)

        # Clean up internal variables before sending to UI
        for h in breakdown.values():
            if isinstance(h, dict):
                h.pop("_raw_score", None)

        final_score = min(total_score, 100)
        
        # Apply strict verdict locking
        if critical_threat_found:
            verdict = "Malicious"
            final_score = 100
        elif final_score >= 50:
            verdict = "Malicious"
        elif final_score >= 20:
            verdict = "Suspicious"
        else:
            verdict = "Safe"

        # --- 6. GENERATE DETAILED ANALYST REPORT ---
        analyst_report = []

        if sender_ctx.get("is_allowlisted"):
            analyst_report.append(f"🟢 <b>Trusted Sender:</b> Email originates from a verified enterprise domain ({sender_ctx.get('domains', {}).get('from')}).")
        elif sender_ctx.get("domain_mismatch"):
            analyst_report.append(f"🔴 <b>Spoofed Sender:</b> Visible address ({sender_ctx.get('domains', {}).get('from')}) does not match the actual routing domain ({sender_ctx.get('domains', {}).get('return_path')}).")
            
        if sender_ctx.get("auth_failed"):
            analyst_report.append("🔴 <b>Auth Failed:</b> SPF/DKIM signatures are invalid or missing.")
            
        if sender_ctx.get("return_path_reputation") == "malicious":
            analyst_report.append("🔴 <b>Malicious Infra:</b> Sender domain flagged by VirusTotal.")

        # Social Engineering Evidence
        if soc_eng_ctx.get("categories_triggered"):
            hits = []
            for cat, words in soc_eng_ctx["categories_triggered"].items():
                clean_cat = cat.replace('_', ' ').title()
                hits.append(f"{clean_cat} ('{', '.join(words)}')")
            analyst_report.append(f"🟠 <b>Suspicious Text:</b> Detected high-risk phrasing: {'; '.join(hits)}.")

        # Link Evidence
        link_ctx = breakdown.get("link_target_mismatch", {})
        if link_ctx.get("vt_malicious_hits", 0) >= 3:
            analyst_report.append("🔴 <b>Malicious Links:</b> VirusTotal confirmed link(s) point to malware/phishing sites.")
        elif link_ctx.get("mismatch_found"):
            mismatches = link_ctx.get("mismatched_links", [])
            examples = [f"'{m['display']}' redirects to '{m['actual_href']}'" for m in mismatches[:1]]
            count = link_ctx.get('mismatch_count')
            analyst_report.append(f"🟠 <b>Deceptive Links:</b> Found {count} link(s) masking their true destination. (e.g., {examples[0]})")
        if link_ctx.get("is_shortener"):
            analyst_report.append("🟠 <b>Obfuscation:</b> Uses URL shorteners to hide final destinations.")

        # Attachment Evidence
        att_ctx = breakdown.get("attachment_scan", {})
        if att_ctx.get("vt_malicious_hits", 0) > 0:
            analyst_report.append("🔴 <b>Malware:</b> VirusTotal confirmed attachment contains malware.")
        elif att_ctx.get("findings"):
            for file in att_ctx.get("findings", []):
                if file.get("is_dangerous"):
                    analyst_report.append(f"🟠 <b>Dangerous File:</b> '{file.get('filename')}' uses a high-risk executable extension.")
                if file.get("is_double_extension"):
                    analyst_report.append(f"🟠 <b>Suspicious File:</b> '{file.get('filename')}' uses a deceptive double extension.")

        if len(analyst_report) == 0 and final_score < 20:
            analyst_report.append("🟢 <b>Clean:</b> No suspicious indicators found across standard heuristics.")

        return {
            "verdict": verdict,
            "total_score": final_score,
            "analysis": breakdown,
            "analyst_report": analyst_report
        }