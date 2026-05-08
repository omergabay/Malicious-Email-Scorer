import logging
import tldextract
import re
from typing import Dict, Any
from .base import BaseHeuristic

logger = logging.getLogger(__name__)

class SenderIdentityHeuristic(BaseHeuristic):
    @property
    def name(self) -> str:
        return "sender_identity"

    def _get_domain(self, email_header: str) -> str:
        """Extracts a valid registered domain from a messy raw email header."""
        if not email_header:
            return ""
            
        # 1. Clean the header: Extract exactly what is inside the < > brackets
        # If no brackets exist, just use the raw string.
        match = re.search(r'<([^>]+)>', email_header)
        clean_email = match.group(1) if match else email_header.strip()
        
        # 2. Grab ONLY the text after the '@' symbol
        if "@" in clean_email:
            domain_part = clean_email.split("@")[-1]
        else:
            domain_part = clean_email

        # 3. Finally, extract the safe, root domain
        ext = tldextract.extract(domain_part)
        
        # Only return the domain if both the domain and suffix (e.g., .com) exist
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}".lower()
            
        return ""

    async def evaluate(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        sender = (email_data.get("sender_address") or "").lower()
        return_path = (email_data.get("return_path") or "").lower()
        reply_to = (email_data.get("reply_to") or "").lower()
        auth_results = (email_data.get("authentication_results") or "").lower()
        
        s_domain = self._get_domain(sender)
        r_domain = self._get_domain(return_path)
        reply_domain = self._get_domain(reply_to)
        
        # 1. Check for SPF/DKIM/DMARC failures
        auth_failed = any(x in auth_results for x in ["spf=fail", "dkim=fail", "dmarc=fail"])
        
        # 2. Check for Domain Mismatch
        domain_mismatch = bool(s_domain and r_domain and s_domain != r_domain)
        
        # 3. Check Reply-To vs From
        reply_mismatch = bool(s_domain and reply_domain and s_domain != reply_domain)

        # 4. Enrichment: VirusTotal check
        domain_to_scan = r_domain if r_domain else s_domain
        
        vt_reputation = "unknown"
        if self.vt_client and domain_to_scan:
            logger.info(f"Enriching scan to domain '{domain_to_scan}' with VirusTotal...")
            try:
                vt_data = await self.vt_client.get_domain_report(domain_to_scan)
                if vt_data:
                    stats = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    if stats.get("malicious", 0) >= 3:
                        vt_reputation = "malicious"
                        logger.warning(f"VirusTotal flagged domain: {domain_to_scan}")
                    else:
                        vt_reputation = "clean"
            except Exception as e:
                logger.error(f"VirusTotal enrichment failed for {domain_to_scan}: {str(e)}")

        # --- Scoring Logic ---
        score = 0
        
        # High Risk: The domains don't match AND the security check failed
        if auth_failed and domain_mismatch:
            score += 50
        # Medium-Low Risk: The domains don't match, but the security check passed
        # (This is common in internal Gmail-to-Gmail routing)
        elif domain_mismatch:
            score += 15 
            
        if reply_mismatch:
            score += 20
        
        if vt_reputation == "malicious":
            score += 50

        return {
            "score": score,
            "details": {
                "score": score, 
                "auth_failed": auth_failed,
                "domain_mismatch": domain_mismatch,
                "reply_mismatch": reply_mismatch,
                "return_path_reputation": vt_reputation,
                "domains": {"from": s_domain, "return_path": r_domain, "reply_to": reply_domain}
            }
        }