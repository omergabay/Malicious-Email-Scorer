import logging
import tldextract
import re
import json
import os
from typing import Dict, Any, Set
from .base import BaseHeuristic

logger = logging.getLogger(__name__)

class SenderIdentityHeuristic(BaseHeuristic):
    @property
    def name(self) -> str:
        return "sender_identity"

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.allowlist: Set[str] = set()
        self._load_trusted_domains()

    def _load_trusted_domains(self) -> None:
        """Loads the trusted domain allowlist into memory once at startup."""
        file_path = os.path.join(os.path.dirname(__file__), "data", "trusted_domains.json")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                categories = json.load(f)
                
            # Flatten the categorized lists into a single, lightning-fast Set
            for domains in categories.values():
                for domain in domains:
                    self.allowlist.add(domain.lower())
                    
            logger.info(f"Loaded {len(self.allowlist)} trusted domains into the allowlist.")
            
        except FileNotFoundError:
            logger.error(f"Allowlist file missing at {file_path}. Sender analysis degraded.")
            # Fallback to absolute bare minimums if the file is missing
            self.allowlist = {"google.com"}

    def _get_domain(self, email_header: str) -> str:
        """Extracts a valid registered domain from a messy raw email header."""
        if not email_header:
            return ""
            
        # 1. Clean the header: Extract exactly what is inside the < > brackets
        match = re.search(r'<([^>]+)>', email_header)
        clean_email = match.group(1) if match else email_header.strip()
        
        # 2. Grab ONLY the text after the '@' symbol
        if "@" in clean_email:
            domain_part = clean_email.split("@")[-1]
        else:
            domain_part = clean_email

        # 3. Finally, extract the safe, root domain
        ext = tldextract.extract(domain_part)
        
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
        
        if auth_failed and domain_mismatch:
            score += 50
        elif domain_mismatch:
            score += 15 
            
        if reply_mismatch:
            score += 20
        
        if vt_reputation == "malicious":
            score += 50

        # Determine if this is a cryptographically verified trusted sender
        is_allowlisted = bool(s_domain in self.allowlist and not auth_failed)

        return {
            "score": score,
            "details": {
                "score": score, 
                "auth_failed": auth_failed,
                "domain_mismatch": domain_mismatch,
                "reply_mismatch": reply_mismatch,
                "return_path_reputation": vt_reputation,
                "is_allowlisted": is_allowlisted,
                "domains": {"from": s_domain, "return_path": r_domain, "reply_to": reply_domain}
            }
        }