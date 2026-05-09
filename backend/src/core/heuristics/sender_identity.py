import logging
import tldextract
import re
import json
import os
from typing import Dict, Any, Set
from .base import BaseHeuristic

logger = logging.getLogger(__name__)

class SenderIdentityHeuristic(BaseHeuristic):
    """Validates sender authenticity via SPF/DKIM/DMARC, domain mismatch detection, and VT reputation."""

    @property
    def name(self) -> str:
        return "sender_identity"

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.allowlist: Set[str] = set()
        self._load_trusted_domains()

    def _load_trusted_domains(self) -> None:
        """Loads trusted domain allowlist from JSON at startup."""
        file_path = os.path.join(os.path.dirname(__file__), "data", "trusted_domains.json")
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                categories = json.load(f)
            for domains in categories.values():
                for domain in domains:
                    self.allowlist.add(domain.lower())
            logger.info(f"Loaded {len(self.allowlist)} trusted domains into the allowlist.")
        except FileNotFoundError:
            logger.error(f"Allowlist file missing at {file_path}. Sender analysis degraded.")
            self.allowlist = {"google.com"}

    def _get_domain(self, email_header: str) -> str:
        """Extracts a registered domain from a raw email header string.

        Handles angle-bracket notation (e.g. 'Display Name <user@domain.com>')
        and falls back to treating the whole string as a domain or URL.

        Args:
            email_header: Raw header value from From, Return-Path, or Reply-To.

        Returns:
            Lowercase registered domain (e.g. 'example.com'), or empty string.
        """
        if not email_header:
            return ""
        match = re.search(r'<([^>]+)>', email_header)
        clean_email = match.group(1) if match else email_header.strip()
        domain_part = clean_email.split("@")[-1] if "@" in clean_email else clean_email
        ext = tldextract.extract(domain_part)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}".lower()
        return ""

    async def evaluate(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Scores the email sender for spoofing and reputation signals.

        Args:
            email_data: Parsed email payload dict.

        Returns:
            Dict with 'score' (int) and 'details' (dict of findings).
        """
        sender = (email_data.get("sender_address") or "").lower()
        return_path = (email_data.get("return_path") or "").lower()
        reply_to = (email_data.get("reply_to") or "").lower()
        auth_results = (email_data.get("authentication_results") or "").lower()

        s_domain = self._get_domain(sender)
        r_domain = self._get_domain(return_path)
        reply_domain = self._get_domain(reply_to)

        auth_failed = any(x in auth_results for x in ["spf=fail", "dkim=fail", "dmarc=fail"])
        domain_mismatch = bool(s_domain and r_domain and s_domain != r_domain)
        reply_mismatch = bool(s_domain and reply_domain and s_domain != reply_domain)

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

        score = 0
        if auth_failed and domain_mismatch:
            score += 50
        elif domain_mismatch:
            score += 15
        if reply_mismatch:
            score += 20
        if vt_reputation == "malicious":
            score += 50

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
