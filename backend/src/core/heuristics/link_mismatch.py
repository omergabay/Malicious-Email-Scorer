import asyncio
import logging
from bs4 import BeautifulSoup
import tldextract
from typing import Dict, Any, List, Set
from .base import BaseHeuristic

logger = logging.getLogger(__name__)

class LinkMismatchHeuristic(BaseHeuristic):
    @property
    def name(self) -> str:
        return "link_target_mismatch"

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.shorteners: Set[str] = {
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "qrco.de",
            "is.gd", "buff.ly", "cutt.ly", "rebrand.ly", "t.ly", "goo.su"
        }

    def _get_registered_domain(self, text: str) -> str:
        if not text:
            return ""
        ext = tldextract.extract(text)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}".lower()
        return ""

    async def evaluate(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        body_html = email_data.get("body_html", "")
        
        if not body_html:
            return {
                "score": 0, 
                "details": {
                    "score": 0,
                    "is_shortener": False,
                    "mismatch_found": False, 
                    "note": "No HTML body found."
                }
            }

        soup = BeautifulSoup(body_html, 'html.parser')
        mismatches: List[Dict[str, str]] = []
        mismatch_domains: Set[str] = set()
        shortener_domains: Set[str] = set()
        
        # --- 1. Parse HTML ---
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href'].strip()
            display_text = a_tag.get_text().strip()
            href_domain = self._get_registered_domain(href)
            text_domain = self._get_registered_domain(display_text)
            
            if not href_domain:
                continue 
                
            is_mismatch = bool(text_domain and text_domain != href_domain)
            is_shortener = href_domain in self.shorteners

            if is_mismatch:
                mismatches.append({"display": display_text, "actual_href": href})
                mismatch_domains.add(href_domain)
                
            if is_shortener:
                shortener_domains.add(href_domain)

        # --- 2. Build the Prioritized Queue ---
        # Order of operations: Mismatches first, then any Shorteners that aren't already in the list
        prioritized_scan_queue: List[str] = list(mismatch_domains)
        for domain in shortener_domains:
            if domain not in mismatch_domains:
                prioritized_scan_queue.append(domain)

        # --- 3. Enrichment: Concurrent VT Scans with Rate Limit Defense ---
        vt_malicious_hits = 0
        domains_scanned: List[str] = []
        
        if prioritized_scan_queue and self.vt_client:
            # VirusTotal allows to make up to 4 API calls per minute, so we'll cap the number of calls to 4
            domains_to_scan = prioritized_scan_queue[:4]
            domains_scanned = domains_to_scan
            
            if len(prioritized_scan_queue) > 4:
                logger.warning(f"Rate limit defense: Capping VT scans at 4. Ignored {len(prioritized_scan_queue) - 4} lower-priority domains.")

            logger.info(f"Concurrent VT Scan started for {len(domains_to_scan)} domains...")
            
            tasks = [self.vt_client.get_domain_report(domain) for domain in domains_to_scan]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for res in results:
                if isinstance(res, Exception):
                    logger.error(f"VT API call failed during concurrent scan: {str(res)}")
                    continue
                    
                if res:
                    stats = res.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    vt_malicious_hits += stats.get("malicious", 0)

        # --- 4. Dynamic Scoring Logic ---
        has_mismatch = len(mismatches) > 0
        has_suspicious_links = len(prioritized_scan_queue) > 0
        is_shortener_present = len(shortener_domains) > 0
        
        score = 0
        if vt_malicious_hits >= 3:
            score = 50  
        elif has_mismatch:
            score = 30  
        elif has_suspicious_links:
            score = 15  

        return {
            "score": score,
            "details": {
                "score": score,
                "is_shortener": is_shortener_present,
                "mismatch_found": has_mismatch,
                "mismatch_count": len(mismatches),
                "mismatched_links": mismatches,
                "vt_domains_scanned": domains_scanned,
                "vt_malicious_hits": vt_malicious_hits
            }
        }