import asyncio
import logging
from typing import Dict, Any, List, Set
from .base import BaseHeuristic

logger = logging.getLogger(__name__)

class AttachmentHeuristic(BaseHeuristic):
    @property
    def name(self) -> str:
        return "attachment_scan"

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.dangerous_exts: Set[str] = {
            "exe", "bat", "ps1", "scr", "vbs", "js", "jar", "msi", 
            "cmd", "com", "hta", "vbe", "jse", "wsf", "wsh",
            "pif", "lnk", "reg", "dll", "library-ms", "search-ms"
        }
        self.safe_double_exts: Set[str] = {
            "tar.gz", "tar.bz2", "tar.xz", "min.js", "min.css", "d.ts"
        }
        # NEW: A list of safe extensions attackers use as "lures"
        self.lure_exts: Set[str] = {
            "pdf", "doc", "docx", "xls", "xlsx", "txt", "csv", "jpg", "png", "zip"
        }

    def _analyze_file(self, filename: str) -> Dict[str, Any]:
        """Analyzes a filename for risky patterns."""
        parts = filename.lower().split('.')
        actual_ext = parts[-1] if parts else ""
        
        is_double_ext = False
        
        if len(parts) > 2:
            penultimate_ext = parts[-2]
            last_two = f"{penultimate_ext}.{actual_ext}"
            
            # SMART FILTER: It is only a threat if the middle part looks like a real extension
            # e.g., 'invoice.pdf.exe' -> 'pdf' is in lure_exts (Flag it!)
            # e.g., 'order.2026.pdf' -> '2026' is NOT in lure_exts (Ignore it!)
            if penultimate_ext in self.lure_exts or penultimate_ext in self.dangerous_exts:
                if last_two not in self.safe_double_exts:
                    is_double_ext = True
        
        return {
            "is_dangerous": actual_ext in self.dangerous_exts,
            "is_double_extension": is_double_ext,
            "extension": actual_ext
        }

    async def evaluate(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        attachments = email_data.get("attachments", [])
        if not attachments:
            return {"score": 0, "details": {"files_analyzed": 0}}

        double_ext_hashes: Set[str] = set()
        dangerous_ext_hashes: Set[str] = set()
        other_hashes: Set[str] = set()
        
        all_findings = []

        for att in attachments:
            name = att.get("filename", "unknown")
            sha256 = att.get("sha256")
            if not sha256: continue

            analysis = self._analyze_file(name)
            analysis["filename"] = name
            analysis["sha256"] = sha256
            all_findings.append(analysis)

            if analysis["is_double_extension"]:
                double_ext_hashes.add(sha256)
            elif analysis["is_dangerous"]:
                dangerous_ext_hashes.add(sha256)
            else:
                other_hashes.add(sha256)

        # --- Build Prioritized VT Queue ---
        # 1. Double Ext -> 2. Dangerous Ext -> 3. Others
        queue = list(double_ext_hashes)
        for h in dangerous_ext_hashes:
            if h not in queue: queue.append(h)
        for h in other_hashes:
            if h not in queue: queue.append(h)

        # Enrichment: Capped at 4 to respect VT rate limits
        vt_malicious_count = 0
        hashes_scanned = queue[:4]
        
        if hashes_scanned and self.vt_client:
            tasks = [self.vt_client.get_file_hash_report(h) for h in hashes_scanned]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for res in results:
                if res and not isinstance(res, Exception):
                    stats = res.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    if stats.get("malicious", 0) > 0:
                        vt_malicious_count += 1

        # --- Scoring Logic ---
        score = 0
        has_double = len(double_ext_hashes) > 0
        has_dangerous = len(dangerous_ext_hashes) > 0

        if vt_malicious_count > 0:
            score = 100  # Critical immediate fail
        elif has_double:
            score = 40   # High suspicion for obfuscation
        elif has_dangerous:
            score = 25   # Suspicious file type

        return {
            "score": score,
            "details": {
                "score": score,
                "files_analyzed": len(all_findings),
                "vt_hashes_scanned": hashes_scanned,
                "vt_malicious_hits": vt_malicious_count,
                "findings": all_findings
            }
        }