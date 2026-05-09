import re
import json
import os
import logging
from typing import Dict, Any, List
from .base import BaseHeuristic

logger = logging.getLogger(__name__)

class SocialEngineeringHeuristic(BaseHeuristic):
    @property
    def name(self) -> str:
        return "social_engineering"

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        
        self.categories: Dict[str, List[str]] = {}
        self.pattern: re.Pattern = re.compile(r"")
        
        # Load the external threat feed into memory ONCE at startup (Zero latency per request)
        self._load_threat_intel()

    def _load_threat_intel(self) -> None:
        file_path = os.path.join(os.path.dirname(__file__), "data", "phishing_keywords.json")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                self.categories = json.load(f)
                
            all_words = []
            for words in self.categories.values():
                all_words.extend(words)
                
            if all_words:
                escaped_words = [re.escape(w) for w in all_words]
                self.pattern = re.compile(rf"\b({'|'.join(escaped_words)})\b", re.IGNORECASE)
                logger.info(f"Loaded {len(all_words)} threat indicators across {len(self.categories)} categories.")
                
        except FileNotFoundError:
            logger.error(f"Threat intel file missing at {file_path}. Text analysis degraded.")

    async def evaluate(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        raw_body = email_data.get("body_plain", "").lower()
        
        if not self.pattern.pattern or not raw_body:
            return {"score": 0, "details": "No text to analyze or patterns loaded."}

        matches = self.pattern.findall(raw_body)
        word_count = len(raw_body.split())
        density = len(matches) / word_count if word_count > 0 else 0
        
        # Categorize hits
        hits = {category: [] for category in self.categories.keys()}
        for match in matches:
            for category, words in self.categories.items():
                if match in words:
                    hits[category].append(match)

        # --- Dynamic Scoring Logic ---
        score = 0
        
        if hits.get("extortion_blackmail"): score += 40
        if hits.get("tech_support_scam"): score += 25
            
        has_urgency = bool(hits.get("account_takeover_urgency"))
        if has_urgency and hits.get("credential_theft"): score += 35
        elif has_urgency and hits.get("financial_fraud"): score += 35

        if hits.get("credential_theft"): score += 15
        if hits.get("financial_fraud"): score += 15
        if hits.get("account_takeover_urgency"): score += 10
        if hits.get("attachment_lures"): score += 10
        if hits.get("too_good_to_be_true"): score += 15

        if density > 0.03: score += 5

        triggered_categories = {k: list(set(v)) for k, v in hits.items() if v}

        return {
            "score": min(score, 40),
            "details": {
                "score": min(score, 40),
                "density": round(density, 4),
                "total_matches": len(matches),
                "categories_triggered": triggered_categories
            }
        }