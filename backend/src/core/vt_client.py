import httpx
import logging
from typing import Dict, Any, Optional
from cachetools import TTLCache

logger = logging.getLogger(__name__)

class VirusTotalClient:
    """Async client for the VirusTotal v3 API with TTL caching."""

    def __init__(self, api_key: str, max_cache_size: int = 100, ttl_seconds: int = 86400) -> None:
        """
        Args:
            api_key: VirusTotal API key.
            max_cache_size: Maximum number of cached responses.
            ttl_seconds: Cache time-to-live in seconds (default 24 h).
        """
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers: Dict[str, str] = {"x-apikey": self.api_key}
        self.cache: TTLCache = TTLCache(maxsize=max_cache_size, ttl=ttl_seconds)

    async def _fetch_report(self, url: str, cache_key: str) -> Optional[Dict[str, Any]]:
        """Fetches a VT report, returning the cached value when available.

        Args:
            url: Full VirusTotal API endpoint URL.
            cache_key: Key used for cache lookup and storage.

        Returns:
            Parsed JSON response dict, or None on rate-limit or error.
        """
        if cache_key in self.cache:
            logger.info(f"TTL Cache hit for: {cache_key}")
            return self.cache[cache_key]

        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(url, headers=self.headers)
                if response.status_code == 200:
                    data: Dict[str, Any] = response.json()
                    self.cache[cache_key] = data
                    return data
                if response.status_code == 429:
                    logger.warning("VirusTotal API rate limit reached (429).")
                    return None
                logger.error(f"VT API Error {response.status_code}: {response.text}")
                return None
            except Exception as e:
                logger.error(f"Connection error to VirusTotal: {str(e)}")
                return None

    async def get_domain_report(self, domain: str) -> Optional[Dict[str, Any]]:
        """Retrieves the live reputation report for a domain.

        Args:
            domain: Registered domain to query (e.g. 'example.com').

        Returns:
            VT report dict, or None on failure.
        """
        return await self._fetch_report(f"{self.base_url}/domains/{domain}", domain)

    async def get_file_hash_report(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Checks a SHA-256 hash against the VirusTotal database.

        Args:
            file_hash: 64-character SHA-256 hex string.

        Returns:
            VT report dict, or None on failure.
        """
        return await self._fetch_report(f"{self.base_url}/files/{file_hash}", file_hash)
