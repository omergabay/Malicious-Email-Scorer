import httpx
import logging
from typing import Dict, Any, Optional
from cachetools import TTLCache

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class VirusTotalClient:
    def __init__(self, api_key: str, max_cache_size: int = 100, ttl_seconds: int = 86400) -> None:
        self.api_key: str = api_key
        self.base_url: str = "https://www.virustotal.com/api/v3"
        self.headers: Dict[str, str] = {"x-apikey": self.api_key}
        
        self.cache: TTLCache = TTLCache(maxsize=max_cache_size, ttl=ttl_seconds)

    async def get_domain_report(self, domain: str) -> Optional[Dict[str, Any]]:
        """Retrieves the live reputation report for a specific domain."""
        if domain in self.cache:
            logger.info(f"TTL Cache hit for domain: {domain}")
            return self.cache[domain]

        url: str = f"{self.base_url}/domains/{domain}"
        
        async with httpx.AsyncClient() as client:
            try:
                response: httpx.Response = await client.get(url, headers=self.headers)
                if response.status_code == 200:
                    data: Dict[str, Any] = response.json()
                    
                    self.cache[domain] = data
                    return data
                elif response.status_code == 429:
                    logger.warning("VirusTotal API rate limit reached (429).")
                    return None
                else:
                    logger.error(f"VT API Error {response.status_code}: {response.text}")
                    return None
            except Exception as e:
                logger.error(f"Connection error to VirusTotal: {str(e)}")
                return None

    async def get_file_hash_report(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Checks a live SHA-256 hash against the VirusTotal database."""
        if file_hash in self.cache:
            logger.info(f"TTL Cache hit for hash: {file_hash}")
            return self.cache[file_hash]

        url: str = f"{self.base_url}/files/{file_hash}"

        async with httpx.AsyncClient() as client:
            try:
                response: httpx.Response = await client.get(url, headers=self.headers)
                if response.status_code == 200:
                    data: Dict[str, Any] = response.json()
                    
                    self.cache[file_hash] = data
                    return data
                return None
            except Exception as e:
                logger.error(f"Connection error to VirusTotal: {str(e)}")
                return None