import asyncio
import os
import logging
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from core.vt_client import VirusTotalClient

# Configure logging to see the cache hit messages
logging.basicConfig(level=logging.INFO)

async def run_test() -> None:
    # 1. Verify Environment Variable Injection
    api_key: str | None = os.getenv("VT_API_KEY")
    if not api_key or api_key == "paste_the_key_from_my_email_here":
        print("❌ ERROR: VT_API_KEY is not set correctly or is using the placeholder.")
        return
        
    print(f"✅ Securely loaded API Key: {api_key[:5]}...[REDACTED]")
    
    # Initialize the client
    client = VirusTotalClient(api_key=api_key)

    # 2. Test Live Network Request
    print("\n🌐 Testing Live API Call for 'github.com'...")
    domain_report = await client.get_domain_report("github.com")
    
    if domain_report and "data" in domain_report:
        stats = domain_report["data"]["attributes"]["last_analysis_stats"]
        print(f"✅ Success! VirusTotal Stats for github.com: {stats}")
    else:
        print("❌ Failed to retrieve live domain report.")

    # 3. Test LRU Cache Logic
    print("\n⚡ Testing LRU Cache for 'github.com' (Should be instant)...")
    cached_report = await client.get_domain_report("github.com")
    
    if cached_report:
        print("✅ Cache test complete! (Check the logs above for the 'Cache hit' message)")

if __name__ == "__main__":
    asyncio.run(run_test())