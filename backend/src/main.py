import os
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from typing import Dict

from api.schemas import EmailPayload, AnalysisResponse 
from core.vt_client import VirusTotalClient
from core.heuristics.engine import HeuristicEngine

# Standard production logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global engine instance to share cache and connection pools across requests
engine: HeuristicEngine = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Everything before 'yield' runs on startup. Everything after runs on shutdown.
    """
    global engine
    api_key = os.getenv("VT_API_KEY")
    
    if not api_key:
        logger.warning("VT_API_KEY environment variable is missing! VirusTotal enrichment will be disabled.")
        vt_client = None
    else:
        logger.info("Initializing VirusTotal client and TTL Cache...")
        vt_client = VirusTotalClient(api_key=api_key)
        
    engine = HeuristicEngine(vt_client=vt_client)
    logger.info("Heuristic Engine fully loaded and ready.")
    
    yield
    
    logger.info("Shutting down Heuristic Engine...")

app = FastAPI(
    title="Malicious Email Scorer API",
    description="Backend service for Gmail Workspace Add-on",
    version="1.0.0",
    lifespan=lifespan 
)

@app.post("/api/v1/analyze", response_model=AnalysisResponse)
async def analyze_email(payload: EmailPayload) -> AnalysisResponse:
    """
    Ingests an email payload from the Gmail Add-on, runs all heuristics concurrently,
    and returns a structured threat report.
    """
    try:
        result = await engine.analyze(payload.model_dump())
        
        return AnalysisResponse(
            verdict=result["verdict"],
            total_score=result["total_score"],
            analysis=result["analysis"]
        )
        
    except Exception as e:
        logger.critical(f"Fatal error during email analysis: {str(e)}")
        raise HTTPException(
            status_code=500, 
            detail="Internal server error during the analysis pipeline."
        )

@app.get("/health")
async def health_check() -> Dict[str, str]:
    """Simple health probe for deployment pipelines."""
    return {"status": "healthy"}