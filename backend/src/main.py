from fastapi import FastAPI
from typing import Dict
from src.models.schemas import EmailPayload, AnalysisResponse, HeuristicResult

app: FastAPI = FastAPI(
    title="Malicious Email Scorer API",
    description="Backend service for Gmail Workspace Add-on",
    version="1.0.0"
)

@app.post("/api/v1/analyze", response_model=AnalysisResponse)
async def analyze_email(payload: EmailPayload) -> AnalysisResponse:
    """
    Receives extracted email data from the Gmail Add-on,
    runs security heuristics, and returns a final score.
    """
    
    # Dummy logic to prove the API contract works before we build the real engine
    dummy_heuristic: HeuristicResult = HeuristicResult(
        name="Initial Skeleton Check",
        score=10,
        verdict="Suspicious",
        details="This is a dummy response proving the backend circuit is closed."
    )
    
    response: AnalysisResponse = AnalysisResponse(
        total_score=10,
        overall_verdict="Suspicious",
        heuristics=[dummy_heuristic]
    )
    
    return response

@app.get("/health")
async def health_check() -> Dict[str, str]:
    """Simple health probe for deployment pipelines."""
    return {"status": "healthy"}