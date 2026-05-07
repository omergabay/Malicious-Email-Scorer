from pydantic import BaseModel, Field
from typing import Optional, List, Dict

class EmailPayload(BaseModel):
    """The exact JSON structure the Gmail Add-on will POST to the backend."""
    message_id: str = Field(..., description="The unique Gmail message ID")
    sender_address: str = Field(..., description="The visible 'From' address")
    return_path: Optional[str] = Field(None, description="The hidden 'Return-Path' address")
    headers: Dict[str, str] = Field(default_factory=dict, description="Key-value pairs of raw email headers")
    body_plain: Optional[str] = Field(None, description="The plaintext body of the email")
    body_html: Optional[str] = Field(None, description="The raw HTML body of the email")
    attachment_hashes: List[str] = Field(default_factory=list, description="SHA-256 hashes computed by the frontend")

class HeuristicResult(BaseModel):
    """The result of a single security check (e.g., 'Domain Mismatch')."""
    name: str = Field(..., description="Name of the heuristic executed")
    score: int = Field(..., description="Points added to the maliciousness score (0-100)")
    verdict: str = Field(..., description="Short status (e.g., 'Safe', 'Suspicious', 'Critical')")
    details: str = Field(..., description="Human-readable explanation of why this triggered")

class AnalysisResponse(BaseModel):
    """The final JSON structure returned to the Gmail Add-on to render the UI."""
    total_score: int = Field(..., description="Aggregated score from 0 to 100+")
    overall_verdict: str = Field(..., description="Final verdict (Safe, Suspicious, Malicious)")
    heuristics: List[HeuristicResult] = Field(..., description="Detailed breakdown of each check")