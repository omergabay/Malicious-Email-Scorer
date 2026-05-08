from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

class AttachmentSchema(BaseModel):
    """Represents a single parsed attachment with its computed hash."""
    filename: str = Field(..., max_length=255, description="Full name of the attached file")
    sha256: Optional[str] = Field(None, min_length=64, max_length=64, description="SHA-256 hash computed by the frontend")
    
class EmailPayload(BaseModel):
    """The exact JSON structure the Gmail Add-on will POST to the backend."""
    # Identification
    message_id: str = Field(..., max_length=255, description="The unique Gmail message ID")
    
    # Routing and Identity
    sender_address: str = Field(..., max_length=255, description="The visible 'From' address")
    return_path: Optional[str] = Field(None, max_length=255, description="The hidden 'Return-Path' address")
    reply_to: Optional[str] = Field(None, max_length=255, description="The 'Reply-To' address if specified")
    authentication_results: str = Field("", max_length=500, description="Raw SPF/DKIM/DMARC results")
    headers: Dict[str, str] = Field(default_factory=dict, description="Key-value pairs of raw email headers")
    
    # Body Content - Hard capped to prevent regex/BeautifulSoup memory exhaustion (DoS protection)
    # 50,000 chars is roughly 10-15 pages of text.
    body_plain: str = Field("", max_length=50000, description="The plaintext body of the email")
    body_html: str = Field("", max_length=150000, description="The raw HTML body of the email") 
    
    # Attachments - Capped to prevent processing loops
    attachments: List[AttachmentSchema] = Field(default_factory=list, max_length=20, description="List of attachments with metadata and hashes")

class AnalysisResponse(BaseModel):
    """The final JSON structure returned to the Gmail Add-on to render the UI."""
    total_score: int = Field(..., description="Aggregated score from 0 to 100")
    verdict: str = Field(..., description="Final verdict (Safe, Suspicious, Malicious)")
    analysis: Dict[str, Any] = Field(..., description="Detailed breakdown of each heuristic's specific findings")