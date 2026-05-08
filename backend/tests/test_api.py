import pytest
from fastapi.testclient import TestClient
from main import app

# Using a fixture with a context manager forces FastAPI to run the `lifespan` 
# startup code, ensuring our HeuristicEngine is actually instantiated.
@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c

def test_health_check(client):
    """Verifies the API is online and responding to load balancers."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}

def test_analyze_endpoint_contract(client):
    """
    Sends a valid JSON payload to the main endpoint and verifies 
    that it returns the strictly typed AnalysisResponse schema.
    """
    payload = {
        "message_id": "test_integration_001",
        "sender_address": "admin@trusted-bank.com",
        "return_path": "admin@trusted-bank.com",
        "authentication_results": "spf=pass dkim=pass",
        "body_plain": "Your statement is ready for viewing.",
        "body_html": "",
        "attachments": []
    }

    # Simulate the frontend POST request
    response = client.post("/api/v1/analyze", json=payload)
    
    # 1. Did the endpoint accept the payload? (200 OK)
    assert response.status_code == 200, f"API rejected payload with: {response.text}"
    
    data = response.json()
    
    # 2. Does the response match our Pydantic schema?
    assert "verdict" in data
    assert "total_score" in data
    assert "analysis" in data
    
    # 3. Since this is a clean email, it should return Safe
    assert data["verdict"] == "Safe"
    assert data["total_score"] == 0

def test_analyze_endpoint_validation_shield(client):
    """Verifies that Pydantic automatically blocks bad payloads."""
    bad_payload = {
        "message_id": "missing_sender_address_payload",
        # Missing 'sender_address', which is a required field!
        "body_plain": "I forgot to include the sender."
    }

    response = client.post("/api/v1/analyze", json=bad_payload)
    
    # FastApi should automatically return a 422 Unprocessable Entity
    assert response.status_code == 422