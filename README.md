# Malicious Email Scorer

A Gmail Workspace Add-on that analyzes incoming emails for phishing, malware, and social engineering threats in real time. The add-on extracts email metadata and posts it to a self-hosted FastAPI backend, which runs four concurrent heuristics and returns a scored threat report rendered inside Gmail.

---

## Architecture

```
Gmail Add-on (Apps Script)
        │
        │  POST /api/v1/analyze  (JSON payload)
        ▼
    ngrok Tunnel
        │
        ▼
  FastAPI Backend (Docker) ──────────────────────────────────┐
        │                                                     │
        │  asyncio.gather()                                   │
        ├── SenderIdentityHeuristic                          │
        │     └─ SPF/DKIM/DMARC, domain mismatch, VT domain │
        ├── SocialEngineeringHeuristic                       ├── VirusTotal API
        │     └─ Regex keyword feed (EN + HE)               │   (domain & hash lookups)
        ├── LinkMismatchHeuristic                            │
        │     └─ display vs href domain, shorteners, VT     │
        └── AttachmentHeuristic                              │
              └─ extension analysis, double-ext, VT hash ───┘
        │
        │  AnalysisResponse (verdict, score, breakdown, analyst_report)
        ▼
Gmail Add-on renders card UI
```

---

## Security & Data Handling

Treating all email content as untrusted input is a core design principle of this architecture:

- Strict Input Validation: The backend uses strict Pydantic schemas (schemas.py) to sanitize and validate the incoming JSON payload. Overly large payloads are truncated to prevent memory exhaustion (DoS mitigation).

- No Execution: Attachments are never downloaded or executed. The frontend computes the SHA-256 hash and sends only the hash to the backend for threat intelligence lookup.

- HTML Sanitization: Before running social engineering heuristics, raw HTML is parsed safely using BeautifulSoup to extract plaintext, preventing malicious scripts from interfering with the analysis engine.

---

## Trade-offs and Future Work

Given the strict four-day time constraint for this assignment, several architectural trade-offs were made to prioritize a functional, end-to-end reliable pipeline over deep infrastructure complexity. If I had more time, I would expand the system in the following ways:

- Persistent Database: Currently, the system uses an in-memory TTLCache to store VirusTotal results and reduce API calls. With more time, I would integrate a persistent data store (like Redis or PostgreSQL). This would allow the system to maintain a historical reputation graph of senders across container restarts and build a long-term profile of targeted attacks.

- External Threat Intelligence APIs: VirusTotal is highly effective, but it is a single point of failure. I would implement an adapter pattern to query multiple distinct Threat Intelligence (CTI) feeds concurrently, such as URLScan.io for dynamic link detonation, or AbuseIPDB for sender IP reputation.

- Machine Learning Models: The social engineering heuristic currently relies on deterministic regex pattern matching and keyword density. While fast and predictable, it struggles with highly semantic or novel attacks. I would replace or augment this with an NLP model (e.g., a fine-tuned BERT model or an LLM integration) to analyze the intent of the text (e.g., detecting manufactured urgency or manipulation) rather than relying strictly on predefined threat feeds.

- Sandboxed Detonation (Dynamic Analysis): Currently, the attachment heuristic only performs static analysis (extension checking) and hash lookups. A robust future feature would involve routing suspicious attachments (like .docx or .pdf files) to a secure sandbox (e.g., Cuckoo Sandbox or an AWS EC2 throwaway instance) to detonate the file and monitor its actual behavioral footprint before delivering a verdict.

---

## Scoring Logic

Each heuristic returns a raw score. The engine aggregates them as follows:

| Step | Rule |
|------|------|
| Sum | Raw scores from all four heuristics are summed |
| Dampening | If sender is on the trusted allowlist, Social Engineering score × 0.2 |
| Compound multiplier | Spoofed sender + phishing language → total × 1.5 |
| Cap | Final score capped at 100 |
| VT override | Any heuristic score ≥ 100 (VT confirmed malware) → verdict locked to Malicious / score 100 |

**Verdict thresholds:**

| Score | Verdict |
|-------|---------|
| 0–19 | Safe |
| 20–49 | Suspicious |
| 50–100 | Malicious |

---

## Prerequisites

- Python 3.11
- Docker and Docker Compose
- [ngrok](https://ngrok.com/) account (free tier is sufficient)
- Google Workspace account (for Gmail Add-on deployment)
- [VirusTotal API key](https://www.virustotal.com/) (free tier: 4 req/min)

---

## Local Setup

### 1. Clone the repo

```bash
git clone https://github.com/omergabay/Malicious-Email-Scorer
cd Malicious-Email-Scorer
```

### 2. Configure environment variables

```bash
cp .env.example .env
# Edit .env and set VT_API_KEY to your VirusTotal API key
```

If `VT_API_KEY` is not set, the backend starts in degraded mode — heuristics run but VirusTotal enrichment is skipped.

### 3. Start the backend

```bash
docker compose up --build
```

The API is now available at `http://localhost:8000`.

Verify with:
```bash
curl http://localhost:8000/health
# → {"status": "healthy"}
```

### 4. Create an ngrok tunnel

```bash
.\ngrok.exe http 127.0.0.1:8000
```

Copy the HTTPS forwarding URL (e.g. `https://abc123.ngrok-free.dev`). You will need it in the next step.

---

## Gmail Add-on Deployment

### 1. Create an Apps Script project

1. Go to [script.google.com](https://script.google.com) and create a new project.
2. Delete the default `Code.gs` content.
3. Copy the contents of each file in `addon/` into separate script files with the same names:
   - `Code.gs`
   - `ApiClient.gs`
   - `CardBuilder.gs`
   - `Extractor.gs`
4. Add `appsscript.json` as the manifest (enable "Show appsscript.json manifest file" in Project Settings).
5. Enable Chrome V8 runtime

### 2. Set the backend URL

In the Apps Script editor, go to **Project Settings → Script Properties** and add:

| Property | Value |
|----------|-------|
| `BACKEND_URL` | Your ngrok HTTPS URL (e.g. `https://abc123.ngrok-free.dev`) |

The add-on reads this property at runtime — update it whenever your ngrok URL changes without touching any code.

### 3. Deploy and install

1. Click **Deploy → Test deployments** in the Apps Script editor.
2. In Gmail, open a message. The add-on panel will appear in the right sidebar.
3. Click the add-on icon to trigger analysis.

---

## API Reference

### `POST /api/v1/analyze`

Analyzes an email payload and returns a structured threat report.

**Request body** (`EmailPayload`):

| Field | Type | Description |
|-------|------|-------------|
| `message_id` | string | Gmail message ID |
| `sender_address` | string | Visible From address |
| `return_path` | string? | Hidden Return-Path address |
| `reply_to` | string? | Reply-To address |
| `authentication_results` | string | Raw SPF/DKIM/DMARC header value |
| `body_plain` | string | Plaintext body (max 50 KB) |
| `body_html` | string | HTML body (max 150 KB) |
| `attachments` | array | List of `{filename, sha256}` objects (max 20) |

**Response** (`AnalysisResponse`):

| Field | Type | Description |
|-------|------|-------------|
| `verdict` | string | `"Safe"`, `"Suspicious"`, or `"Malicious"` |
| `total_score` | int | Aggregate threat score 0–100 |
| `analysis` | object | Per-heuristic finding breakdown |
| `analyst_report` | string[] | Human-readable threat findings |

**Example:**

```bash
curl -X POST http://localhost:8000/api/v1/analyze \
  -H 'Content-Type: application/json' \
  -d '{
    "message_id": "test-001",
    "sender_address": "support@paypal-scam.com",
    "return_path": "bounces@evil.ru",
    "reply_to": null,
    "authentication_results": "spf=fail dkim=fail dmarc=fail",
    "body_plain": "Your account is suspended. Verify immediately.",
    "body_html": "",
    "attachments": []
  }'
```

### `GET /health`

Returns `{"status": "healthy"}`. Used by deployment pipelines to confirm the service is up.

---

## Configuration

All tunable values are defined inline in source files. The table below lists the non-obvious ones:

| Value | Location | Default | Description |
|-------|----------|---------|-------------|
| VT cache size | `vt_client.py` `__init__` | 100 | Max cached VT responses |
| VT cache TTL | `vt_client.py` `__init__` | 86400 s (24 h) | Cache time-to-live |
| VT scan cap (links) | `link_mismatch.py` | 4 | Max domains scanned per email |
| VT scan cap (files) | `scan_attachments.py` | 4 | Max hashes scanned per email |
| Allowlist dampening | `engine.py` | 0.2× | Social engineering multiplier for trusted senders |
| Compound multiplier | `engine.py` | 1.5× | Score boost when spoofing + phishing combine |
| Trusted domain list | `heuristics/data/trusted_domains.json` | 98 domains | Enterprise domains that lower false-positive rate |
| Phishing keywords | `heuristics/data/phishing_keywords.json` | Multi-language | Regex threat feed used by SocialEngineeringHeuristic |

---

## Running Tests

```bash
cd backend
PYTHONPATH=src pytest tests/ -v
```

The two tests in `test_vt.py` are automatically skipped when `VT_API_KEY` is not set (they make live network requests). All other tests use mocks and run offline.

To run only the offline tests explicitly:
```bash
PYTHONPATH=src pytest tests/ -v -k "not test_live"
```
