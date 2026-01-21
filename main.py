from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
from pydantic import BaseModel
from typing import Optional
import anthropic
import os
from dotenv import load_dotenv
from detection_engine import DetectionEngine
from enrichment_engine import EnrichmentEngine

load_dotenv()

app = FastAPI(
    title="SecDetect AI",
    description="GenAI-Powered Detection Engineering Platform",
    version="0.1.0"
)

# Allow frontend to connect
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize engines
detection_engine = DetectionEngine()
enrichment_engine = EnrichmentEngine()
claude = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))

# Request models
class DetectionRequest(BaseModel):
    event_type: str
    user: str
    hour: int

class EnrichmentRequest(BaseModel):
    user: str
    source_ip: str

class AnalyzeRequest(BaseModel):
    query: str

@app.get("/")
def root():
    return {
        "name": "SecDetect AI",
        "status": "running",
        "timestamp": datetime.now().isoformat()
    }

@app.get("/health")
def health_check():
    return {"status": "healthy"}

@app.get("/api/status")
def get_status():
    return {
        "status": "online",
        "version": "0.1.0",
        "rules_loaded": len(detection_engine.rules),
        "ai_status": "active",
        "timestamp": datetime.now().isoformat()
    }

@app.get("/api/rules")
def get_rules():
    return {
        "rules": detection_engine.get_rules_summary(),
        "total": len(detection_engine.rules)
    }

@app.post("/api/detect")
def run_detection(request: DetectionRequest):
    log_event = {
        'event_type': request.event_type,
        'user': request.user,
        'hour': request.hour,
        'source_ip': '192.168.1.100',
        'timestamp': datetime.now().isoformat()
    }
    
    matches = detection_engine.evaluate_log(log_event)
    
    return {
        "input": log_event,
        "matches": matches,
        "alert_triggered": len(matches) > 0
    }

@app.post("/api/enrich")
def run_enrichment(request: EnrichmentRequest):
    alert_data = {
        "event_type": "security_alert",
        "user": request.user,
        "source_ip": request.source_ip,
        "severity": "medium"
    }
    
    enriched = enrichment_engine.enrich_alert(alert_data)
    
    return enriched

@app.post("/api/analyze")
def run_analysis(request: AnalyzeRequest):
    response = claude.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1024,
        messages=[{
            "role": "user",
            "content": f"""You are a security analyst assistant. Analyze the following and provide:
1. What type of indicator this is (IP, domain, hash, etc.)
2. Potential security concerns
3. Recommended actions

Keep response concise (under 200 words). Use emoji for visual clarity.

Analyze: {request.query}"""
        }]
    )
    
    return {
        "query": request.query,
        "analysis": response.content[0].text,
        "timestamp": datetime.now().isoformat()
    }