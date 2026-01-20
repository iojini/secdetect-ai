from fastapi import FastAPI
from datetime import datetime

app = FastAPI(
    title="SecDetect AI",
    description="GenAI-Powered Detection Engineering Platform",
    version="0.1.0"
)

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