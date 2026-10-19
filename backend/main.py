
import sys
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Make the project root importable.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from detector import analyze_url

app = FastAPI(
    title="PhishGuard AI API",
    description="Experimental ML-based phishing URL risk assessment.",
    version="1.0.0",
)

# Local frontend development only.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


class URLRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)


@app.get("/")
def home():
    return {
        "message": "Welcome to PhishGuard AI",
        "status": "running",
        "docs": "/docs",
    }


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.post("/analyze")
def analyze(request: URLRequest):
    try:
        result = analyze_url(request.url)
        return result
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))
