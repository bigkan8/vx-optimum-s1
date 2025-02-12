from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional
from ..core.detector import PhishingDetector, PhishingAnalysisResult

app = FastAPI(title="Phishing Detection API")
detector = PhishingDetector()

class AnalysisRequest(BaseModel):
    text: str

class AnalysisResponse(BaseModel):
    is_phishing: bool
    explanation: str
    url_analysis: Optional[dict] = None
    message_analysis: Optional[dict] = None
    fact_check_results: Optional[dict] = None

@app.post("/analyze", response_model=AnalysisResponse)
async def analyze_text(request: AnalysisRequest) -> AnalysisResponse:
    try:
        result: PhishingAnalysisResult = await detector.analyze(request.text)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    return {"status": "healthy"} 