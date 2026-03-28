from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()

class AnalyzeRequest(BaseModel):
    message: str

@router.post("/analyze")
def analyze(request: AnalyzeRequest):
    return {
        "message": request.message,
        "is_scam": True,
        "confidence": 0.91,
        "risk_level": "high",
        "reason": "This is a dummy response. AI detection coming next.",
        "flags": ["urgent language", "prize claim", "suspicious link"]
    }