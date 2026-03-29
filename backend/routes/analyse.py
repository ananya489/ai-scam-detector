from fastapi import APIRouter
from pydantic import BaseModel
from backend.detector import analyze_message   # ✅ fixed

router = APIRouter()

class AnalyzeRequest(BaseModel):
    message: str

@router.post("/analyze")
def analyze(request: AnalyzeRequest):
    if not request.message.strip():
        return {"error": "Message cannot be empty"}

    result = analyze_message(request.message)   # ✅ fixed
    return {
        "message": request.message,
        **result
    }