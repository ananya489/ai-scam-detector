from fastapi import APIRouter
from pydantic import BaseModel
from backend.detector import analyze_message

router = APIRouter()

class MessageRequest(BaseModel):
    message: str

@router.post("/analyze")
def analyze(req: MessageRequest):
    result = analyze_message(req.message)
    return result