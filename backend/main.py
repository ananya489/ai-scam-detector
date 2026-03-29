from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.routes.analyse import router as analyze_router

app = FastAPI(title="AI Scam Detector API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

from fastapi.responses import FileResponse

@app.get("/favicon.ico")
def favicon():
    return FileResponse("favicon.ico")

app.include_router(analyze_router, prefix="/api")

@app.get("/")
def root():
    return {"status": "running", "message": "AI Scam Detector API is live"}