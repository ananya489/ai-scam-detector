from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.routes.analyse import router as analyze_router

app = FastAPI(title="AI Scam Detector API")

# ✅ Allow frontend (HTML) to call API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # for dev (later restrict)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ✅ Register routes
app.include_router(analyze_router, prefix="/api")

# ✅ Root route
@app.get("/")
def root():
    return {"status": "running", "message": "AI Scam Detector API is live"}