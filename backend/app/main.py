"""
ScamLens — FastAPI application entrypoint.

PHASE 4 SCOPE:
- App instantiation
- CORS configuration for local frontend development
- Router registration (investigation routes)
- GET /api/health

No business logic (OCR, risk engine, analyzers, AI, database) lives
here or is wired in yet — that arrives in later phases.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routes import investigation

app = FastAPI(
    title="ScamLens API",
    description="AI-powered scam investigation backend.",
    version="0.1.0",
)

# ---------------------------------------------------------------------
# CORS — allow the local static frontend (served separately, e.g. via
# VS Code Live Server or `python -m http.server`) to call this API
# during development.
# ---------------------------------------------------------------------
ALLOWED_ORIGINS = [
    "http://localhost:5500",
    "http://127.0.0.1:5500",
    "http://localhost:5501",
    "http://127.0.0.1:5501",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------
app.include_router(investigation.router)


@app.get("/api/health", tags=["health"])
def health_check() -> dict:
    """Simple liveness check for the API."""
    return {"status": "ok", "service": "scamlens-api"}