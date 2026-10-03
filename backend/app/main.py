"""
AI Threat Intelligence Assistant - FastAPI Application Entry Point

This is the main application file that initializes the FastAPI server,
configures CORS middleware, validates environment config, and registers
API routes.

Run with: uvicorn app.main:app --reload --port 8000
"""

import logging
from pathlib import Path
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from app.config import settings
from app.routes.threat_routes import router as threat_router

# ============================================================
# Path to the frontend directory (relative to project root)
# ============================================================
FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend"

# ============================================================
# Logging Setup
# ============================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s │ %(levelname)-7s │ %(name)s │ %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("app")

# ============================================================
# Startup / Shutdown Lifespan
# ============================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Runs once when the server starts, and once when it shuts down."""
    # ---- Startup ----
    logger.info("🚀 Starting %s v%s", settings.APP_NAME, settings.APP_VERSION)
    settings.validate()     # Log which API keys are present / missing
    logger.info("📖 API docs at http://localhost:8000/docs")
    logger.info("🌐 Dashboard at http://localhost:8000")
    yield
    # ---- Shutdown ----
    logger.info("👋 Shutting down %s", settings.APP_NAME)

# ============================================================
# Application Factory
# ============================================================

app = FastAPI(
    title="AI Threat Intelligence Assistant",
    description=(
        "An AI-powered threat intelligence platform that analyzes "
        "IP addresses, domains, and URLs using VirusTotal, AbuseIPDB, "
        "and Google Gemini to produce analyst-friendly threat reports."
    ),
    version="1.0.0",
    docs_url="/docs",       # Swagger UI
    redoc_url="/redoc",     # ReDoc UI
    lifespan=lifespan,
)

# ============================================================
# CORS Middleware
# Allows the frontend (served on a different port) to call
# the backend API without being blocked by browser security.
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # In production, restrict to your domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================
# Register API Routers
# ============================================================
app.include_router(threat_router)

# ============================================================
# Health Check Endpoints
# ============================================================

@app.get("/health", tags=["Health"])
async def health():
    """Dedicated health-check endpoint for monitoring."""
    return {"status": "healthy"}


@app.get("/config/status", tags=["Health"])
async def config_status():
    """Check which API keys are configured (values are never exposed)."""
    result = settings.validate()
    return {
        "configured_keys": result["configured"],
        "missing_keys": result["missing"],
        "all_configured": len(result["missing"]) == 0,
    }

# ============================================================
# Serve Frontend — Static Files + Catch-All
# ============================================================

# Mount CSS, JS, and assets as static files
if FRONTEND_DIR.exists():
    app.mount("/css", StaticFiles(directory=FRONTEND_DIR / "css"), name="css")
    app.mount("/js", StaticFiles(directory=FRONTEND_DIR / "js"), name="js")
    app.mount("/assets", StaticFiles(directory=FRONTEND_DIR / "assets"), name="assets")

    @app.get("/", tags=["Frontend"], include_in_schema=False)
    async def serve_frontend():
        """Serve the dashboard (index.html) at the root URL."""
        return FileResponse(FRONTEND_DIR / "index.html")
else:
    logger.warning("⚠️  Frontend directory not found at %s", FRONTEND_DIR)

    @app.get("/", tags=["Health"])
    async def health_check():
        """Root endpoint — frontend not found, show API status."""
        return {
            "status": "online",
            "application": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "message": "Frontend not found. Visit /docs for API documentation.",
        }
