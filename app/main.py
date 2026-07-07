"""
============================================================================
PHISHING GUARDIAN — MAIN APPLICATION
============================================================================
"""

from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from pathlib import Path
from app.core.config import settings
from app.api.v1 import health_router, analyze_router, history_router
from app.models.database import init_db
import logging
import time

logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Free Phishing Email Analysis Platform",
    docs_url="/docs",
    redoc_url="/redoc",
)

# ---------------------------------------------------------------------------
# STATIC FILES (CSS, JS, images)
# ---------------------------------------------------------------------------
app.mount("/static", StaticFiles(directory="frontend"), name="static")

# ---------------------------------------------------------------------------
# MIDDLEWARE
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(round(process_time, 3))
    response.headers["X-Application"] = f"{settings.APP_NAME} v{settings.APP_VERSION}"
    return response

# ---------------------------------------------------------------------------
# ERROR HANDLER
# ---------------------------------------------------------------------------
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled error: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "internal_server_error",
            "message": "An unexpected error occurred.",
            "detail": str(exc) if settings.APP_DEBUG else None,
        },
    )

# ---------------------------------------------------------------------------
# PAGES
# ---------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
async def homepage():
    """Serve the main analysis page."""
    html_file = Path(__file__).resolve().parent.parent / "frontend" / "index.html"
    if html_file.exists():
        return HTMLResponse(content=html_file.read_text(encoding="utf-8"))
    return HTMLResponse(content="<h1>index.html not found</h1>", status_code=500)

@app.get("/history", response_class=HTMLResponse)
async def history_page():
    """Serve the analysis history page."""
    history_file = Path(__file__).resolve().parent.parent / "frontend" / "history.html"
    if history_file.exists():
        return HTMLResponse(content=history_file.read_text(encoding="utf-8"))
    return HTMLResponse(content="<h1>history.html not found</h1>", status_code=500)

# ---------------------------------------------------------------------------
# PDF REPORT DOWNLOAD
# ---------------------------------------------------------------------------
@app.get("/api/v1/report/{analysis_id}")
async def download_report(analysis_id: str):
    """Generate and download PDF report for an analysis."""
    from app.services.database_service import DatabaseService
    from app.services.reporter import PDFReportGenerator
    
    data = await DatabaseService.get_analysis(analysis_id)
    
    if not data:
        raise HTTPException(status_code=404, detail={"error": "Analysis not found"})
    
    generator = PDFReportGenerator()
    pdf_bytes = generator.generate(data)
    
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=phishing_report_{analysis_id[:12]}.pdf"
        }
    )

# ---------------------------------------------------------------------------
# API ROUTES
# ---------------------------------------------------------------------------
app.include_router(health_router, prefix="/api/v1", tags=["Health"])
app.include_router(analyze_router, prefix="/api/v1", tags=["Analysis"])
app.include_router(history_router, prefix="/api/v1", tags=["History"])

# ---------------------------------------------------------------------------
# EVENTS
# ---------------------------------------------------------------------------
@app.on_event("startup")
async def startup_event():
    """Initialize database and log startup."""
    await init_db()
    logger.info(f"{settings.APP_NAME} v{settings.APP_VERSION} starting on {settings.APP_HOST}:{settings.APP_PORT}")
    logger.info(f"Database initialized at: {settings.DATABASE_URL}")
    logger.info(f"Free APIs available: {[k for k, v in settings.available_apis.items() if v]}")

@app.on_event("shutdown")
async def shutdown_event():
    """Log application shutdown."""
    logger.info(f"{settings.APP_NAME} shutting down...")