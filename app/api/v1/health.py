"""
============================================================================
PHISHING GUARDIAN — HEALTH CHECK ENDPOINT
============================================================================

Author:  Dr. Erik
Version: 1.0.0
============================================================================
"""

from fastapi import APIRouter
from app.core.config import settings, verify_configuration

router = APIRouter()


@router.get("/health")
async def health_check():
    """
    Health check endpoint.
    Returns application status and available APIs.
    """
    config_status = verify_configuration()
    
    return {
        "status": "healthy",
        "application": {
            "name": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "environment": settings.APP_ENV,
        },
        "apis": {
            "available": config_status["total_apis_available"],
            "free_sources": config_status["free_apis"],
            "configured_with_keys": config_status["apis_with_keys"],
            "completely_free": config_status["completely_free"],
        },
        "timestamp": __import__("datetime").datetime.utcnow().isoformat(),
    }


@router.get("/")
async def root():
    """
    Root endpoint — basic API information.
    """
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "description": "Free phishing email analysis platform",
        "documentation": "/docs",
        "health_check": "/api/v1/health",
        "analyze_endpoint": "/api/v1/analyze",
    }