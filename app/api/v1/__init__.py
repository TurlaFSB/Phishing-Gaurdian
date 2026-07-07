"""
============================================================================
PHISHING GUARDIAN — API v1 PACKAGE
============================================================================

Author:  Dr. Erik
Version: 1.0.0
============================================================================
"""

from app.api.v1.health import router as health_router
from app.api.v1.analyze import router as analyze_router
from app.api.v1.history import router as history_router

__all__ = ["health_router", "analyze_router", "history_router"]