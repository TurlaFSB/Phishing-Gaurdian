"""
============================================================================
PHISHING GUARDIAN — API PACKAGE
============================================================================

Author:  Dr. Erik
Version: 1.0.0
============================================================================
"""

from app.api.v1 import health_router, analyze_router, history_router

__all__ = ["health_router", "analyze_router", "history_router"]