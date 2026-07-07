"""
============================================================================
PHISHING GUARDIAN — API DEPENDENCIES
============================================================================
Shared dependencies for API routes: rate limiting, authentication,
and service injection.

Author:  Dr. Erik
Version: 1.0.0
============================================================================
"""

import time
from typing import Dict, Tuple
from fastapi import Request, HTTPException, status
from app.core.config import settings
import logging

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# IN-MEMORY RATE LIMITER
# ---------------------------------------------------------------------------
class RateLimiter:
    """
    Simple in-memory rate limiter.
    Tracks requests per client IP within a time window.
    """
    
    def __init__(self, max_requests: int = None, window_seconds: int = 60):
        self.max_requests = max_requests or settings.RATE_LIMIT_PER_MINUTE
        self.window_seconds = window_seconds
        self._clients: Dict[str, list] = {}
    
    def is_allowed(self, client_ip: str) -> Tuple[bool, int]:
        """
        Check if client is within rate limits.
        
        Returns:
            Tuple of (is_allowed, remaining_requests)
        """
        now = time.time()
        window_start = now - self.window_seconds
        
        # Clean old entries
        if client_ip in self._clients:
            self._clients[client_ip] = [
                t for t in self._clients[client_ip] if t > window_start
            ]
        else:
            self._clients[client_ip] = []
        
        # Check limit
        current_count = len(self._clients[client_ip])
        if current_count >= self.max_requests:
            return False, 0
        
        # Add request
        self._clients[client_ip].append(now)
        remaining = self.max_requests - current_count - 1
        
        return True, remaining


# ---------------------------------------------------------------------------
# GLOBAL INSTANCES
# ---------------------------------------------------------------------------
rate_limiter = RateLimiter()


# ---------------------------------------------------------------------------
# DEPENDENCY FUNCTIONS
# ---------------------------------------------------------------------------
async def check_rate_limit(request: Request):
    """
    FastAPI dependency: Check rate limit before processing request.
    """
    client_ip = request.client.host if request.client else "unknown"
    
    allowed, remaining = rate_limiter.is_allowed(client_ip)
    
    if not allowed:
        logger.warning(f"Rate limit exceeded for {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "error": "Rate limit exceeded",
                "message": f"Maximum {settings.RATE_LIMIT_PER_MINUTE} requests per minute. Please wait.",
                "retry_after_seconds": 60,
            }
        )
    
    return {"client_ip": client_ip, "remaining_requests": remaining}


async def get_analysis_services():
    """
    FastAPI dependency: Get analysis service instances.
    Lazily imports to avoid circular dependencies.
    """
    from app.services.parser import EmailParser
    from app.services.analyzer import AnalysisEngine
    from app.services.scorer import RiskScoringEngine
    
    return {
        "parser": EmailParser(),
        "analyzer": AnalysisEngine(),
        "scorer": RiskScoringEngine(),
    }