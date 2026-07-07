"""
============================================================================
PHISHING GUARDIAN — CACHE UTILITY
============================================================================
Simple file-based cache to avoid redundant API calls.

Author:  Dr. Erik
Version: 1.0.0
============================================================================
"""

import json
import time
import hashlib
import logging
from pathlib import Path
from typing import Optional, Any

from app.core.config import settings

logger = logging.getLogger(__name__)


class SimpleCache:
    """
    File-based cache for API responses.
    Reduces redundant API calls and respects rate limits.
    """
    
    def __init__(self, cache_dir: Path = None):
        self.cache_dir = cache_dir or settings.CACHE_DIR
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.ttl = settings.CACHE_TTL_HOURS * 3600
    
    def _get_key(self, data: str) -> str:
        """Generate a cache key from input data."""
        return hashlib.sha256(data.encode()).hexdigest()[:16]
    
    def get(self, key_data: str) -> Optional[Any]:
        """Retrieve a cached value."""
        if not settings.CACHE_ENABLED:
            return None
        
        key = self._get_key(key_data)
        cache_file = self.cache_dir / f"{key}.json"
        
        if not cache_file.exists():
            return None
        
        try:
            with open(cache_file, "r") as f:
                data = json.load(f)
            
            # Check expiration
            if time.time() - data.get("cached_at", 0) > self.ttl:
                cache_file.unlink(missing_ok=True)
                return None
            
            logger.debug(f"Cache hit: {key}")
            return data.get("value")
        except Exception:
            return None
    
    def set(self, key_data: str, value: Any) -> None:
        """Store a value in the cache."""
        if not settings.CACHE_ENABLED:
            return
        
        key = self._get_key(key_data)
        cache_file = self.cache_dir / f"{key}.json"
        
        try:
            with open(cache_file, "w") as f:
                json.dump({
                    "key": key,
                    "cached_at": time.time(),
                    "ttl_hours": settings.CACHE_TTL_HOURS,
                    "value": value
                }, f, default=str)
        except Exception as e:
            logger.warning(f"Cache write failed: {e}")
    
    def clear(self) -> int:
        """Clear all cached entries. Returns count of removed files."""
        count = 0
        for cache_file in self.cache_dir.glob("*.json"):
            cache_file.unlink()
            count += 1
        return count