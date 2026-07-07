"""
============================================================================
PHISHING GUARDIAN — BASE INTEGRATION CLASS
============================================================================
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from dataclasses import dataclass, field
import time
import logging

logger = logging.getLogger(__name__)


@dataclass
class IntegrationResult:
    """Standard result from any integration module."""
    source: str
    success: bool = True
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    response_time_ms: float = 0.0
    cached: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        result = {
            "source": self.source,
            "success": self.success,
            "response_time_ms": round(self.response_time_ms, 2),
            "cached": self.cached,
        }
        if self.success:
            result.update(self.data)
        if self.error:
            result["error"] = self.error
        return result


class BaseIntegration(ABC):
    """Base class for all integrations. Override only the methods you support."""
    
    @property
    @abstractmethod
    def source_name(self) -> str:
        pass
    
    @property
    @abstractmethod
    def is_available(self) -> bool:
        pass
    
    async def check_url(self, url: str) -> IntegrationResult:
        return IntegrationResult(
            source=self.source_name,
            success=False,
            error=f"URL checking not supported by {self.source_name}"
        )
    
    async def check_ip(self, ip: str) -> IntegrationResult:
        return IntegrationResult(
            source=self.source_name,
            success=False,
            error=f"IP checking not supported by {self.source_name}"
        )
    
    async def check_domain(self, domain: str) -> IntegrationResult:
        return IntegrationResult(
            source=self.source_name,
            success=False,
            error=f"Domain checking not supported by {self.source_name}"
        )
    
    async def check_hash(self, file_hash: str) -> IntegrationResult:
        return IntegrationResult(
            source=self.source_name,
            success=False,
            error=f"Hash checking not supported by {self.source_name}"
        )
    
    def _timed_result(self, result: IntegrationResult, start_time: float) -> IntegrationResult:
        result.response_time_ms = (time.time() - start_time) * 1000
        return result