"""
============================================================================
PHISHING GUARDIAN — HISTORY ENDPOINT
============================================================================
GET /api/v1/history — Retrieve past analysis results from database.

Author:  Dr. Erik
Version: 1.0.0
============================================================================
"""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.api.deps import check_rate_limit
from app.services.database_service import DatabaseService

router = APIRouter()


@router.get("/history")
async def get_history(
    limit: int = Query(50, ge=1, le=200, description="Results per page"),
    offset: int = Query(0, ge=0, description="Number of results to skip"),
    risk_level: Optional[str] = Query(None, description="Filter by risk level"),
    search: Optional[str] = Query(None, description="Search in subject and sender"),
    start_date: Optional[str] = Query(None, description="Start date (ISO format)"),
    end_date: Optional[str] = Query(None, description="End date (ISO format)"),
    _rate_limit: dict = Depends(check_rate_limit),
):
    """Retrieve paginated analysis history with optional filters."""
    result = await DatabaseService.get_history(
        limit=limit,
        offset=offset,
        risk_level=risk_level,
        search=search,
        start_date=start_date,
        end_date=end_date,
    )
    return result


@router.get("/history/{analysis_id}")
async def get_analysis_detail(
    analysis_id: str,
    _rate_limit: dict = Depends(check_rate_limit),
):
    """Retrieve a specific analysis by ID."""
    result = await DatabaseService.get_analysis(analysis_id)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "Analysis not found"}
        )
    return result


@router.delete("/history/{analysis_id}")
async def delete_analysis(
    analysis_id: str,
    _rate_limit: dict = Depends(check_rate_limit),
):
    """Delete a specific analysis by ID."""
    success = await DatabaseService.delete_analysis(analysis_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "Analysis not found"}
        )
    return {"message": "Analysis deleted successfully", "analysis_id": analysis_id}


@router.get("/statistics")
async def get_statistics(
    _rate_limit: dict = Depends(check_rate_limit),
):
    """Get aggregate analysis statistics."""
    return await DatabaseService.get_statistics()