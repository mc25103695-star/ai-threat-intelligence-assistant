"""
Threat Routes - API endpoints for threat intelligence analysis.

Production endpoint:
    POST /api/analyze  — Full threat analysis pipeline

Dev/test endpoints:
    GET /api/test/*    — Individual service verification (dev only)

Routes are registered as a FastAPI APIRouter and included in main.py.
"""

import logging
from fastapi import APIRouter, Query, HTTPException

from app.models.schemas import AnalyzeRequest, AnalyzeResponse, ErrorResponse
from app.services.virustotal_service import VirusTotalService
from app.services.abuseipdb_service import AbuseIPDBService
from app.services.aggregator import ThreatAggregator
from app.services.gemini_service import GeminiService
from app.services.comparison_service import ComparisonService

logger = logging.getLogger("app.routes")

router = APIRouter(prefix="/api", tags=["Threat Intelligence"])

# ============================================================
# Service Instances
# ============================================================
vt_service = VirusTotalService()
abuse_service = AbuseIPDBService()
aggregator = ThreatAggregator()
gemini_service = GeminiService()
comparison_service = ComparisonService()


# ============================================================
# PRODUCTION ENDPOINT — POST /api/analyze
# ============================================================

@router.post(
    "/analyze",
    response_model=AnalyzeResponse,
    responses={
        200: {"description": "Threat analysis completed successfully"},
        400: {"model": ErrorResponse, "description": "Invalid request"},
        500: {"model": ErrorResponse, "description": "Internal server error"},
    },
    summary="Analyze a threat indicator",
    description=(
        "Submit an IP address, domain, or URL for comprehensive threat analysis. "
        "The system collects intelligence from VirusTotal and AbuseIPDB, "
        "then uses Google Gemini AI to generate a structured threat report."
    ),
)
async def analyze_threat(request: AnalyzeRequest):
    """
    Full threat intelligence pipeline:

    1. Validate the request
    2. Collect intelligence from VirusTotal + AbuseIPDB
    3. Aggregate and compute risk verdict
    4. Generate AI analysis via Gemini (fallback if unavailable)
    5. Compare AI assessment vs VirusTotal findings
    6. Return structured threat report
    """
    indicator = request.indicator.strip()
    indicator_type = request.type.value  # Convert enum to string

    logger.info(
        "📥 Analyze request: indicator=%s, type=%s",
        indicator, indicator_type,
    )

    try:
        # ---- Step 1: Gather intelligence from all sources ----
        logger.info("Step 1/4: Collecting threat intelligence...")
        aggregated = await aggregator.gather_intelligence(indicator, indicator_type)

        # Check if aggregation itself returned an error
        if "error" in aggregated:
            raise HTTPException(
                status_code=400,
                detail=aggregated["error"],
            )

        # ---- Step 2: Generate AI analysis ----
        logger.info("Step 2/4: Running AI analysis...")
        ai_report = await gemini_service.analyze_threat(aggregated)

        # ---- Step 3: Compare AI vs VirusTotal ----
        logger.info("Step 3/4: Comparing AI vs VirusTotal...")
        comparison = comparison_service.compare(ai_report, aggregated)

        # ---- Step 4: Build response ----
        logger.info("Step 4/4: Building response...")
        response = AnalyzeResponse(
            success=True,
            indicator=indicator,
            type=indicator_type,
            timestamp=aggregated.get("timestamp", ""),
            aggregated_data=aggregated,
            ai_report=ai_report,
            combined_verdict=aggregated.get("combined_verdict", {}),
            comparison=comparison,
        )

        logger.info(
            "✅ Analysis complete: indicator=%s, risk=%s, source=%s, alignment=%s",
            indicator,
            response.combined_verdict.risk_level,
            response.ai_report.analysis_source,
            comparison.get("alignment", "N/A"),
        )

        return response

    except HTTPException:
        raise  # Re-raise HTTP exceptions as-is

    except Exception as exc:
        logger.error("❌ Analysis failed: %s — %s", type(exc).__name__, str(exc))
        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed: {str(exc)}",
        )


# ============================================================
# DEV/TEST ENDPOINTS — For individual service verification
# These are useful during development but the frontend only
# uses POST /api/analyze.
# ============================================================

# ---- VirusTotal ----

@router.get("/test/vt/ip", tags=["Dev/Test"])
async def test_vt_ip(ip: str = Query(..., description="IP address to analyze", example="8.8.8.8")):
    """[DEV] Test VirusTotal IP analysis."""
    return await vt_service.analyze_ip(ip)


@router.get("/test/vt/domain", tags=["Dev/Test"])
async def test_vt_domain(domain: str = Query(..., description="Domain to analyze", example="google.com")):
    """[DEV] Test VirusTotal domain analysis."""
    return await vt_service.analyze_domain(domain)


@router.get("/test/vt/url", tags=["Dev/Test"])
async def test_vt_url(url: str = Query(..., description="URL to analyze", example="https://google.com")):
    """[DEV] Test VirusTotal URL analysis."""
    return await vt_service.analyze_url(url)


# ---- AbuseIPDB ----

@router.get("/test/abuse/ip", tags=["Dev/Test"])
async def test_abuse_ip(ip: str = Query(..., description="IP address to check", example="8.8.8.8")):
    """[DEV] Test AbuseIPDB IP check."""
    return await abuse_service.check_ip(ip)


# ---- Aggregator ----

@router.get("/test/aggregate", tags=["Dev/Test"])
async def test_aggregate(
    indicator: str = Query(..., description="IP, domain, or URL to analyze", example="8.8.8.8"),
    type: str = Query(..., description="Indicator type: ip, domain, or url", example="ip"),
):
    """[DEV] Test the aggregation layer."""
    return await aggregator.gather_intelligence(indicator, type)


# ---- Gemini AI ----

@router.get("/test/gemini", tags=["Dev/Test"])
async def test_gemini(
    indicator: str = Query(..., description="IP, domain, or URL to analyze", example="8.8.8.8"),
    type: str = Query(..., description="Indicator type: ip, domain, or url", example="ip"),
):
    """[DEV] Test the full pipeline (Aggregate → Gemini)."""
    aggregated = await aggregator.gather_intelligence(indicator, type)
    report = await gemini_service.analyze_threat(aggregated)
    return {"aggregated_data": aggregated, "ai_report": report}
