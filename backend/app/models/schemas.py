"""
Pydantic Schemas - Request and Response Models

Defines the data models for API request validation and
response serialization. Using Pydantic ensures that:
  - Invalid requests are rejected with clear error messages
  - Responses have a consistent, documented structure
  - Swagger/OpenAPI docs are auto-generated from these models

Usage:
    from app.models.schemas import AnalyzeRequest, AnalyzeResponse
"""

from typing import Optional
from enum import Enum

from pydantic import BaseModel, Field


# ============================================================
# Enums
# ============================================================

class IndicatorType(str, Enum):
    """Supported indicator types for analysis."""
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"


# ============================================================
# Request Models
# ============================================================

class AnalyzeRequest(BaseModel):
    """
    Request body for POST /api/analyze.

    Examples:
        {"indicator": "8.8.8.8", "type": "ip"}
        {"indicator": "example.com", "type": "domain"}
        {"indicator": "https://evil.com/phish", "type": "url"}
    """
    indicator: str = Field(
        ...,
        min_length=1,
        max_length=2048,
        description="The IP address, domain name, or URL to analyze.",
        examples=["8.8.8.8", "example.com", "https://example.com"],
    )
    type: IndicatorType = Field(
        ...,
        description="Type of indicator: 'ip', 'domain', or 'url'.",
        examples=["ip"],
    )

    class Config:
        json_schema_extra = {
            "example": {
                "indicator": "8.8.8.8",
                "type": "ip",
            }
        }


# ============================================================
# Response Models
# ============================================================

class RiskAssessment(BaseModel):
    """AI-generated or fallback risk assessment."""
    risk_level: str = Field(..., description="CRITICAL, HIGH, MEDIUM, LOW, or CLEAN")
    confidence: str = Field(..., description="HIGH, MEDIUM, or LOW")
    justification: str = Field(..., description="Explanation citing specific data points")


class CombinedVerdict(BaseModel):
    """Computed risk verdict from the aggregation layer."""
    risk_level: str
    risk_score: int = Field(..., ge=0, le=100)
    factors: list[str] = []


class ThreatReport(BaseModel):
    """The AI-generated (or fallback) threat analysis report."""
    threat_summary: str
    risk_assessment: RiskAssessment
    potential_attack_types: list[str] = []
    investigation_steps: list[str] = []
    analyst_questions: list[str] = []
    mitigation_recommendations: list[str] = []
    analysis_source: str = Field(
        ...,
        description="'gemini' if AI-generated, 'fallback' if rule-based",
    )


class AnalyzeResponse(BaseModel):
    """
    Full response from POST /api/analyze.

    Contains both the raw aggregated intelligence data and the
    AI-generated threat report.
    """
    success: bool = Field(..., description="Whether the analysis completed successfully")
    indicator: str
    type: str
    timestamp: str
    aggregated_data: dict = Field(
        ...,
        description="Raw intelligence from VirusTotal and AbuseIPDB",
    )
    ai_report: ThreatReport
    combined_verdict: CombinedVerdict
    comparison: dict = Field(
        ...,
        description="AI vs VirusTotal comparison: alignment, confidence score, and explanation",
    )


class ErrorResponse(BaseModel):
    """Standard error response."""
    success: bool = False
    error: str
    detail: Optional[str] = None
