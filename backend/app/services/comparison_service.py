"""
Comparison Service - AI vs VirusTotal Assessment

Compares the AI-generated threat assessment against raw
VirusTotal detection data to produce:
  - Alignment status (Agree / Partial / Disagree)
  - Confidence score (0-100%)
  - Detailed explanation
  - Side-by-side data points

This is the "bonus feature" that validates AI findings
against real threat intelligence data.

Usage:
    from app.services.comparison_service import ComparisonService

    comparison = ComparisonService()
    result = comparison.compare(ai_report, aggregated_data)
"""

import logging

logger = logging.getLogger("app.services.comparison")


class ComparisonService:
    """
    Compares AI threat assessment with VirusTotal findings
    to measure alignment and produce a confidence score.
    """

    RISK_ORDER = ["CLEAN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

    def compare(self, ai_report: dict, aggregated_data: dict) -> dict:
        """
        Run the comparison between AI assessment and VT data.

        Args:
            ai_report:       The structured report from Gemini/fallback.
            aggregated_data: The full aggregated data from ThreatAggregator.

        Returns:
            {
                "ai_assessment": { ... },
                "vt_assessment": { ... },
                "alignment": "Agree" | "Partial" | "Disagree",
                "confidence_score": 0-100,
                "explanation": "...",
                "details": [ ... ]
            }
        """
        vt = aggregated_data.get("virustotal", {})
        ai_risk = ai_report.get("risk_assessment", {})

        # ---- Extract AI side ----
        ai_level = (ai_risk.get("risk_level", "UNKNOWN")).upper()
        ai_confidence = ai_risk.get("confidence", "N/A")
        ai_attack_count = len(ai_report.get("potential_attack_types", []))
        ai_source = ai_report.get("analysis_source", "unknown")

        ai_assessment = {
            "risk_level": ai_level,
            "confidence": ai_confidence,
            "attack_types_identified": ai_attack_count,
            "analysis_source": ai_source,
        }

        # ---- Extract VT side ----
        if "error" in vt:
            return self._vt_unavailable(ai_assessment, vt.get("error", ""))

        malicious = vt.get("malicious", 0)
        suspicious = vt.get("suspicious", 0)
        harmless = vt.get("harmless", 0)
        undetected = vt.get("undetected", 0)
        total = malicious + suspicious + harmless + undetected
        reputation = vt.get("reputation", 0)

        vt_level = self._compute_vt_risk_level(malicious, suspicious)
        detection_rate = round((malicious / total * 100), 1) if total > 0 else 0

        vt_assessment = {
            "risk_level": vt_level,
            "malicious_detections": malicious,
            "suspicious_detections": suspicious,
            "clean_detections": harmless,
            "total_engines": total,
            "detection_rate_percent": detection_rate,
            "reputation_score": reputation,
        }

        # ---- Compute alignment ----
        alignment, confidence, explanation = self._compute_alignment(
            ai_level, vt_level, malicious, suspicious, total, reputation, ai_confidence
        )

        # ---- Build detail points ----
        details = self._build_details(
            ai_level, vt_level, malicious, suspicious, total, reputation, ai_confidence
        )

        result = {
            "ai_assessment": ai_assessment,
            "vt_assessment": vt_assessment,
            "alignment": alignment,
            "confidence_score": confidence,
            "explanation": explanation,
            "details": details,
        }

        logger.info(
            "Comparison: AI=%s, VT=%s, Alignment=%s, Confidence=%d%%",
            ai_level, vt_level, alignment, confidence,
        )

        return result

    # ============================================================
    # VT Risk Level Computation
    # ============================================================

    def _compute_vt_risk_level(self, malicious: int, suspicious: int) -> str:
        """Derive a risk level from raw VT detection counts."""
        if malicious >= 10:
            return "CRITICAL"
        elif malicious >= 5:
            return "HIGH"
        elif malicious >= 2 or suspicious >= 3:
            return "MEDIUM"
        elif malicious >= 1 or suspicious >= 1:
            return "LOW"
        else:
            return "CLEAN"

    # ============================================================
    # Alignment Computation
    # ============================================================

    def _compute_alignment(
        self, ai_level, vt_level, malicious, suspicious, total, reputation, ai_confidence
    ):
        """
        Compare AI risk level with VT-derived risk level.

        Returns (alignment, confidence_score, explanation).
        """
        ai_idx = self.RISK_ORDER.index(ai_level) if ai_level in self.RISK_ORDER else -1
        vt_idx = self.RISK_ORDER.index(vt_level) if vt_level in self.RISK_ORDER else -1

        # Unknown AI risk level
        if ai_idx == -1:
            return (
                "Inconclusive",
                30,
                "AI produced an unknown risk level — comparison inconclusive.",
            )

        diff = abs(ai_idx - vt_idx)

        if diff == 0:
            # Perfect agreement
            confidence = 95 if ai_confidence == "HIGH" else 85
            return (
                "Agree",
                confidence,
                f"AI and VirusTotal independently assess this indicator as {vt_level}. "
                f"With {malicious}/{total} malicious detections and AI confidence of {ai_confidence}, "
                f"the assessment is well-corroborated.",
            )

        elif diff == 1:
            # Adjacent levels — minor divergence
            confidence = 70 if ai_confidence == "HIGH" else 60
            direction = "higher" if ai_idx > vt_idx else "lower"
            return (
                "Partial",
                confidence,
                f"AI assessed the risk as {ai_level} while VirusTotal data suggests {vt_level}. "
                f"AI rates the threat slightly {direction} than raw detections alone. "
                f"This is common when AI considers contextual factors beyond detection counts.",
            )

        else:
            # Significant divergence
            confidence = 40
            return (
                "Disagree",
                confidence,
                f"Significant divergence: AI assessed {ai_level} but VirusTotal indicates {vt_level} "
                f"({malicious}/{total} malicious detections, reputation {reputation}). "
                f"Manual review is strongly recommended to resolve this discrepancy.",
            )

    # ============================================================
    # Detail Points
    # ============================================================

    def _build_details(
        self, ai_level, vt_level, malicious, suspicious, total, reputation, ai_confidence
    ):
        """Build a list of comparison detail observations."""
        details = []

        # Detection coverage
        if total > 0:
            rate = round(malicious / total * 100, 1)
            details.append(
                f"VirusTotal: {malicious} of {total} engines ({rate}%) flagged this as malicious."
            )
        else:
            details.append("VirusTotal: No engine data available.")

        # Suspicious count
        if suspicious > 0:
            details.append(
                f"VirusTotal: {suspicious} engines flagged this as suspicious (not confirmed malicious)."
            )

        # Reputation
        if reputation < 0:
            details.append(
                f"VirusTotal reputation score is negative ({reputation}), indicating community distrust."
            )
        elif reputation > 0:
            details.append(
                f"VirusTotal reputation score is positive ({reputation}), suggesting community trust."
            )

        # Level comparison
        if ai_level == vt_level:
            details.append(
                f"Both AI and VirusTotal agree on {ai_level} risk — high confidence in assessment."
            )
        else:
            details.append(
                f"AI assessed {ai_level} vs VirusTotal's {vt_level} — review recommended."
            )

        # AI confidence note
        details.append(
            f"AI analysis confidence: {ai_confidence}."
        )

        return details

    # ============================================================
    # VT Unavailable Fallback
    # ============================================================

    def _vt_unavailable(self, ai_assessment: dict, error: str) -> dict:
        """Return a comparison result when VT data is not available."""
        return {
            "ai_assessment": ai_assessment,
            "vt_assessment": {"error": error},
            "alignment": "N/A",
            "confidence_score": 0,
            "explanation": f"VirusTotal data unavailable ({error}). Cannot compare AI findings against threat intelligence.",
            "details": ["Comparison requires VirusTotal data to validate AI assessment."],
        }
