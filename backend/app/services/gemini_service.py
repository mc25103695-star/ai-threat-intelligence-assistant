"""
Gemini Service - AI-Powered Threat Analysis

Takes aggregated threat intelligence (from VT + AbuseIPDB) and
sends it to Google Gemini to produce a structured, analyst-friendly
threat intelligence report.

Pipeline:
    1. Gemini is ALWAYS attempted first.
    2. If Gemini fails (quota, network, parse error), the service
       falls back to a deterministic rule-based analysis.
    3. The response always includes "analysis_source" so the
       frontend knows which engine produced the report.

Output sections:
    1. Threat Summary
    2. Risk Assessment
    3. Potential Attack Types
    4. Investigation Steps
    5. Analyst Questions
    6. Mitigation Recommendations

Usage:
    from app.services.gemini_service import GeminiService

    gemini = GeminiService()
    report = await gemini.analyze_threat(aggregated_data)
"""

import json
import logging

from google import genai
from google.genai import types

from app.config import settings

logger = logging.getLogger("app.services.gemini")


# ============================================================
# JSON Schema for Gemini Response Validation
# ============================================================

EXPECTED_SCHEMA = {
    "threat_summary": str,
    "risk_assessment": {
        "risk_level": str,       # CRITICAL | HIGH | MEDIUM | LOW | CLEAN
        "confidence": str,       # HIGH | MEDIUM | LOW
        "justification": str,
    },
    "potential_attack_types": list,
    "investigation_steps": list,
    "analyst_questions": list,
    "mitigation_recommendations": list,
}

VALID_RISK_LEVELS = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "CLEAN", "UNKNOWN"}
VALID_CONFIDENCE_LEVELS = {"HIGH", "MEDIUM", "LOW"}


# ============================================================
# Prompt Template — Improved
# ============================================================

SYSTEM_INSTRUCTION = """You are an elite cybersecurity threat intelligence analyst with 15+ years of experience in SOC operations, incident response, and threat hunting.

Your job is to analyze threat intelligence data collected from multiple sources (VirusTotal, AbuseIPDB) and produce a structured, actionable intelligence report.

IMPORTANT CONTEXT:
- "virustotal_current" contains REAL-TIME detection results from security engines scanning this indicator RIGHT NOW.
- "abuseipdb_historical" contains HISTORICAL abuse reports submitted by users over time. A high number of historical reports does NOT necessarily mean the indicator is currently malicious — it may have been cleaned up, reassigned, or the abuse may have stopped.
- Your analysis must distinguish between current threat status and historical reputation.

RULES:
- Be specific and actionable — avoid vague, generic statements.
- Base your analysis strictly on the provided data. Do NOT invent or assume facts.
- If data is limited or a source returned an error, acknowledge this honestly and lower your confidence accordingly.
- Tailor your analysis to the indicator type (IP, domain, or URL).
- For "potential_attack_types": infer attack types from the combination of detection patterns, risk score, reputation, and usage context — NOT by simply copying AbuseIPDB report categories.
- Always respond in valid JSON matching the exact schema provided.
"""

ANALYSIS_PROMPT_TEMPLATE = """Analyze the following threat intelligence data and produce a structured threat report.

## Indicator
- **Value:** {indicator}
- **Type:** {indicator_type}
- **Computed Risk Score:** {risk_score}/100
- **Computed Risk Level:** {risk_level}

## Intelligence Data (compact)
```json
{compact_data}
```

## Required JSON Output
Return ONLY a JSON object with these exact keys:

{{
    "threat_summary": "2-3 sentence executive summary. State what the indicator is, what the data shows, and whether it poses a current threat. Distinguish between historical reports and current detections.",

    "risk_assessment": {{
        "risk_level": "One of: CRITICAL, HIGH, MEDIUM, LOW, CLEAN",
        "confidence": "One of: HIGH, MEDIUM, LOW — based on data completeness and source agreement",
        "justification": "Cite specific numbers: VT detections (X/Y engines), AbuseIPDB confidence (Z%), reputation score, and explain what they mean together."
    }},

    "potential_attack_types": [
        "Infer specific attack types from the threat data patterns. Examples: Command & Control (C2), Phishing, Brute Force, DDoS, Malware Distribution, Cryptomining, Spam, Web Application Attack. Return empty list if the indicator is clean. Do NOT just copy AbuseIPDB categories."
    ],

    "investigation_steps": [
        "Provide 4-6 specific, actionable steps. Include exact tools, commands, or queries an analyst should run. Tailor to the indicator type ({indicator_type})."
    ],

    "analyst_questions": [
        "List 4-5 questions that help determine scope, impact, attribution, and whether this is part of a larger campaign."
    ],

    "mitigation_recommendations": [
        "Provide 4-6 specific, prioritized recommendations. Scale severity to the risk level. Include both immediate actions and long-term hardening steps."
    ]
}}
"""


class GeminiService:
    """
    AI threat analysis service.

    - Model is configurable via GEMINI_MODEL env var.
    - Gemini is ALWAYS attempted first.
    - If Gemini fails, a rule-based fallback generates the report.
    - Every response includes "analysis_source": "gemini" | "fallback".
    """

    def __init__(self):
        self.api_key = settings.GEMINI_API_KEY
        self.model_name = settings.GEMINI_MODEL
        self.client = None

        if self.api_key:
            self.client = genai.Client(api_key=self.api_key)
            logger.info("Gemini: Client initialized — model=%s", self.model_name)
        else:
            logger.warning("Gemini: No API key — will use fallback analysis.")

    # ============================================================
    # Main Analysis Method
    # ============================================================
    async def analyze_threat(self, aggregated_data: dict) -> dict:
        """
        Analyze threat data. Gemini is attempted first; on any
        failure the fallback engine takes over.

        Args:
            aggregated_data: Normalized dict from ThreatAggregator
                (must contain 'compact_summary').

        Returns:
            Structured report dict with "analysis_source" field.
        """
        indicator = aggregated_data.get("indicator", "unknown")
        indicator_type = aggregated_data.get("type", "unknown")

        # ---- Guard: no API key ----
        if not self.client:
            logger.warning(
                "Gemini: API key not configured — using fallback for %s", indicator
            )
            return self._fallback_analysis(aggregated_data)

        logger.info(
            "Gemini: Attempting AI analysis for %s (%s) — model=%s",
            indicator, indicator_type, self.model_name,
        )

        # ---- Use compact summary for the prompt (token-efficient) ----
        compact = aggregated_data.get("compact_summary", aggregated_data)
        risk_score = compact.get("risk_score", 0)
        risk_level = compact.get("risk_level", "UNKNOWN")

        prompt = ANALYSIS_PROMPT_TEMPLATE.format(
            indicator=indicator,
            indicator_type=indicator_type,
            risk_score=risk_score,
            risk_level=risk_level,
            compact_data=json.dumps(compact, indent=2, default=str),
        )

        raw_text = None  # defined here so it's accessible in except blocks

        try:
            # ---- Call Gemini API ----
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=prompt,
                config=types.GenerateContentConfig(
                    system_instruction=SYSTEM_INSTRUCTION,
                    temperature=0.2,          # Very low for factual analysis
                    max_output_tokens=2048,
                    response_mime_type="application/json",  # Force JSON output
                ),
            )

            raw_text = response.text.strip()

            # ---- Log the raw Gemini response ----
            logger.info("Gemini: Raw response received (%d chars)", len(raw_text))
            logger.debug("Gemini: Full response:\n%s", raw_text[:2000])

            # ---- Parse JSON ----
            report = json.loads(raw_text)

            # ---- Validate against expected schema ----
            validation_errors = self._validate_schema(report)
            if validation_errors:
                logger.warning(
                    "Gemini: Schema validation issues: %s — patching with defaults",
                    validation_errors,
                )

            report = self._patch_defaults(report)
            report["analysis_source"] = "gemini"

            logger.info("✅ Gemini: Analysis SUCCESS for %s — risk_level=%s",
                        indicator, report.get("risk_assessment", {}).get("risk_level", "?"))
            return report

        except json.JSONDecodeError as exc:
            logger.error(
                "❌ Gemini: JSON parse error — %s\n   Raw response (first 500 chars): %s",
                str(exc),
                (raw_text or "")[:500],
            )
            logger.info("Gemini: Falling back to rule-based analysis.")
            return self._fallback_analysis(aggregated_data)

        except Exception as exc:
            logger.error(
                "❌ Gemini: API call FAILED — %s: %s",
                type(exc).__name__, str(exc),
            )
            logger.info("Gemini: Falling back to rule-based analysis.")
            return self._fallback_analysis(aggregated_data)

    # ============================================================
    # JSON Schema Validation
    # ============================================================
    def _validate_schema(self, report: dict) -> list[str]:
        """
        Validate that the Gemini response matches the expected
        schema. Returns a list of error strings (empty = valid).
        """
        errors = []

        # ---- Check top-level keys ----
        for key, expected_type in EXPECTED_SCHEMA.items():
            if key not in report:
                errors.append(f"Missing key: '{key}'")
            elif isinstance(expected_type, type) and not isinstance(report[key], expected_type):
                errors.append(
                    f"Key '{key}' expected {expected_type.__name__}, got {type(report[key]).__name__}"
                )

        # ---- Check risk_assessment sub-keys ----
        ra = report.get("risk_assessment")
        if isinstance(ra, dict):
            for sub_key in ("risk_level", "confidence", "justification"):
                if sub_key not in ra:
                    errors.append(f"Missing risk_assessment.{sub_key}")

            if ra.get("risk_level") and ra["risk_level"] not in VALID_RISK_LEVELS:
                errors.append(
                    f"Invalid risk_level: '{ra['risk_level']}' — expected one of {VALID_RISK_LEVELS}"
                )
            if ra.get("confidence") and ra["confidence"] not in VALID_CONFIDENCE_LEVELS:
                errors.append(
                    f"Invalid confidence: '{ra['confidence']}' — expected one of {VALID_CONFIDENCE_LEVELS}"
                )
        elif ra is not None:
            errors.append(f"risk_assessment should be dict, got {type(ra).__name__}")

        # ---- Check list fields contain strings ----
        for list_key in ("potential_attack_types", "investigation_steps",
                         "analyst_questions", "mitigation_recommendations"):
            val = report.get(list_key)
            if isinstance(val, list):
                for i, item in enumerate(val):
                    if not isinstance(item, str):
                        errors.append(f"{list_key}[{i}] is not a string")
                        break  # one error per field is enough

        if errors:
            logger.warning("Gemini: Schema validation found %d issue(s)", len(errors))
            for err in errors:
                logger.warning("  → %s", err)

        return errors

    # ============================================================
    # Default Patcher (fills missing keys)
    # ============================================================
    def _patch_defaults(self, report: dict) -> dict:
        """
        Patch any missing or malformed fields with safe defaults
        so downstream code never crashes.
        """
        defaults = {
            "threat_summary": "No summary available.",
            "risk_assessment": {
                "risk_level": "UNKNOWN",
                "confidence": "LOW",
                "justification": "Analysis did not produce a risk assessment.",
            },
            "potential_attack_types": [],
            "investigation_steps": [],
            "analyst_questions": [],
            "mitigation_recommendations": [],
        }

        for key, default_value in defaults.items():
            if key not in report:
                report[key] = default_value
            elif key == "risk_assessment" and isinstance(report[key], dict):
                # Patch sub-keys within risk_assessment
                for sub_key, sub_default in defaults["risk_assessment"].items():
                    if sub_key not in report[key]:
                        report[key][sub_key] = sub_default

        return report

    # ============================================================
    # Fallback Rule-Based Analysis
    # ============================================================
    def _fallback_analysis(self, aggregated_data: dict) -> dict:
        """
        Generate a structured threat report using deterministic
        rules when Gemini is unavailable. Uses risk scores,
        detection counts, and indicator context — NOT raw
        AbuseIPDB category labels.
        """
        indicator = aggregated_data.get("indicator", "unknown")
        indicator_type = aggregated_data.get("type", "unknown")
        vt = aggregated_data.get("virustotal", {})
        abuse = aggregated_data.get("abuseipdb", {})
        verdict = aggregated_data.get("combined_verdict", {})

        # ---- Extract scores ----
        vt_malicious = vt.get("malicious", 0)
        vt_suspicious = vt.get("suspicious", 0)
        vt_harmless = vt.get("harmless", 0)
        vt_undetected = vt.get("undetected", 0)
        abuse_score = abuse.get("abuse_confidence_score", 0)
        total_reports = abuse.get("total_reports", 0)
        risk_level = verdict.get("risk_level", "UNKNOWN")
        risk_score = verdict.get("risk_score", 0)

        # ============================================================
        # 1. Threat Summary (distinguishes current vs historical)
        # ============================================================
        vt_status = "VirusTotal data not available"
        if "error" not in vt:
            total_engines = vt_malicious + vt_suspicious + vt_harmless + vt_undetected
            vt_status = (
                f"VirusTotal currently shows {vt_malicious} malicious and "
                f"{vt_suspicious} suspicious detections across {total_engines} engines"
            )

        abuse_status = "AbuseIPDB data not applicable (IP-only service)"
        if "error" not in abuse and "note" not in abuse:
            abuse_status = (
                f"AbuseIPDB historical data shows {total_reports} abuse reports "
                f"with {abuse_score}% confidence score (note: these are "
                f"accumulated reports, not real-time detections)"
            )

        threat_summary = (
            f"Analysis of {indicator_type.upper()} indicator '{indicator}': "
            f"{vt_status}. {abuse_status}. "
            f"Combined risk assessment: {risk_level} (score: {risk_score}/100)."
        )

        # ============================================================
        # 2. Attack Types — inferred from threat indicators, NOT
        #    copied from AbuseIPDB categories
        # ============================================================
        attack_types = []

        if risk_level in ("CRITICAL", "HIGH"):
            # High risk — infer based on detection patterns
            if vt_malicious >= 10:
                attack_types.append("Malware Distribution")
            if vt_malicious >= 5:
                attack_types.append("Command & Control (C2)")
            if abuse_score >= 75 and total_reports >= 50:
                attack_types.append("Brute Force / Credential Stuffing")
            if abuse_score >= 50:
                attack_types.append("Network Scanning / Reconnaissance")

            # Add type based on indicator context
            if indicator_type == "url":
                attack_types.append("Phishing / Social Engineering")
            elif indicator_type == "domain":
                if vt_malicious >= 3:
                    attack_types.append("Malicious Domain Hosting")

        elif risk_level == "MEDIUM":
            if vt_malicious >= 2:
                attack_types.append("Suspicious Activity")
            if abuse_score >= 25:
                attack_types.append("Low-Confidence Abuse")
            if vt_suspicious >= 3:
                attack_types.append("Potentially Unwanted Activity")

        # Deduplicate
        attack_types = list(dict.fromkeys(attack_types))

        # ============================================================
        # 3. Risk Justification
        # ============================================================
        justification_parts = []
        if "error" not in vt:
            justification_parts.append(
                f"VirusTotal: {vt_malicious} malicious, {vt_suspicious} suspicious "
                f"detections (current scan)"
            )
        if "error" not in abuse and "note" not in abuse:
            justification_parts.append(
                f"AbuseIPDB: {abuse_score}% confidence from {total_reports} "
                f"historical reports"
            )
        justification = ". ".join(justification_parts) if justification_parts else "Insufficient data for assessment."

        # ============================================================
        # 4. Investigation Steps (tailored to indicator type)
        # ============================================================
        investigation_steps = [
            f"Step 1: Search SIEM/firewall logs for any connections involving '{indicator}' in the past 30 days.",
            f"Step 2: Check DNS/proxy logs for resolution or access attempts to '{indicator}'.",
            "Step 3: Cross-reference this indicator with your organization's internal threat intel feeds and blocklists.",
        ]
        if indicator_type == "ip":
            investigation_steps.extend([
                f"Step 4: Run 'whois {indicator}' and 'nslookup {indicator}' to identify ownership and associated domains.",
                f"Step 5: Check Shodan (shodan.io) for open ports and services on {indicator}.",
            ])
        elif indicator_type == "domain":
            investigation_steps.extend([
                f"Step 4: Check WHOIS history and passive DNS records for '{indicator}' using tools like DomainTools or SecurityTrails.",
                f"Step 5: Verify the domain's SSL certificate and registration date for signs of typosquatting.",
            ])
        else:  # url
            investigation_steps.extend([
                f"Step 4: Submit '{indicator}' to urlscan.io or VirusTotal for dynamic sandbox analysis.",
                f"Step 5: Inspect the URL structure for suspicious patterns (encoded characters, misleading paths, lookalike domains).",
            ])

        # ============================================================
        # 5. Analyst Questions
        # ============================================================
        analyst_questions = [
            f"Have any internal systems communicated with '{indicator}' in the past 90 days?",
            "Is this indicator associated with any known APT group or threat campaign?",
            "How was this indicator initially discovered — via alert, email, or proactive hunt?",
            "Are there related indicators (other IPs, domains, hashes) that should be investigated together?",
            "Has this indicator appeared in any third-party threat intelligence reports?",
        ]

        # ============================================================
        # 6. Mitigation Recommendations (scaled to risk level)
        # ============================================================
        mitigations = []
        if risk_level in ("CRITICAL", "HIGH"):
            mitigations = [
                f"IMMEDIATE: Block '{indicator}' at the perimeter firewall, web proxy, and DNS resolver.",
                "Isolate any internal hosts that have communicated with this indicator for forensic investigation.",
                "Scan affected endpoints with updated EDR/antivirus signatures.",
                "Update IDS/IPS rules to detect and alert on traffic to/from this indicator.",
                "Notify the SOC team and escalate per your incident response playbook.",
                "Submit the indicator to your threat intelligence platform for tracking.",
            ]
        elif risk_level == "MEDIUM":
            mitigations = [
                f"Add '{indicator}' to your monitoring watchlist for 30 days.",
                "Review logs for unusual patterns or data exfiltration attempts.",
                "Consider blocking if additional corroborating evidence emerges.",
                "Update threat intelligence feeds with this indicator for future correlation.",
            ]
        else:  # LOW or CLEAN
            mitigations = [
                "No immediate blocking action required — indicator appears low-risk.",
                "Continue routine monitoring and periodic re-assessment.",
                "Document this indicator in case it reappears in future investigations.",
            ]

        # ============================================================
        # 7. Confidence Level
        # ============================================================
        if "error" in vt and ("error" in abuse or "note" in abuse):
            confidence = "LOW"
        elif "error" in vt or ("error" in abuse or "note" in abuse):
            confidence = "MEDIUM"
        else:
            confidence = "HIGH"

        return {
            "threat_summary": threat_summary,
            "risk_assessment": {
                "risk_level": risk_level,
                "confidence": confidence,
                "justification": justification,
            },
            "potential_attack_types": attack_types,
            "investigation_steps": investigation_steps,
            "analyst_questions": analyst_questions,
            "mitigation_recommendations": mitigations,
            "analysis_source": "fallback",
        }
