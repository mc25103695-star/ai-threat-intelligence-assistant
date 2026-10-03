"""
AbuseIPDB Service - IP Abuse & Reputation Intelligence

Fetches abuse reports and confidence scores for IP addresses
from the AbuseIPDB API v2.

NOTE: AbuseIPDB only supports IP address lookups.
      For domains/URLs, the aggregation layer will skip this service.

API Docs: https://docs.abuseipdb.com/#check-endpoint

Usage:
    from app.services.abuseipdb_service import AbuseIPDBService

    abuse = AbuseIPDBService()
    result = await abuse.check_ip("8.8.8.8")
"""

import logging
from typing import Optional

import httpx

from app.config import settings

logger = logging.getLogger("app.services.abuseipdb")

# ============================================================
# Constants
# ============================================================
ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"


class AbuseIPDBService:
    """
    Async client for the AbuseIPDB API v2.

    Returns a standardized dict that downstream consumers
    (aggregation layer, Gemini) can use directly. If the API
    call fails, returns an error dict for graceful degradation.
    """

    def __init__(self):
        self.api_key = settings.ABUSEIPDB_API_KEY
        self.headers = {
            "Key": self.api_key,
            "Accept": "application/json",
        }

    # --------------------------------------------------------
    # IP Address Check
    # --------------------------------------------------------
    async def check_ip(self, ip_address: str, max_age_days: int = 90) -> dict:
        """
        Check an IP address against AbuseIPDB.

        Args:
            ip_address:   The IP to look up (IPv4 or IPv6).
            max_age_days: How far back to look for reports (default 90 days).

        Returns:
            {
                "indicator": "8.8.8.8",
                "type": "ip",
                "abuse_confidence_score": 0,
                "is_public": true,
                "is_whitelisted": true,
                "isp": "Google LLC",
                "domain": "google.com",
                "country_code": "US",
                "country_name": "United States",
                "usage_type": "Data Center/Web Hosting/Transit",
                "total_reports": 50,
                "num_distinct_users": 12,
                "last_reported_at": "2025-12-01T10:30:00+00:00",
                "abuse_categories": [14, 18],
                "raw_response": { ... }
            }
        """
        logger.info("AbuseIPDB: Checking IP — %s", ip_address)

        if not self.api_key:
            logger.error("AbuseIPDB API key is not configured.")
            return {
                "indicator": ip_address,
                "type": "ip",
                "error": "AbuseIPDB API key is not configured.",
            }

        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": str(max_age_days),
            "verbose": "",          # Include country name, ISP, etc.
        }

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    f"{ABUSEIPDB_BASE_URL}/check",
                    headers=self.headers,
                    params=params,
                )

                if response.status_code == 200:
                    data = response.json().get("data", {})
                    return self._parse_response(ip_address, data)

                elif response.status_code == 401:
                    logger.error("AbuseIPDB: Invalid API key.")
                    return {
                        "indicator": ip_address,
                        "type": "ip",
                        "error": "AbuseIPDB API key is invalid.",
                    }

                elif response.status_code == 429:
                    logger.warning("AbuseIPDB: Rate limit exceeded.")
                    return {
                        "indicator": ip_address,
                        "type": "ip",
                        "error": "AbuseIPDB rate limit exceeded. Try again later.",
                    }

                else:
                    logger.error(
                        "AbuseIPDB: HTTP %d — %s",
                        response.status_code,
                        response.text[:200],
                    )
                    return {
                        "indicator": ip_address,
                        "type": "ip",
                        "error": f"AbuseIPDB API error (HTTP {response.status_code}).",
                    }

        except httpx.TimeoutException:
            logger.error("AbuseIPDB: Request timed out for %s", ip_address)
            return {
                "indicator": ip_address,
                "type": "ip",
                "error": "AbuseIPDB request timed out.",
            }
        except httpx.RequestError as exc:
            logger.error("AbuseIPDB: Request failed — %s", str(exc))
            return {
                "indicator": ip_address,
                "type": "ip",
                "error": f"AbuseIPDB request failed: {str(exc)}",
            }

    # --------------------------------------------------------
    # Response Parser
    # --------------------------------------------------------
    def _parse_response(self, ip_address: str, data: dict) -> dict:
        """Extract and normalize fields from AbuseIPDB response."""
        return {
            "indicator": ip_address,
            "type": "ip",
            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
            "is_public": data.get("isPublic", False),
            "is_whitelisted": data.get("isWhitelisted", None),
            "isp": data.get("isp", "Unknown"),
            "domain": data.get("domain", "Unknown"),
            "country_code": data.get("countryCode", "Unknown"),
            "country_name": data.get("countryName", "Unknown"),
            "usage_type": data.get("usageType", "Unknown"),
            "total_reports": data.get("totalReports", 0),
            "num_distinct_users": data.get("numDistinctUsers", 0),
            "last_reported_at": data.get("lastReportedAt", None),
            "abuse_categories": self._decode_categories(
                data.get("reports", [])
            ),
            "raw_response": data,
        }

    # --------------------------------------------------------
    # Category Decoder
    # --------------------------------------------------------
    # AbuseIPDB uses numeric category IDs.
    # Reference: https://www.abuseipdb.com/categories
    CATEGORY_MAP = {
        1: "DNS Compromise",
        2: "DNS Poisoning",
        3: "Fraud Orders",
        4: "DDoS Attack",
        5: "FTP Brute-Force",
        6: "Ping of Death",
        7: "Phishing",
        8: "Fraud VoIP",
        9: "Open Proxy",
        10: "Web Spam",
        11: "Email Spam",
        12: "Blog Spam",
        13: "VPN IP",
        14: "Port Scan",
        15: "Hacking",
        16: "SQL Injection",
        17: "Spoofing",
        18: "Brute-Force",
        19: "Bad Web Bot",
        20: "Exploited Host",
        21: "Web App Attack",
        22: "SSH",
        23: "IoT Targeted",
    }

    def _decode_categories(self, reports: list) -> list[str]:
        """
        Extract unique human-readable category names from
        the reports array returned by AbuseIPDB.
        """
        category_ids = set()
        for report in reports:
            for cat_id in report.get("categories", []):
                category_ids.add(cat_id)

        return [
            self.CATEGORY_MAP.get(cat_id, f"Unknown ({cat_id})")
            for cat_id in sorted(category_ids)
        ]
