"""
VirusTotal Service - Threat Intelligence Integration

Fetches threat intelligence data from the VirusTotal API v3 for:
  - IP addresses
  - Domain names
  - URLs

API Docs: https://docs.virustotal.com/reference/overview

Usage:
    from app.services.virustotal_service import VirusTotalService

    vt = VirusTotalService()
    result = await vt.analyze_ip("8.8.8.8")
"""

import logging
import base64
from typing import Optional

import httpx

from app.config import settings

logger = logging.getLogger("app.services.virustotal")

# ============================================================
# Constants
# ============================================================
VT_BASE_URL = "https://www.virustotal.com/api/v3"


class VirusTotalService:
    """
    Async client for the VirusTotal API v3.

    Each method returns a standardized dict with the fields
    downstream consumers (aggregation layer, Gemini) expect.
    If the API call fails, returns an error dict instead of
    raising — so the pipeline can degrade gracefully.
    """

    def __init__(self):
        self.api_key = settings.VIRUSTOTAL_API_KEY
        self.headers = {"x-apikey": self.api_key}

    # --------------------------------------------------------
    # Internal: make an authenticated GET request
    # --------------------------------------------------------
    async def _get(self, endpoint: str) -> dict:
        """
        Make a GET request to VT API.
        Returns the JSON response or an error dict.
        """
        if not self.api_key:
            logger.error("VirusTotal API key is not configured.")
            return {"error": "VirusTotal API key is not configured."}

        url = f"{VT_BASE_URL}/{endpoint}"
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(url, headers=self.headers)

                if response.status_code == 200:
                    return response.json()
                elif response.status_code == 404:
                    logger.warning("VT: Resource not found — %s", endpoint)
                    return {"error": "Resource not found on VirusTotal."}
                elif response.status_code == 429:
                    logger.warning("VT: Rate limit exceeded.")
                    return {"error": "VirusTotal rate limit exceeded. Try again later."}
                else:
                    logger.error("VT: HTTP %d — %s", response.status_code, response.text[:200])
                    return {"error": f"VirusTotal API error (HTTP {response.status_code})."}

        except httpx.TimeoutException:
            logger.error("VT: Request timed out for %s", endpoint)
            return {"error": "VirusTotal request timed out."}
        except httpx.RequestError as exc:
            logger.error("VT: Request failed — %s", str(exc))
            return {"error": f"VirusTotal request failed: {str(exc)}"}

    # --------------------------------------------------------
    # IP Address Analysis
    # --------------------------------------------------------
    async def analyze_ip(self, ip_address: str) -> dict:
        """
        Fetch threat intelligence for an IP address.

        Returns:
            {
                "indicator": "8.8.8.8",
                "type": "ip",
                "malicious": 2,
                "suspicious": 0,
                "harmless": 70,
                "undetected": 10,
                "reputation": -5,
                "country": "US",
                "as_owner": "GOOGLE",
                "network": "8.8.8.0/24",
                "total_votes": {"harmless": 100, "malicious": 5},
                "raw_response": { ... }
            }
        """
        logger.info("VT: Analyzing IP — %s", ip_address)
        data = await self._get(f"ip_addresses/{ip_address}")

        if "error" in data:
            return {"indicator": ip_address, "type": "ip", **data}

        return self._parse_ip_response(ip_address, data)

    def _parse_ip_response(self, ip_address: str, data: dict) -> dict:
        """Extract relevant fields from a VT IP response."""
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        return {
            "indicator": ip_address,
            "type": "ip",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attributes.get("reputation", 0),
            "country": attributes.get("country", "Unknown"),
            "as_owner": attributes.get("as_owner", "Unknown"),
            "network": attributes.get("network", "Unknown"),
            "total_votes": attributes.get("total_votes", {}),
            "raw_response": attributes,
        }

    # --------------------------------------------------------
    # Domain Analysis
    # --------------------------------------------------------
    async def analyze_domain(self, domain: str) -> dict:
        """
        Fetch threat intelligence for a domain name.

        Returns:
            {
                "indicator": "example.com",
                "type": "domain",
                "malicious": 0,
                "suspicious": 1,
                "harmless": 65,
                "undetected": 8,
                "reputation": 10,
                "registrar": "...",
                "creation_date": 1234567890,
                "categories": { ... },
                "total_votes": {"harmless": 50, "malicious": 2},
                "raw_response": { ... }
            }
        """
        logger.info("VT: Analyzing Domain — %s", domain)
        data = await self._get(f"domains/{domain}")

        if "error" in data:
            return {"indicator": domain, "type": "domain", **data}

        return self._parse_domain_response(domain, data)

    def _parse_domain_response(self, domain: str, data: dict) -> dict:
        """Extract relevant fields from a VT domain response."""
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        return {
            "indicator": domain,
            "type": "domain",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attributes.get("reputation", 0),
            "registrar": attributes.get("registrar", "Unknown"),
            "creation_date": attributes.get("creation_date", None),
            "categories": attributes.get("categories", {}),
            "total_votes": attributes.get("total_votes", {}),
            "raw_response": attributes,
        }

    # --------------------------------------------------------
    # URL Analysis
    # --------------------------------------------------------
    async def analyze_url(self, url: str) -> dict:
        """
        Fetch threat intelligence for a URL.

        VT API expects the URL to be encoded as a base64url string
        (without padding) to form the URL identifier.

        Returns:
            {
                "indicator": "https://evil.com/malware",
                "type": "url",
                "malicious": 5,
                "suspicious": 2,
                "harmless": 50,
                "undetected": 3,
                "reputation": -20,
                "final_url": "...",
                "title": "...",
                "total_votes": {"harmless": 10, "malicious": 8},
                "raw_response": { ... }
            }
        """
        logger.info("VT: Analyzing URL — %s", url)

        # VT URL identifier = base64url(url) without '=' padding
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        data = await self._get(f"urls/{url_id}")

        if "error" in data:
            return {"indicator": url, "type": "url", **data}

        return self._parse_url_response(url, data)

    def _parse_url_response(self, url: str, data: dict) -> dict:
        """Extract relevant fields from a VT URL response."""
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        return {
            "indicator": url,
            "type": "url",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attributes.get("reputation", 0),
            "final_url": attributes.get("last_final_url", url),
            "title": attributes.get("title", "Unknown"),
            "total_votes": attributes.get("total_votes", {}),
            "raw_response": attributes,
        }
