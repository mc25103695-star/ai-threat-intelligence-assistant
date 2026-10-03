"""
Threat Aggregator - Combines intelligence from all sources

Calls VirusTotal and AbuseIPDB concurrently, merges their
results into a single normalized dict that the Gemini
analysis layer can consume.

Logic:
    - IP addresses  → VirusTotal + AbuseIPDB (both)
    - Domains       → VirusTotal domain + resolve IP → AbuseIPDB
    - URLs          → Parse URL → VT URL + VT IP + AbuseIPDB IP
                      + URL heuristic scoring

Usage:
    from app.services.aggregator import ThreatAggregator

    aggregator = ThreatAggregator()
    report = await aggregator.gather_intelligence("8.8.8.8", "ip")
"""

import asyncio
import logging
import re
from datetime import datetime, timezone
from urllib.parse import urlparse

from app.services.virustotal_service import VirusTotalService
from app.services.abuseipdb_service import AbuseIPDBService

logger = logging.getLogger("app.services.aggregator")

# ============================================================
# Service Instances (shared across requests)
# ============================================================
vt_service = VirusTotalService()
abuse_service = AbuseIPDBService()

# ============================================================
# URL Heuristic Constants
# ============================================================
SUSPICIOUS_EXTENSIONS = {
    ".sh", ".exe", ".bat", ".ps1", ".cmd", ".vbs", ".js",
    ".msi", ".dll", ".scr", ".pif", ".wsf", ".hta",
    ".elf", ".bin", ".py", ".pl", ".rb",
}

STANDARD_PORTS = {80, 443, 8080, 8443}

# Regex to detect an IPv4 address
IPV4_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


class ThreatAggregator:
    """
    Orchestrates threat data collection and normalization.

    The output dict is designed so Gemini receives everything
    it needs in a single, clean structure — no further lookups.
    """

    SUPPORTED_TYPES = {"ip", "domain", "url"}

    async def gather_intelligence(self, indicator: str, indicator_type: str) -> dict:
        """
        Collect and merge threat intelligence for a given indicator.

        Args:
            indicator:      The value to analyze (e.g., "8.8.8.8", "evil.com")
            indicator_type: One of "ip", "domain", "url"

        Returns:
            A normalized dict with keys:
                indicator, type, timestamp,
                virustotal, abuseipdb,
                combined_verdict
        """
        if indicator_type not in self.SUPPORTED_TYPES:
            return {
                "indicator": indicator,
                "type": indicator_type,
                "error": f"Unsupported indicator type: '{indicator_type}'. "
                         f"Use one of: {', '.join(self.SUPPORTED_TYPES)}",
            }

        logger.info(
            "Aggregator: Gathering intelligence for %s (%s)",
            indicator, indicator_type,
        )

        # ---- Dispatch to the right collector ----
        if indicator_type == "ip":
            vt_data, abuse_data, extras = await self._collect_ip(indicator)
        elif indicator_type == "domain":
            vt_data, abuse_data, extras = await self._collect_domain(indicator)
        else:  # url
            vt_data, abuse_data, extras = await self._collect_url(indicator)

        # ---- Build normalized report ----
        report = self._build_report(
            indicator, indicator_type, vt_data, abuse_data, extras
        )

        logger.info(
            "Aggregator: Completed — verdict=%s, vt_malicious=%s, abuse_score=%s",
            report["combined_verdict"]["risk_level"],
            report["virustotal"].get("malicious", "N/A"),
            report["abuseipdb"].get("abuse_confidence_score", "N/A"),
        )

        return report

    # ============================================================
    # URL Parser
    # ============================================================

    @staticmethod
    def _parse_url(url: str) -> dict:
        """
        Parse a URL and extract security-relevant components.

        Returns:
            {
                "host": "182.116.116.205",
                "port": 49661,
                "path": "/bin.sh",
                "is_ip": True,
                "has_non_standard_port": True,
                "suspicious_extension": ".sh",
                "has_encoded_path": False,
            }
        """
        try:
            parsed = urlparse(url)
        except Exception:
            return {"host": "", "port": None, "path": "", "is_ip": False}

        host = parsed.hostname or ""
        port = parsed.port
        path = parsed.path or ""

        is_ip = bool(IPV4_PATTERN.match(host))

        # Non-standard port detection
        has_non_standard_port = port is not None and port not in STANDARD_PORTS

        # Suspicious file extension
        ext = ""
        if "." in path.split("/")[-1]:
            ext = "." + path.split("/")[-1].rsplit(".", 1)[-1].lower()
        suspicious_ext = ext if ext in SUSPICIOUS_EXTENSIONS else None

        # Encoded/obfuscated path detection
        has_encoded_path = bool(re.search(r"%[0-9a-fA-F]{2}", path))

        return {
            "host": host,
            "port": port,
            "path": path,
            "is_ip": is_ip,
            "has_non_standard_port": has_non_standard_port,
            "suspicious_extension": suspicious_ext,
            "has_encoded_path": has_encoded_path,
        }

    # ============================================================
    # URL Heuristic Scorer
    # ============================================================

    @staticmethod
    def _compute_url_heuristics(parsed: dict) -> tuple:
        """
        Compute a heuristic risk score from URL structure alone.

        Returns (score, factors_list).
        """
        score = 0
        factors = []

        if parsed.get("is_ip"):
            score += 15
            factors.append(f"URL contains raw IP address ({parsed['host']})")

        if parsed.get("has_non_standard_port"):
            score += 10
            factors.append(f"Non-standard port ({parsed['port']})")

        ext = parsed.get("suspicious_extension")
        if ext:
            score += 15
            factors.append(f"Suspicious file extension ({ext})")

        if parsed.get("has_encoded_path"):
            score += 5
            factors.append("URL path contains encoded/obfuscated characters")

        return score, factors

    # ============================================================
    # Collectors — run API calls concurrently where possible
    # ============================================================

    async def _collect_ip(self, ip: str):
        """IP → call both VT and AbuseIPDB in parallel."""
        vt_data, abuse_data = await asyncio.gather(
            vt_service.analyze_ip(ip),
            abuse_service.check_ip(ip),
        )
        return vt_data, abuse_data, {}

    async def _collect_domain(self, domain: str):
        """
        Domain → VT domain analysis.
        Also attempt to resolve the domain's IP via VT data
        and query AbuseIPDB with it.
        """
        vt_data = await vt_service.analyze_domain(domain)

        extras = {}

        # Try to extract an IP from VT's domain response (last_dns_records)
        resolved_ip = None
        if "error" not in vt_data:
            raw = vt_data.get("raw_response", {})
            dns_records = raw.get("last_dns_records", [])
            for record in dns_records:
                if record.get("type") == "A":
                    resolved_ip = record.get("value")
                    break

        if resolved_ip and IPV4_PATTERN.match(resolved_ip):
            logger.info("Aggregator: Domain %s resolved to IP %s — querying AbuseIPDB", domain, resolved_ip)
            abuse_data = await abuse_service.check_ip(resolved_ip)
            extras["resolved_ip"] = resolved_ip
            extras["ip_abuse_data"] = abuse_data
        else:
            abuse_data = {"indicator": domain, "type": "domain", "note": "AbuseIPDB supports IP addresses only."}

        return vt_data, abuse_data, extras

    async def _collect_url(self, url: str):
        """
        URL → Parse URL → Run VT URL scan + VT IP scan + AbuseIPDB IP scan.

        If the URL contains an IP address (e.g., http://182.116.x.x:port/path),
        also queries VT and AbuseIPDB for the embedded IP to cross-reference.
        """
        parsed = self._parse_url(url)
        host = parsed.get("host", "")
        is_ip = parsed.get("is_ip", False)

        logger.info(
            "Aggregator: URL parsed — host=%s, port=%s, is_ip=%s, ext=%s",
            host, parsed.get("port"), is_ip, parsed.get("suspicious_extension"),
        )

        # Always query VT for the URL itself
        tasks = [vt_service.analyze_url(url)]

        # If the host is an IP, also query VT IP + AbuseIPDB IP
        if is_ip and host:
            tasks.append(vt_service.analyze_ip(host))
            tasks.append(abuse_service.check_ip(host))
        else:
            tasks.append(self._noop())
            tasks.append(self._noop())

        results = await asyncio.gather(*tasks, return_exceptions=True)

        vt_url_data = results[0] if not isinstance(results[0], Exception) else {"error": str(results[0])}

        extras = {"url_parsed": parsed}

        if is_ip and host:
            vt_ip_data = results[1] if not isinstance(results[1], Exception) else {"error": str(results[1])}
            abuse_ip_data = results[2] if not isinstance(results[2], Exception) else {"error": str(results[2])}

            extras["embedded_ip"] = host
            extras["ip_vt_data"] = vt_ip_data
            extras["ip_abuse_data"] = abuse_ip_data

            # Use IP abuse data as the primary AbuseIPDB result
            abuse_data = abuse_ip_data

            logger.info(
                "Aggregator: Embedded IP %s — VT malicious=%s, AbuseIPDB score=%s",
                host,
                vt_ip_data.get("malicious", "N/A"),
                abuse_ip_data.get("abuse_confidence_score", "N/A"),
            )
        else:
            abuse_data = {"indicator": url, "type": "url", "note": "AbuseIPDB supports IP addresses only."}

        return vt_url_data, abuse_data, extras

    @staticmethod
    async def _noop():
        """No-op coroutine for gather() padding."""
        return None

    # ============================================================
    # Report Builder
    # ============================================================

    def _build_report(
        self,
        indicator: str,
        indicator_type: str,
        vt_data: dict,
        abuse_data: dict,
        extras: dict = None,
    ) -> dict:
        """
        Merge VT + AbuseIPDB data into a single normalized report.

        Strips raw_response from both to keep the payload lean
        (Gemini doesn't need the full raw dump — just the parsed fields).
        """
        extras = extras or {}

        # Remove bulky raw data before sending to Gemini
        vt_clean = {k: v for k, v in vt_data.items() if k != "raw_response"}
        abuse_clean = {k: v for k, v in abuse_data.items() if k != "raw_response"}
        verdict = self._compute_verdict(vt_data, abuse_data, extras)

        # Build the compact summary for Gemini (token-efficient)
        compact = self._build_compact_summary(
            indicator, indicator_type, vt_clean, abuse_clean, verdict, extras
        )

        report = {
            "indicator": indicator,
            "type": indicator_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "virustotal": vt_clean,
            "abuseipdb": abuse_clean,
            "combined_verdict": verdict,
            "compact_summary": compact,
        }

        # Include enrichment data if present
        if "url_parsed" in extras:
            report["url_parsed"] = extras["url_parsed"]
        if "embedded_ip" in extras:
            ip_vt = extras.get("ip_vt_data", {})
            ip_abuse = extras.get("ip_abuse_data", {})
            report["ip_enrichment"] = {
                "ip": extras["embedded_ip"],
                "vt_malicious": ip_vt.get("malicious", 0) if "error" not in ip_vt else "N/A",
                "vt_suspicious": ip_vt.get("suspicious", 0) if "error" not in ip_vt else "N/A",
                "abuse_score": ip_abuse.get("abuse_confidence_score", 0) if "error" not in ip_abuse else "N/A",
                "abuse_reports": ip_abuse.get("total_reports", 0) if "error" not in ip_abuse else "N/A",
            }
        if "resolved_ip" in extras:
            report["resolved_ip"] = extras["resolved_ip"]

        return report

    # ============================================================
    # Compact Summary for Gemini
    # ============================================================

    def _build_compact_summary(
        self,
        indicator: str,
        indicator_type: str,
        vt: dict,
        abuse: dict,
        verdict: dict,
        extras: dict = None,
    ) -> dict:
        """
        Build a minimal, token-efficient dict that contains only
        the metrics Gemini needs for analysis. This is what gets
        sent in the prompt — NOT the full API responses.

        Distinguishes between historical reports (abuse reports
        accumulated over time) and current detection status
        (live engine scans from VirusTotal).
        """
        extras = extras or {}

        summary = {
            "indicator": indicator,
            "type": indicator_type,
            "risk_score": verdict.get("risk_score", 0),
            "risk_level": verdict.get("risk_level", "UNKNOWN"),
            "risk_factors": verdict.get("factors", []),
        }

        # ---- VirusTotal: current detection status ----
        if "error" not in vt:
            total_engines = (
                vt.get("malicious", 0) + vt.get("suspicious", 0)
                + vt.get("harmless", 0) + vt.get("undetected", 0)
            )
            summary["virustotal_current"] = {
                "malicious_detections": vt.get("malicious", 0),
                "suspicious_detections": vt.get("suspicious", 0),
                "clean_detections": vt.get("harmless", 0),
                "total_engines": total_engines,
                "reputation_score": vt.get("reputation", 0),
                "country": vt.get("country", "Unknown"),
                "as_owner": vt.get("as_owner", "Unknown"),
            }
        else:
            summary["virustotal_current"] = {"error": vt["error"]}

        # ---- AbuseIPDB: historical abuse reports ----
        if "error" not in abuse and "note" not in abuse:
            summary["abuseipdb_historical"] = {
                "abuse_confidence_percent": abuse.get("abuse_confidence_score", 0),
                "total_reports": abuse.get("total_reports", 0),
                "distinct_reporters": abuse.get("num_distinct_users", 0),
                "last_reported_at": abuse.get("last_reported_at", None),
                "isp": abuse.get("isp", "Unknown"),
                "usage_type": abuse.get("usage_type", "Unknown"),
                "note": "These are historical abuse reports — not current real-time detections.",
            }
        else:
            reason = abuse.get("note") or abuse.get("error", "Unavailable")
            summary["abuseipdb_historical"] = {"unavailable": reason}

        # ---- URL/Domain enrichment for Gemini ----
        if "url_parsed" in extras:
            summary["url_analysis"] = extras["url_parsed"]
        if "embedded_ip" in extras:
            ip_vt = extras.get("ip_vt_data", {})
            summary["embedded_ip_threat"] = {
                "ip": extras["embedded_ip"],
                "vt_malicious": ip_vt.get("malicious", 0) if "error" not in ip_vt else "N/A",
            }

        return summary

    # ============================================================
    # Risk Verdict Calculator
    # ============================================================

    def _compute_verdict(self, vt_data: dict, abuse_data: dict, extras: dict = None) -> dict:
        """
        Compute a combined risk level from all data sources.

        Scoring logic:
            - VT malicious detections  → weighted heavily
            - VT suspicious detections → moderate weight
            - AbuseIPDB confidence     → weighted heavily
            - VT reputation (negative) → minor weight
            - URL heuristics           → structural risk signals
            - Embedded IP reputation   → cross-reference boost

        Risk levels:
            CRITICAL  → score >= 80
            HIGH      → score >= 50
            MEDIUM    → score >= 25
            LOW       → score >= 10
            CLEAN     → score < 10
        """
        extras = extras or {}
        score = 0
        factors = []

        # ---- VirusTotal signals (URL/Domain/IP) ----
        vt_malicious = vt_data.get("malicious", 0)
        vt_suspicious = vt_data.get("suspicious", 0)
        vt_reputation = vt_data.get("reputation", 0)

        if "error" not in vt_data:
            if vt_malicious > 0:
                score += min(vt_malicious * 5, 50)   # cap at 50
                factors.append(f"VT: {vt_malicious} malicious detections")
            if vt_suspicious > 0:
                score += min(vt_suspicious * 3, 20)  # cap at 20
                factors.append(f"VT: {vt_suspicious} suspicious detections")
            if vt_reputation < 0:
                score += min(abs(vt_reputation), 15) # cap at 15
                factors.append(f"VT: negative reputation ({vt_reputation})")
        else:
            factors.append(f"VT: unavailable — {vt_data['error']}")

        # ---- AbuseIPDB signals ----
        abuse_score = abuse_data.get("abuse_confidence_score", 0)
        total_reports = abuse_data.get("total_reports", 0)

        if "error" not in abuse_data and "note" not in abuse_data:
            if abuse_score > 0:
                score += min(abuse_score, 50)  # 0-100 scale, cap at 50
                factors.append(f"AbuseIPDB: confidence {abuse_score}%")
            if total_reports > 0:
                factors.append(f"AbuseIPDB: {total_reports} reports")
        elif "note" in abuse_data:
            factors.append(abuse_data["note"])

        # ---- URL heuristic scoring ----
        url_parsed = extras.get("url_parsed")
        if url_parsed:
            h_score, h_factors = self._compute_url_heuristics(url_parsed)
            score += h_score
            factors.extend(h_factors)

        # ---- Embedded IP cross-reference (URL contains an IP) ----
        ip_vt = extras.get("ip_vt_data", {})
        ip_abuse = extras.get("ip_abuse_data", {})

        if ip_vt and "error" not in ip_vt:
            ip_mal = ip_vt.get("malicious", 0)
            ip_sus = ip_vt.get("suspicious", 0)
            if ip_mal > 0:
                ip_boost = min(ip_mal * 4, 40)
                score += ip_boost
                factors.append(f"Embedded IP: {ip_mal} malicious detections (VT)")
            if ip_sus > 0:
                score += min(ip_sus * 2, 15)
                factors.append(f"Embedded IP: {ip_sus} suspicious detections (VT)")
            ip_rep = ip_vt.get("reputation", 0)
            if ip_rep < 0:
                score += min(abs(ip_rep), 10)
                factors.append(f"Embedded IP: negative reputation ({ip_rep})")

        if ip_abuse and "error" not in ip_abuse and "note" not in ip_abuse:
            ip_abuse_score = ip_abuse.get("abuse_confidence_score", 0)
            ip_reports = ip_abuse.get("total_reports", 0)
            if ip_abuse_score > 0:
                score += min(ip_abuse_score, 40)
                factors.append(f"Embedded IP AbuseIPDB: confidence {ip_abuse_score}%")
            if ip_reports > 0:
                factors.append(f"Embedded IP AbuseIPDB: {ip_reports} reports")

        # ---- Domain resolved IP cross-reference ----
        resolved_abuse = extras.get("ip_abuse_data") if "resolved_ip" in extras else None
        if resolved_abuse and "error" not in resolved_abuse and "note" not in resolved_abuse:
            res_score = resolved_abuse.get("abuse_confidence_score", 0)
            if res_score > 0 and "embedded_ip" not in extras:  # avoid double-counting
                score += min(res_score, 30)
                factors.append(f"Resolved IP AbuseIPDB: confidence {res_score}%")

        # ---- Determine risk level ----
        if score >= 80:
            risk_level = "CRITICAL"
        elif score >= 50:
            risk_level = "HIGH"
        elif score >= 25:
            risk_level = "MEDIUM"
        elif score >= 10:
            risk_level = "LOW"
        else:
            risk_level = "CLEAN"

        return {
            "risk_level": risk_level,
            "risk_score": min(score, 100),
            "factors": factors,
        }

