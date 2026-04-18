"""
build_master_feed.py
Takes enriched IOCs, deduplicates them, computes summary metrics,
and writes a single master_threat_feed.json.

JSON structure:
{
  "generated":  "<ISO timestamp>",
  "date":       "<YYYY-MM-DD>",
  "summary": {
    "total_iocs": N,
    "unique_iocs": N,
    "by_type":     { "ip": N, ... },
    "by_severity": { "critical": N, ... },
    "by_source":   { "OTX": N, ... },
    "by_category": { "malware": N, ... }
  },
  "iocs": [ { ...flat IOC dict... }, ... ]
}
"""

import json
import logging
from collections import Counter, defaultdict
from datetime import datetime
import pytz

logger = logging.getLogger(__name__)

MST = pytz.timezone("America/Denver")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_float(val) -> float:
    try:
        return float(str(val).strip())
    except (ValueError, TypeError):
        return 0.0


def _parse_ts(date_str: str):
    try:
        return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
    except Exception:
        return None


def _deduplicate(iocs: list[dict]) -> list[dict]:
    """
    Keep one entry per (type, value).
    Prefer the entry with the highest confidence; break ties with most recent date.
    """
    bucket: dict[tuple, list] = defaultdict(list)
    for ioc in iocs:
        key = (ioc.get("type", ""), ioc.get("value", ""))
        if key[0] and key[1]:
            bucket[key].append(ioc)

    deduped = []
    for entries in bucket.values():
        best = max(
            entries,
            key=lambda x: (
                _safe_float(x.get("confidence", 0)),
                _parse_ts(x.get("date", "")) or datetime(1970, 1, 1, tzinfo=pytz.UTC),
            ),
        )
        deduped.append(best)

    logger.info(f"[Dedup] {len(iocs)} → {len(deduped)} unique IOCs")
    return deduped


def _clean_ioc(ioc: dict) -> dict:
    """Return a clean, consistently-keyed IOC dict for the output JSON."""
    return {
        # Core identity
        "type":          ioc.get("type", ""),
        "value":         ioc.get("value", ""),
        "source":        ioc.get("source", ""),
        # Classification
        "severity":      ioc.get("severity", "low").capitalize(),
        "confidence":    ioc.get("confidence", ""),
        "category":      ioc.get("category", "other"),
        # Context
        "description":   ioc.get("description", ""),
        "tags":          ioc.get("tags", ""),
        "date":          ioc.get("date", ""),
        # Geo / network (IPs)
        "country":       ioc.get("country", ""),
        "country_full":  ioc.get("country_full", ""),
        "city":          ioc.get("city", ""),
        "asn":           ioc.get("asn", ""),
        "org":           ioc.get("org", ""),
        # Domain / URL resolution
        "resolved_ip":   ioc.get("resolved_ip", ""),
        # C2 pivot
        "c2_ip":         ioc.get("c2_ip", ""),
        # Hash-specific
        "hash_type":     ioc.get("hash_type", ""),
        # CVE-specific
        "cve":           ioc.get("cve", ""),
        "cvss":          ioc.get("cvss", 0.0),
        "cvss_severity": ioc.get("cvss_severity", ""),
        "vendor":        ioc.get("vendor", ""),
        "product":       ioc.get("product", ""),
        "published":     ioc.get("published", ""),
        # APT-specific
        "apt":                    ioc.get("apt", ""),
        "aliases":                ioc.get("aliases", ""),
        "attribution_confidence": ioc.get("attribution_confidence", ""),
        "state_sponsor":          ioc.get("state_sponsor", ""),
        "targets":                ioc.get("targets", ""),
        "victims":                ioc.get("victims", ""),
        "refs":                   ioc.get("refs", ""),
        # Threat attribution
        "actor":          ioc.get("actor", ""),
        "malware":        ioc.get("malware", ""),
        # AbuseIPDB-specific
        "abuse_categories": ioc.get("abuse_categories", []),
        "categories_raw":   ioc.get("categories_raw", []),
        "last_seen":        ioc.get("last_seen", ""),
        "isp":              ioc.get("isp", ""),
    }


# ---------------------------------------------------------------------------
# Main builder
# ---------------------------------------------------------------------------

def build_master_feed(iocs: list[dict], output_path: str) -> dict:
    """
    Deduplicate, summarize, and write master_threat_feed.json.
    Returns the full data dict.
    """
    now = datetime.now(MST)
    date_str = now.strftime("%Y-%m-%d")

    deduped = _deduplicate(iocs)
    cleaned = [_clean_ioc(ioc) for ioc in deduped]

    # Summary counters
    by_type     = Counter(c["type"]     for c in cleaned)
    by_severity = Counter(c["severity"].lower() for c in cleaned)
    by_source   = Counter(c["source"]   for c in cleaned)
    by_category = Counter(c["category"] for c in cleaned)

    data = {
        "generated":  now.isoformat(),
        "date":       date_str,
        "summary": {
            "total_iocs":  len(iocs),
            "unique_iocs": len(cleaned),
            "by_type":     dict(by_type),
            "by_severity": dict(by_severity),
            "by_source":   dict(by_source),
            "by_category": dict(by_category),
        },
        "iocs": cleaned,
    }

    import pathlib
    pathlib.Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    logger.info(f"[Output] Master feed written → {output_path}")
    logger.info(f"[Output] {len(cleaned)} unique IOCs across {len(by_type)} types")
    return data