"""
pull_iocs.py
Pulls raw IOCs from open-source threat feeds.
Returns a list of normalized IOC dicts.
"""

import requests
import logging
import os
from datetime import datetime
import pytz
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

MST = pytz.timezone("America/Denver")
TODAY = datetime.now(MST).strftime("%Y-%m-%d")
NOW_ISO = datetime.now(MST).isoformat()

OTX_API_KEY       = os.getenv("OTX_API_KEY")
ABUSE_API_KEY     = os.getenv("ABUSE_API_KEY")
THREATFOX_API_KEY = os.getenv("THREATFOX_API_KEY")
IPINFO_TOKEN      = os.getenv("IPINFO_TOKEN")

# ---------------------------------------------------------------------------
# AbuseIPDB category ID → display name
# ---------------------------------------------------------------------------
ABUSEIPDB_CATEGORIES = {
    3: "Fraud Orders",     4: "DDoS Attack",      5: "FTP Brute-Force",
    6: "Ping of Death",    7: "Phishing",          8: "Fraud VoIP",
    9: "Open Proxy",      10: "Web Spam",         11: "Email Spam",
   12: "Blog Spam",       13: "VPN IP",           14: "Port Scan",
   15: "Hacking",         18: "Brute-Force",      19: "Bad Web Bot",
   20: "Exploited Host",  21: "Web App Attack",   22: "SSH",
   23: "IoT Targeted",
}

# ---------------------------------------------------------------------------
# Type normalization
# ---------------------------------------------------------------------------
TYPE_MAP = {
    "ipv4": "ip", "ip": "ip",
    "ip:port": "ip_port",                     # preserve port info
    "hostname": "domain", "domain": "domain",
    "url": "url",
    "md5_hash": "hash",   "sha1_hash": "hash",   "sha256_hash": "hash",
    "filehash-md5": "hash", "filehash-sha1": "hash", "filehash-sha256": "hash",
    "cve": "cve",
    "apt": "threat_actor", "threat_actor": "threat_actor",
}

VALID_TYPES = {"ip", "ip_port", "domain", "url", "hash", "cve", "threat_actor"}


def normalize(ioc: dict) -> dict | None:
    """Normalize and validate a raw IOC dict. Returns None if invalid."""
    raw_type = str(ioc.get("type", "")).lower().strip()
    ioc_type = TYPE_MAP.get(raw_type, raw_type)

    if ioc_type not in VALID_TYPES:
        return None

    value = str(ioc.get("value", "")).strip()
    if not value:
        return None

    # Normalize date
    raw_date = ioc.get("date", "")
    parsed_date = ""
    if raw_date:
        for fmt in ["%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%Y-%m-%dT%H:%M:%S"]:
            try:
                dt = datetime.strptime(str(raw_date), fmt)
                if dt.tzinfo is None:
                    dt = MST.localize(dt)
                parsed_date = dt.isoformat()
                break
            except ValueError:
                continue
    if not parsed_date:
        parsed_date = NOW_ISO

    return {
        "type":                   ioc_type,
        "value":                  value,
        "source":                 str(ioc.get("source", "unknown")),
        "description":            str(ioc.get("description", ""))[:500].strip(),
        "date":                   parsed_date,
        "country":                str(ioc.get("country", "")).strip(),
        "attribution_confidence": str(ioc.get("attribution_confidence", "")).strip(),
        "state_sponsor":          str(ioc.get("state_sponsor", "")).strip(),
        "victims":                str(ioc.get("victims", "")).strip(),
        "targets":                str(ioc.get("targets", "")).strip(),
        "synonyms":               str(ioc.get("synonyms", "")).strip(),
        "refs":                   str(ioc.get("refs", "")).strip(),
        # enrichment fields (populated later)
        "confidence":             str(ioc.get("confidence", "")).strip(),
        "tags":                   str(ioc.get("tags", "")).strip(),
        "city":                   "",
        "asn":                    "",
        "org":                    str(ioc.get("org", "")).strip(),
        "resolved_ip":            "",
        "c2_ip":                  "",
        "hash_type":              str(ioc.get("hash_type", "")).strip(),
        "cve":                    str(ioc.get("cve", "")).strip(),
        "apt":                    str(ioc.get("apt", "")).strip(),
        "aliases":                str(ioc.get("aliases", "")).strip(),
        # extra per-source fields
        "actor":                  str(ioc.get("actor", "")).strip(),
        "malware":                str(ioc.get("malware", "")).strip(),
        "categories_raw":         ioc.get("categories_raw", []),   # list of AbuseIPDB cat IDs
        "last_seen":              str(ioc.get("last_seen", "")).strip(),
        "usage_type":             str(ioc.get("usage_type", "")).strip(),
        "isp":                    str(ioc.get("isp", "")).strip(),
        # CVE enrichment fields (populated by enrich.py via NVD)
        "cvss":                   ioc.get("cvss", 0.0),
        "cvss_severity":          str(ioc.get("cvss_severity", "")).strip(),
        "vendor":                 str(ioc.get("vendor", "")).strip(),
        "product":                str(ioc.get("product", "")).strip(),
        "published":              str(ioc.get("published", "")).strip(),
        "country_full":           str(ioc.get("country_full", "")).strip(),
    }


# ---------------------------------------------------------------------------
# Source pullers
# ---------------------------------------------------------------------------

def pull_otx() -> list[dict]:
    if not OTX_API_KEY:
        logger.warning("[OTX] No API key, skipping.")
        return []
    logger.info("[OTX] Pulling pulses...")
    try:
        r = requests.get(
            "https://otx.alienvault.com/api/v1/pulses/subscribed",
            headers={"X-OTX-API-KEY": OTX_API_KEY},
            params={"limit": 100},
            timeout=20,
        )
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        logger.error(f"[OTX] Failed: {e}")
        return []

    iocs = []
    for pulse in data.get("results", []):
        adversary = pulse.get("adversary", "") or ""
        malware_families = pulse.get("malware_families", []) or []
        malware_str = ", ".join(
            (m.get("display_name", "") or m.get("id", "") if isinstance(m, dict) else str(m))
            for m in malware_families
            if m
        )
        tags = ", ".join(pulse.get("tags", []) or [])

        for ind in pulse.get("indicators", []):
            if not isinstance(ind, dict):
                continue
            raw = {
                "type":        ind.get("type", ""),
                "value":       ind.get("indicator", ""),
                "source":      "OTX",
                "description": pulse.get("name", ""),
                "date":        pulse.get("modified", ""),
                "actor":       adversary,
                "malware":     malware_str,
                "tags":        tags,
            }
            n = normalize(raw)
            if n:
                iocs.append(n)
    logger.info(f"[OTX] {len(iocs)} IOCs")
    return iocs


def pull_threatfox() -> list[dict]:
    logger.info("[ThreatFox] Pulling IOCs...")
    headers = {"API-KEY": THREATFOX_API_KEY} if THREATFOX_API_KEY else {}
    try:
        r = requests.get(
            "https://threatfox.abuse.ch/export/csv/recent/",
            headers=headers,
            timeout=20,
        )
        r.raise_for_status()
        lines = r.text.splitlines()
    except Exception as e:
        logger.error(f"[ThreatFox] Failed: {e}")
        return []

    # Actual CSV columns (header line):
    # "first_seen_utc","ioc_id","ioc_value","ioc_type","threat_type",
    # "fk_malware","malware_alias","malware_printable","last_seen_utc",
    # "confidence_level","is_compromised","reference","tags","anonymous","reporter"
    import csv, io

    iocs = []
    for line in lines:
        if line.startswith("#") or not line.strip():
            continue
        try:
            parts = next(csv.reader(io.StringIO(line), skipinitialspace=True))
        except Exception:
            continue
        if len(parts) < 10:
            continue

        malware_name = parts[7].strip()   # malware_printable  e.g. "Vidar"
        fk_malware   = parts[5].strip()   # fk_malware         e.g. "win.vidar"
        malware      = malware_name if malware_name and malware_name.lower() != "none" else fk_malware
        conf_raw     = parts[9].strip()

        raw = {
            "type":        parts[3].strip(),    # ioc_type
            "value":       parts[2].strip(),    # ioc_value
            "source":      "ThreatFox",
            "description": malware,             # human-readable malware name
            "malware":     malware,
            "date":        parts[0].strip(),    # first_seen_utc
            "confidence":  conf_raw,
            "tags":        parts[12].strip() if len(parts) > 12 else fk_malware,
        }
        n = normalize(raw)
        if n:
            iocs.append(n)
    logger.info(f"[ThreatFox] {len(iocs)} IOCs")
    return iocs


def pull_abuseipdb() -> list[dict]:
    if not ABUSE_API_KEY:
        logger.warning("[AbuseIPDB] No API key, skipping.")
        return []
    logger.info("[AbuseIPDB] Pulling blacklist...")
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/blacklist",
            headers={"Accept": "application/json", "Key": ABUSE_API_KEY},
            params={"confidenceMinimum": 90, "limit": 10000},
            timeout=30,
        )
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        logger.error(f"[AbuseIPDB] Failed: {e}")
        return []

    iocs = []
    for entry in data.get("data", []):
        # Map category IDs to names (blacklist returns list of ints)
        cat_ids = entry.get("categories", []) or []
        cat_names = [ABUSEIPDB_CATEGORIES.get(c, str(c)) for c in cat_ids if c]

        raw = {
            "type":          "ip",
            "value":         entry.get("ipAddress", ""),
            "source":        "AbuseIPDB",
            "description":   f"Abuse confidence: {entry.get('abuseConfidenceScore', '')}",
            "date":          entry.get("lastReportedAt", ""),
            "confidence":    str(entry.get("abuseConfidenceScore", "")),
            "country":       entry.get("countryCode", ""),
            "categories_raw": cat_ids,
            "last_seen":     entry.get("lastReportedAt", ""),
            "usage_type":    entry.get("usageType", ""),
            "isp":           entry.get("isp", "") or entry.get("domain", ""),
            "tags":          ", ".join(cat_names),
        }
        n = normalize(raw)
        if n:
            n["categories_raw"] = cat_ids       # preserve list through normalize
            n["abuse_categories"] = cat_names   # resolved names list
            iocs.append(n)
    logger.info(f"[AbuseIPDB] {len(iocs)} IPs")
    return iocs


def pull_urlhaus() -> list[dict]:
    logger.info("[URLHaus] Pulling URLs...")
    try:
        r = requests.get(
            "https://urlhaus.abuse.ch/downloads/csv_recent/",
            timeout=20,
        )
        r.raise_for_status()
        lines = r.text.splitlines()
    except Exception as e:
        logger.error(f"[URLHaus] Failed: {e}")
        return []

    iocs = []
    for line in lines:
        if line.startswith("#") or not line.strip():
            continue
        parts = line.split('","')
        if len(parts) < 5:
            parts = line.split(",")
        if len(parts) < 5:
            continue

        def _strip(s):
            return s.strip().strip('"')

        raw = {
            "type":        "url",
            "value":       _strip(parts[2]),
            "source":      "URLHaus",
            "description": _strip(parts[4]),
            "date":        _strip(parts[1]),
            "tags":        _strip(parts[5]) if len(parts) > 5 else "",
        }
        n = normalize(raw)
        if n:
            iocs.append(n)
    logger.info(f"[URLHaus] {len(iocs)} URLs")
    return iocs


def pull_cisa_kev() -> list[dict]:
    logger.info("[CISA KEV] Pulling CVEs...")
    try:
        r = requests.get(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            timeout=20,
        )
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        logger.error(f"[CISA KEV] Failed: {e}")
        return []

    iocs = []
    for item in data.get("vulnerabilities", []):
        cve_id = item.get("cveID", "")
        if not cve_id:
            continue
        raw = {
            "type":        "cve",
            "value":       cve_id,
            "cve":         cve_id,
            "source":      "CISA KEV",
            "description": item.get("vulnerabilityName", "Known Exploited Vulnerability"),
            "date":        item.get("dateAdded", ""),
            "published":   item.get("dateAdded", ""),
            "vendor":      item.get("vendorProject", ""),
            "product":     item.get("product", ""),
            "tags":        item.get("requiredAction", ""),
        }
        n = normalize(raw)
        if n:
            n["cve"] = cve_id
            iocs.append(n)
    logger.info(f"[CISA KEV] {len(iocs)} CVEs")
    return iocs


def pull_misp_apt() -> list[dict]:
    logger.info("[MISP Galaxy] Pulling APT groups...")
    try:
        r = requests.get(
            "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json",
            timeout=20,
        )
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        logger.error(f"[MISP Galaxy] Failed: {e}")
        return []

    iocs = []
    for actor in data.get("values", []):
        meta = actor.get("meta", {})
        name = actor.get("value", "").strip()
        if not name:
            continue

        synonyms = meta.get("synonyms", []) or []
        victims = meta.get("cfr-suspected-victims", []) or []
        targets = meta.get("cfr-target-category", []) or []
        incident_types = meta.get("cfr-type-of-incident", []) or []
        refs = meta.get("refs", []) or []

        raw = {
            "type":                   "threat_actor",
            "value":                  name,
            "apt":                    name,
            "source":                 "MISP Galaxy",
            "description":            actor.get("description", ""),
            "date":                   TODAY,
            "country":                meta.get("country", ""),
            "attribution_confidence": str(meta.get("attribution-confidence", "")),
            "state_sponsor":          meta.get("cfr-suspected-state-sponsor", ""),
            "victims":                ", ".join(victims),
            "targets":                ", ".join(targets),
            "synonyms":               ", ".join(synonyms),
            "refs":                   ", ".join(refs),
            "aliases":                ", ".join(synonyms),
            "tags":                   ", ".join(incident_types),
        }
        n = normalize(raw)
        if n:
            n["apt"]     = name
            n["aliases"] = raw["aliases"]
            iocs.append(n)
    logger.info(f"[MISP Galaxy] {len(iocs)} APT groups")
    return iocs


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def pull_all() -> list[dict]:
    """Pull from all sources and return a combined, normalized list."""
    all_iocs = []
    for fn in [pull_otx, pull_threatfox, pull_abuseipdb, pull_urlhaus, pull_cisa_kev, pull_misp_apt]:
        try:
            all_iocs.extend(fn())
        except Exception as e:
            logger.error(f"Unhandled error in {fn.__name__}: {e}")
    logger.info(f"[*] Total raw IOCs pulled: {len(all_iocs)}")
    return all_iocs


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    iocs = pull_all()
    print(f"Pulled {len(iocs)} IOCs")
