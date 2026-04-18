"""
enrich.py
Enriches a list of normalized IOC dicts in-place.
  - IPs       → IPinfo (country, city, ASN, org) + country_full with flag
  - IP:Port   → same as IP but preserve port in value
  - Domains   → DNS resolution
  - Hashes    → infer hash type
  - CVEs      → NVD API for CVSS, vendor, product; mark severity from CVSS
  - APTs      → already enriched from MISP; country_full added
  - All       → extract confidence from description, assign severity, category
"""

import re
import socket
import logging
import os
import time
import json
import requests
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

IPINFO_TOKEN = os.getenv("IPINFO_TOKEN")
NVD_API_KEY  = os.getenv("NVD_API_KEY", "")     # optional — raises rate limit to 50/30s

IP_RE   = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
CONF_RE = re.compile(r"Confidence:\s*([\d.]+)", re.I)

NVD_CACHE_FILE = Path(".nvd_cache.json")

SEVERITY_THRESHOLDS = [
    ("critical", 0.9),
    ("high",     0.7),
    ("medium",   0.5),
    ("low",      0.0),
]

CVSS_SEVERITY_MAP = {
    "critical": "critical",
    "high":     "high",
    "medium":   "medium",
    "low":      "low",
    "none":     "low",
}

THREAT_KEYWORDS = {
    "phishing":      ["phish", "credential", "spearphish"],
    "malware":       ["malware", "trojan", "backdoor", "rat ", "loader", "dropper", "infostealer"],
    "ransomware":    ["ransom", "lockbit", "blackcat", "ryuk", "conti", "akira"],
    "ddos":          ["ddos", "botnet", "mirai", "flood"],
    "c2":            ["c2", "command and control", "cobalt strike", "beacon", "c&c", "metasploit"],
    "cryptojacking": ["miner", "crypto", "xmrig", "coinhive"],
    "spyware":       ["spyware", "stalkerware", "pegasus", "keylog"],
    "exploit":       ["exploit", "cve-", "buffer overflow", "rce", "lpe"],
}

# ---------------------------------------------------------------------------
# Country helpers
# ---------------------------------------------------------------------------

COUNTRY_NAMES: dict[str, str] = {
    "AF": "Afghanistan",      "AL": "Albania",          "DZ": "Algeria",
    "AR": "Argentina",        "AU": "Australia",        "AT": "Austria",
    "AZ": "Azerbaijan",       "BD": "Bangladesh",       "BY": "Belarus",
    "BE": "Belgium",          "BR": "Brazil",           "BG": "Bulgaria",
    "KH": "Cambodia",         "CA": "Canada",           "CL": "Chile",
    "CN": "China",            "CO": "Colombia",         "HR": "Croatia",
    "CZ": "Czech Republic",   "DK": "Denmark",          "EG": "Egypt",
    "EE": "Estonia",          "FI": "Finland",          "FR": "France",
    "GE": "Georgia",          "DE": "Germany",          "GH": "Ghana",
    "GR": "Greece",           "HK": "Hong Kong",        "HU": "Hungary",
    "IN": "India",            "ID": "Indonesia",        "IR": "Iran",
    "IQ": "Iraq",             "IE": "Ireland",          "IL": "Israel",
    "IT": "Italy",            "JP": "Japan",            "JO": "Jordan",
    "KZ": "Kazakhstan",       "KE": "Kenya",            "KP": "North Korea",
    "KR": "South Korea",      "LV": "Latvia",           "LB": "Lebanon",
    "LT": "Lithuania",        "LU": "Luxembourg",       "MY": "Malaysia",
    "MX": "Mexico",           "MA": "Morocco",          "MM": "Myanmar",
    "NL": "Netherlands",      "NZ": "New Zealand",      "NG": "Nigeria",
    "NO": "Norway",           "PK": "Pakistan",         "PH": "Philippines",
    "PL": "Poland",           "PT": "Portugal",         "RO": "Romania",
    "RU": "Russia",           "SA": "Saudi Arabia",     "SG": "Singapore",
    "ZA": "South Africa",     "ES": "Spain",            "SE": "Sweden",
    "CH": "Switzerland",      "SY": "Syria",            "TW": "Taiwan",
    "TH": "Thailand",         "TR": "Turkey",           "UA": "Ukraine",
    "AE": "UAE",              "GB": "United Kingdom",   "US": "United States",
    "UZ": "Uzbekistan",       "VN": "Vietnam",          "YE": "Yemen",
}


def cc_to_flag(cc: str) -> str:
    """Convert ISO-2 country code to Unicode flag emoji."""
    if not cc or len(cc) != 2:
        return ""
    cc = cc.upper()
    return chr(0x1F1E6 + ord(cc[0]) - ord("A")) + chr(0x1F1E6 + ord(cc[1]) - ord("A"))


def country_display(cc: str) -> str:
    """Return '🇷🇺 Russia' style string from a 2-letter country code."""
    if not cc:
        return ""
    cc = cc.upper().strip()
    flag = cc_to_flag(cc)
    name = COUNTRY_NAMES.get(cc, cc)
    return f"{flag} {name}".strip()


# ---------------------------------------------------------------------------
# NVD CVE enrichment (with disk cache + rate limiting)
# ---------------------------------------------------------------------------

_nvd_cache: dict = {}
_nvd_request_times: list[float] = []


def _load_nvd_cache():
    global _nvd_cache
    if NVD_CACHE_FILE.exists():
        try:
            _nvd_cache = json.loads(NVD_CACHE_FILE.read_text(encoding="utf-8"))
        except Exception:
            _nvd_cache = {}


def _save_nvd_cache():
    try:
        NVD_CACHE_FILE.write_text(
            json.dumps(_nvd_cache, indent=2, ensure_ascii=False), encoding="utf-8"
        )
    except Exception as e:
        logger.debug(f"[NVD] Cache save failed: {e}")


def _nvd_rate_wait():
    """Enforce NVD rate limit: 5 req/30s (no key) or 50 req/30s (with key)."""
    global _nvd_request_times
    limit  = 45 if NVD_API_KEY else 4   # stay a little under the hard limits
    window = 30.0
    now = time.monotonic()
    _nvd_request_times = [t for t in _nvd_request_times if now - t < window]
    if len(_nvd_request_times) >= limit:
        sleep_for = window - (now - _nvd_request_times[0]) + 0.2
        if sleep_for > 0:
            logger.debug(f"[NVD] Rate limit pause {sleep_for:.1f}s")
            time.sleep(sleep_for)
        _nvd_request_times = []
    _nvd_request_times.append(time.monotonic())


def _nvd_fetch(cve_id: str) -> dict:
    """Fetch CVSS + vendor/product from NVD for one CVE ID."""
    _nvd_rate_wait()
    try:
        headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
        r = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"cveId": cve_id},
            headers=headers,
            timeout=12,
        )
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        logger.debug(f"[NVD] {cve_id}: {e}")
        return {}

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return {}

    cve_data = vulns[0].get("cve", {})

    # CVSS score (prefer v3.1 → v3.0 → v2)
    metrics = cve_data.get("metrics", {})
    cvss_score = 0.0
    cvss_sev   = ""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            m = metrics[key][0].get("cvssData", {})
            cvss_score = float(m.get("baseScore", 0.0))
            cvss_sev   = str(m.get("baseSeverity", "")).lower()
            break

    # vendor / product from CPE configurations
    vendor, product = "", ""
    for config in cve_data.get("configurations", []):
        for node in config.get("nodes", []):
            for cpe in node.get("cpeMatch", []):
                parts = cpe.get("criteria", "").split(":")
                if len(parts) >= 5 and parts[2] == "a":
                    vendor  = parts[3].replace("_", " ").title()
                    product = parts[4].replace("_", " ").title()
                    break
            if vendor:
                break
        if vendor:
            break

    published = (cve_data.get("published") or "")[:10]

    return {
        "cvss":         cvss_score,
        "cvss_severity": cvss_sev,
        "vendor":       vendor,
        "product":      product,
        "published":    published,
    }


def nvd_enrich_batch(cve_iocs: list[dict]):
    """Enrich a list of CVE IOC dicts in-place using NVD. Caches results."""
    _load_nvd_cache()
    dirty = False
    total = len(cve_iocs)
    logger.info(f"[NVD] Enriching {total} CVEs...")

    for i, ioc in enumerate(cve_iocs):
        cve_id = ioc.get("cve") or ioc.get("value", "")
        if not cve_id:
            continue

        if cve_id in _nvd_cache:
            result = _nvd_cache[cve_id]
        else:
            result = _nvd_fetch(cve_id)
            _nvd_cache[cve_id] = result
            dirty = True
            if (i + 1) % 20 == 0:
                _save_nvd_cache()   # periodic flush
                logger.info(f"[NVD] {i + 1}/{total} fetched")

        if result:
            # Only override vendor/product if CISA KEV didn't already set them
            if result.get("cvss"):
                ioc["cvss"] = result["cvss"]
            if result.get("cvss_severity"):
                ioc["cvss_severity"] = result["cvss_severity"]
            if result.get("vendor") and not ioc.get("vendor"):
                ioc["vendor"] = result["vendor"]
            if result.get("product") and not ioc.get("product"):
                ioc["product"] = result["product"]
            if result.get("published") and not ioc.get("published"):
                ioc["published"] = result["published"]

    if dirty:
        _save_nvd_cache()
    logger.info(f"[NVD] Done enriching CVEs.")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_ip(text: str) -> str:
    m = IP_RE.search(text)
    return m.group(0) if m else ""


def _infer_hash_type(h: str) -> str:
    h = h.strip().lower()
    if len(h) == 32:  return "MD5"
    if len(h) == 40:  return "SHA1"
    if len(h) == 64:  return "SHA256"
    return "unknown"


def _safe_float(val) -> float:
    try:
        return float(str(val).strip())
    except (ValueError, TypeError):
        return 0.0


def _get_severity(ioc: dict) -> str:
    """Derive severity from CVSS (CVEs) or confidence score (everything else)."""
    ioc_type = ioc.get("type", "")
    if ioc_type == "cve":
        cvss = _safe_float(ioc.get("cvss", 0))
        if cvss >= 9.0: return "critical"
        if cvss >= 7.0: return "high"
        if cvss >= 4.0: return "medium"
        if cvss > 0.0:  return "low"
        # no CVSS data — KEV entries are all at minimum high
        return "high"
    conf = _safe_float(ioc.get("confidence", 0))
    for sev, thresh in SEVERITY_THRESHOLDS:
        if conf >= thresh:
            return sev
    return "low"


def _categorize(ioc: dict) -> str:
    text = " ".join([
        ioc.get("description", ""),
        ioc.get("tags", ""),
        ioc.get("value", ""),
        ioc.get("malware", ""),
    ]).lower()
    for cat, kws in THREAT_KEYWORDS.items():
        if any(kw in text for kw in kws):
            return cat
    return "other"


def _ipinfo(ip: str) -> dict:
    if not IPINFO_TOKEN:
        return {}
    try:
        r = requests.get(
            f"https://ipinfo.io/{ip}/json",
            headers={"Authorization": f"Bearer {IPINFO_TOKEN}"},
            timeout=6,
        )
        r.raise_for_status()
        return r.json()
    except Exception as e:
        logger.debug(f"[IPinfo] {ip}: {e}")
        return {}


def _resolve(domain: str) -> str:
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Per-type enrichment
# ---------------------------------------------------------------------------

def _enrich_ip(ioc: dict):
    # AbuseIPDB blacklist already provides country + ISP — skip IPinfo to avoid
    # burning 10k requests on every run.
    if ioc.get("source") == "AbuseIPDB":
        cc = (ioc.get("country") or "").upper()
        if cc:
            ioc["country_full"] = country_display(cc)
        if not ioc.get("org") and ioc.get("isp"):
            ioc["org"] = ioc["isp"]
        ioc["c2_ip"] = _extract_ip(ioc.get("description", ""))
        return

    data = _ipinfo(ioc["value"])
    if data:
        cc = data.get("country", ioc.get("country", ""))
        ioc["country"]      = cc
        ioc["country_full"] = country_display(cc)
        ioc["city"]         = data.get("city", "")
        org_raw             = data.get("org", "")
        ioc["asn"]          = org_raw.split(" ")[0] if org_raw else ""
        ioc["org"]          = " ".join(org_raw.split(" ")[1:]) if org_raw else ioc.get("isp", "")
    elif ioc.get("country"):
        ioc["country_full"] = country_display(ioc["country"])
        if not ioc.get("org") and ioc.get("isp"):
            ioc["org"] = ioc["isp"]
    ioc["c2_ip"] = _extract_ip(ioc.get("description", ""))


def _enrich_ip_port(ioc: dict):
    """Enrich IP:Port entries — geo-lookup on the IP portion."""
    value = ioc["value"]
    ip_part = value.split(":")[0] if ":" in value else value
    temp = dict(ioc)
    temp["value"] = ip_part
    _enrich_ip(temp)
    # Copy enrichment fields back, keep original value
    for field in ("country", "country_full", "city", "asn", "org", "c2_ip"):
        ioc[field] = temp.get(field, "")


def _enrich_domain(ioc: dict):
    ioc["resolved_ip"] = _resolve(ioc["value"])
    ioc["c2_ip"]       = _extract_ip(ioc.get("description", ""))


def _enrich_url(ioc: dict):
    m = re.match(r"https?://([^/?\s]+)", ioc["value"])
    if m:
        ioc["resolved_ip"] = _resolve(m.group(1))
    ioc["c2_ip"] = _extract_ip(ioc.get("description", ""))


def _enrich_hash(ioc: dict):
    if not ioc.get("hash_type"):
        ioc["hash_type"] = _infer_hash_type(ioc["value"])
    ioc["c2_ip"] = _extract_ip(ioc.get("description", ""))


def _enrich_cve(ioc: dict):
    val = ioc["value"].upper()
    if not val.startswith("CVE-"):
        val = ""
    ioc["value"] = val
    ioc["cve"]   = val
    ioc["c2_ip"] = _extract_ip(ioc.get("description", ""))
    # CVSS enrichment happens in nvd_enrich_batch (called separately for efficiency)


def _enrich_apt(ioc: dict):
    if not ioc.get("apt"):
        ioc["apt"] = ioc["value"]
    cc = ioc.get("country", "")
    if cc and not ioc.get("country_full"):
        ioc["country_full"] = country_display(cc)
    ioc["c2_ip"] = _extract_ip(ioc.get("description", ""))


# ---------------------------------------------------------------------------
# Confidence + tags from description
# ---------------------------------------------------------------------------

def _process_description(ioc: dict):
    desc = ioc.get("description", "")
    m = CONF_RE.search(desc)
    if m:
        ioc["confidence"] = m.group(1)
        desc = CONF_RE.sub("", desc).strip()
        ioc["description"] = desc
    if not ioc.get("tags") and desc:
        ioc["tags"] = desc


# ---------------------------------------------------------------------------
# Main enrichment function
# ---------------------------------------------------------------------------

ENRICHERS = {
    "ip":           _enrich_ip,
    "ip_port":      _enrich_ip_port,
    "domain":       _enrich_domain,
    "url":          _enrich_url,
    "hash":         _enrich_hash,
    "cve":          _enrich_cve,
    "threat_actor": _enrich_apt,
}


def enrich_all(iocs: list[dict]) -> list[dict]:
    """
    Enrich a list of normalized IOC dicts.
    Modifies in-place; returns the same list with severity + category + geo added.
    """
    total = len(iocs)
    logger.info(f"[Enrich] Starting enrichment of {total} IOCs...")

    # --- Pass 1: per-type enrichment ---
    for i, ioc in enumerate(iocs):
        if i % 500 == 0 and i > 0:
            logger.info(f"[Enrich] {i}/{total}")

        _process_description(ioc)

        fn = ENRICHERS.get(ioc["type"])
        if fn:
            try:
                fn(ioc)
            except Exception as e:
                logger.debug(f"[Enrich] Error on {ioc['type']} {ioc['value']}: {e}")

        ioc["category"] = _categorize(ioc)

    # --- Pass 2: NVD batch for CVEs ---
    cve_iocs = [ioc for ioc in iocs if ioc["type"] == "cve"]
    if cve_iocs:
        nvd_enrich_batch(cve_iocs)

    # --- Pass 3: severity (after CVSS populated) ---
    for ioc in iocs:
        ioc["severity"] = _get_severity(ioc)

    logger.info(f"[Enrich] Done. {total} IOCs enriched.")
    return iocs


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    sample = [
        {
            "type": "ip", "value": "8.8.8.8", "source": "test",
            "description": "Confidence: 90", "date": "", "country": "",
            "attribution_confidence": "", "state_sponsor": "", "victims": "",
            "targets": "", "synonyms": "", "refs": "", "confidence": "",
            "tags": "", "city": "", "asn": "", "org": "", "resolved_ip": "",
            "c2_ip": "", "hash_type": "", "cve": "", "apt": "", "aliases": "",
            "actor": "", "malware": "", "categories_raw": [], "last_seen": "",
            "usage_type": "", "isp": "", "cvss": 0.0, "cvss_severity": "",
            "vendor": "", "product": "", "published": "", "country_full": "",
            "abuse_categories": [],
        },
    ]
    result = enrich_all(sample)
    import json
    print(json.dumps(result, indent=2))
