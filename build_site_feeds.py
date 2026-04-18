"""
build_site_feeds.py
Transforms enriched IOC data into the 6 JSON files consumed by the threat intel
page on the site:

  output/threats/cves.json
  output/threats/ips.json
  output/threats/iocs.json
  output/threats/actors.json
  output/threats/origins.json
  output/threats/stats.json
"""

import json
import logging
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path

from enrich import country_display, COUNTRY_NAMES, cc_to_flag

logger = logging.getLogger(__name__)

OUTPUT_DIR = Path("output/threats")

# Rank → bar color for origins.json
ORIGIN_COLORS = [
    "#ff4d4d", "#ff6b35", "#ffaa00", "#f59e0b",
    "#a855f7", "#6366f1", "#3fbfff", "#00c97a",
]

# Map internal type → site display type
IOC_TYPE_DISPLAY = {
    "ip":           "IP",
    "ip_port":      "IP:Port",
    "domain":       "Domain",
    "url":          "URL",
    "hash":         None,   # resolved from hash_type below
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _safe_float(val) -> float:
    try:
        return float(str(val).strip())
    except (ValueError, TypeError):
        return 0.0


def _cvss_to_severity(cvss: float) -> str:
    if cvss >= 9.0: return "critical"
    if cvss >= 7.0: return "high"
    if cvss >= 4.0: return "medium"
    if cvss > 0.0:  return "low"
    return "high"   # KEV default when no CVSS data


def _ioc_display_type(ioc: dict) -> str | None:
    t = ioc.get("type", "")
    if t == "hash":
        ht = ioc.get("hash_type", "").upper()
        if ht in ("MD5", "SHA256", "SHA1"):
            return ht
        return "SHA256"   # best guess
    return IOC_TYPE_DISPLAY.get(t)


def _first_two_sentences(text: str, max_chars: int = 220) -> str:
    if not text:
        return ""
    text = text.strip()
    sentences = re.split(r"(?<=[.!?])\s+", text)
    result = " ".join(sentences[:2])
    if len(result) > max_chars:
        result = result[:max_chars].rsplit(" ", 1)[0] + "..."
    return result


def _actor_status(description: str) -> str:
    desc = (description or "").lower()
    if any(kw in desc for kw in ("dismantled", "arrested", "disrupted", "indicted", "seized")):
        return "disrupted"
    if any(kw in desc for kw in ("inactive", "dormant", "no recent", "last seen 20")):
        return "dormant"
    return "active"


def _derive_tactics(ioc: dict) -> list[str]:
    """Infer tactic names from tags / cfr-type-of-incident / description."""
    combined = " ".join([
        ioc.get("tags", ""),
        ioc.get("description", ""),
        ioc.get("targets", ""),
    ]).lower()

    tactic_kws = {
        "Spear Phishing":    ["phishing", "spearphish", "spear-phish"],
        "Supply Chain":      ["supply chain", "software supply"],
        "Watering Hole":     ["watering hole", "waterhole"],
        "Ransomware":        ["ransom", "lockbit", "blackcat", "ryuk"],
        "Espionage":         ["espionage", "intel", "intelligence collection"],
        "DDoS":              ["ddos", "denial of service"],
        "C2 Infrastructure": ["c2", "command and control", "cobalt strike", "beacon"],
        "Credential Theft":  ["credential", "password", "harvest"],
        "OAuth Abuse":       ["oauth", "token abuse"],
        "Zero-Day Exploit":  ["zero-day", "0day", "zeroday"],
        "Living off Land":   ["lolbas", "living off", "lolbin"],
    }
    found = []
    for tactic, kws in tactic_kws.items():
        if any(kw in combined for kw in kws):
            found.append(tactic)
    return found or ["Unknown"]


# ---------------------------------------------------------------------------
# Most-seen IOC tracking (call before deduplication)
# ---------------------------------------------------------------------------

def compute_most_seen(raw_iocs: list[dict], top_n: int = 20) -> list[dict]:
    """
    Given the raw (pre-dedup) IOC list, return the top-N most duplicated entries.
    Each entry: { value, type, count, sources }
    """
    counts: Counter = Counter()
    sources: dict[tuple, set] = defaultdict(set)

    for ioc in raw_iocs:
        key = (ioc.get("type", ""), ioc.get("value", ""))
        if key[0] and key[1]:
            counts[key] += 1
            sources[key].add(ioc.get("source", ""))

    top = []
    for (ioc_type, value), count in counts.most_common(top_n):
        if count < 2:
            break
        top.append({
            "value":   value,
            "type":    _ioc_display_type({"type": ioc_type, "hash_type": ""}) or ioc_type,
            "count":   count,
            "sources": sorted(sources[(ioc_type, value)]),
        })
    return top


# ---------------------------------------------------------------------------
# Individual feed builders
# ---------------------------------------------------------------------------

def build_cves_json(enriched: list[dict]) -> dict:
    cves = [ioc for ioc in enriched if ioc.get("type") == "cve" and ioc.get("value")]

    items = []
    for ioc in cves:
        cve_id  = ioc.get("cve") or ioc.get("value", "")
        cvss    = _safe_float(ioc.get("cvss", 0))
        sev_raw = (ioc.get("cvss_severity") or ioc.get("severity") or "").lower()
        severity = CVSS_SEVERITY_MAP.get(sev_raw) if sev_raw in CVSS_SEVERITY_MAP else _cvss_to_severity(cvss)

        title   = ioc.get("description") or ioc.get("tags") or cve_id
        vendor  = ioc.get("vendor", "")
        product = ioc.get("product", "")
        pub     = (ioc.get("published") or ioc.get("date", ""))[:10]
        kev     = ioc.get("source", "") == "CISA KEV"

        items.append({
            "id":       cve_id,
            "title":    title,
            "vendor":   vendor,
            "product":  product,
            "cvss":     round(cvss, 1),
            "severity": severity,
            "kev":      kev,
            "published": pub,
        })

    # Sort critical first, then by CVSS desc
    items.sort(key=lambda x: (-["low","medium","high","critical"].index(x["severity"] if x["severity"] in ["low","medium","high","critical"] else "low"), -x["cvss"]))

    return {
        "updated": _now_iso(),
        "count":   len(items),
        "items":   items,
    }


CVSS_SEVERITY_MAP = {
    "critical": "critical",
    "high":     "high",
    "medium":   "medium",
    "low":      "low",
    "none":     "low",
}


def build_ips_json(enriched: list[dict]) -> dict:
    ips = [
        ioc for ioc in enriched
        if ioc.get("type") == "ip" and ioc.get("source") == "AbuseIPDB"
    ]

    items = []
    for ioc in ips:
        cc = ioc.get("country", "")
        country = ioc.get("country_full") or country_display(cc) or cc

        # Category names: prefer resolved list, fall back to tags
        cats = ioc.get("abuse_categories") or []
        if not cats:
            cat_ids = ioc.get("categories_raw", [])
            from pull_iocs import ABUSEIPDB_CATEGORIES
            cats = [ABUSEIPDB_CATEGORIES.get(c, str(c)) for c in cat_ids if c]
        if not cats and ioc.get("tags"):
            cats = [t.strip() for t in ioc["tags"].split(",") if t.strip()]

        org  = ioc.get("org") or ioc.get("isp") or ""
        conf = int(_safe_float(ioc.get("confidence", 0)))

        items.append({
            "ip":         ioc["value"],
            "confidence": min(max(conf, 0), 100),
            "country":    country,
            "org":        org,
            "lastSeen":   ioc.get("last_seen") or ioc.get("date", ""),
            "categories": cats,
            "source":     "AbuseIPDB",
        })

    # Sort by confidence desc
    items.sort(key=lambda x: -x["confidence"])

    return {
        "updated": _now_iso(),
        "count":   len(items),
        "items":   items,
    }


def build_iocs_json(enriched: list[dict]) -> dict:
    valid_sources = {"OTX", "ThreatFox"}
    valid_types   = {"ip", "ip_port", "domain", "url", "hash"}

    items = []
    for ioc in enriched:
        if ioc.get("source") not in valid_sources:
            continue
        if ioc.get("type") not in valid_types:
            continue

        display_type = _ioc_display_type(ioc)
        if not display_type:
            continue

        actor  = (ioc.get("actor") or "").strip() or "Unknown"
        malware = (ioc.get("malware") or ioc.get("description") or "").strip()
        conf   = int(_safe_float(ioc.get("confidence", 0)))
        first_seen = (ioc.get("date") or "")[:10]

        items.append({
            "value":      ioc["value"],
            "type":       display_type,
            "malware":    malware,
            "actor":      actor,
            "confidence": min(max(conf, 0), 100),
            "source":     ioc.get("source", ""),
            "firstSeen":  first_seen,
        })

    # Sort by confidence desc, then date desc
    items.sort(key=lambda x: (-x["confidence"], x["firstSeen"]), reverse=False)
    items.sort(key=lambda x: -x["confidence"])

    return {
        "updated": _now_iso(),
        "count":   len(items),
        "items":   items,
    }


def build_actors_json(enriched: list[dict]) -> dict:
    actors = [ioc for ioc in enriched if ioc.get("type") == "threat_actor"]

    items = []
    for ioc in actors:
        name = ioc.get("apt") or ioc.get("value", "")
        if not name:
            continue

        cc    = ioc.get("country", "")
        alias = ioc.get("aliases") or ioc.get("synonyms") or ""

        # Build origin string
        sponsor = ioc.get("state_sponsor", "")
        if cc:
            origin_base = ioc.get("country_full") or country_display(cc) or cc
        elif sponsor:
            origin_base = sponsor
        else:
            origin_base = "Unknown"

        if sponsor and sponsor not in origin_base:
            origin = f"{origin_base} ({sponsor})"
        else:
            origin = origin_base

        targets_raw = ioc.get("targets", "")
        targets = [t.strip() for t in targets_raw.split(",") if t.strip()] if targets_raw else []

        tactics = _derive_tactics(ioc)
        status  = _actor_status(ioc.get("description", ""))
        recent  = _first_two_sentences(ioc.get("description", ""))

        items.append({
            "name":           name,
            "alias":          alias,
            "origin":         origin,
            "status":         status,
            "targets":        targets,
            "tactics":        tactics,
            "recentActivity": recent,
            "source":         ioc.get("source", "MISP Galaxy"),
        })

    # Dedup by name
    seen = set()
    deduped = []
    for item in items:
        if item["name"] not in seen:
            seen.add(item["name"])
            deduped.append(item)

    deduped.sort(key=lambda x: x["name"])

    return {
        "updated": _now_iso(),
        "items":   deduped,
    }


def build_origins_json(enriched: list[dict]) -> dict:
    """Aggregate all IP-type IOCs by country."""
    ip_iocs = [
        ioc for ioc in enriched
        if ioc.get("type") in ("ip", "ip_port") and ioc.get("country")
    ]

    country_events: Counter = Counter()
    country_cats: dict[str, set] = defaultdict(set)

    for ioc in ip_iocs:
        cc = (ioc.get("country") or "").upper().strip()
        if not cc or len(cc) != 2:
            continue
        country_events[cc] += 1

        # Collect category labels
        cats = ioc.get("abuse_categories") or []
        if not cats:
            cat_ids = ioc.get("categories_raw", [])
            from pull_iocs import ABUSEIPDB_CATEGORIES
            cats = [ABUSEIPDB_CATEGORIES.get(c, str(c)) for c in cat_ids if c]
        for cat in cats:
            country_cats[cc].add(cat)

    if not country_events:
        return {"updated": _now_iso(), "total": 0, "items": []}

    total = sum(country_events.values())
    max_events = country_events.most_common(1)[0][1]

    items = []
    for rank, (cc, events) in enumerate(country_events.most_common(50)):
        color = ORIGIN_COLORS[rank] if rank < len(ORIGIN_COLORS) else ORIGIN_COLORS[-1]
        items.append({
            "country":    country_display(cc) or cc,
            "events":     events,
            "pct":        round(events / max_events * 100),
            "color":      color,
            "categories": sorted(country_cats[cc]),
        })

    return {
        "updated": _now_iso(),
        "total":   total,
        "items":   items,
    }


def build_stats_json(
    enriched:    list[dict],
    raw_iocs:    list[dict],
    most_seen:   list[dict],
    sources_hit: set[str],
) -> dict:
    now = datetime.now(timezone.utc)
    week_ago = now - timedelta(days=7)

    crit_cves = sum(
        1 for ioc in enriched
        if ioc.get("type") == "cve"
        and (_safe_float(ioc.get("cvss", 0)) >= 9.0 or ioc.get("severity") == "critical")
    )

    malicious_ips = sum(
        1 for ioc in enriched
        if ioc.get("type") == "ip" and ioc.get("source") == "AbuseIPDB"
    )

    iocs_this_week = 0
    for ioc in enriched:
        if ioc.get("source") not in ("OTX", "ThreatFox"):
            continue
        date_str = ioc.get("date", "")
        try:
            dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
            if dt >= week_ago:
                iocs_this_week += 1
        except Exception:
            pass

    threat_actors = len({
        ioc.get("value") for ioc in enriched
        if ioc.get("type") == "threat_actor" and ioc.get("value")
    })

    return {
        "updated":        now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "criticalCves":   crit_cves,
        "maliciousIps":   malicious_ips,
        "iocsThisWeek":   iocs_this_week,
        "threatActors":   threat_actors,
        "sourcesOnline":  len(sources_hit),
        "lastUpdated":    "just now",
        "mostSeenIocs":   most_seen,
    }


# ---------------------------------------------------------------------------
# Weekly highlights
# ---------------------------------------------------------------------------

def build_weekly_json(enriched: list[dict], most_seen: list[dict]) -> dict:
    now      = datetime.now(timezone.utc)
    iso_week = now.strftime("%Y-W%V")
    week_start = now - timedelta(days=now.weekday())
    week_end   = week_start + timedelta(days=6)
    period = f"{week_start.strftime('%b %-d')} – {week_end.strftime('%b %-d, %Y')}"

    # ── Top CVEs by CVSS ────────────────────────────────────────────────────
    cves = [ioc for ioc in enriched if ioc.get("type") == "cve" and ioc.get("value")]
    top_cves_raw = sorted(cves, key=lambda x: -_safe_float(x.get("cvss", 0)))[:10]
    top_cves = []
    for ioc in top_cves_raw:
        cvss = _safe_float(ioc.get("cvss", 0))
        sev  = (ioc.get("cvss_severity") or ioc.get("severity") or "").lower()
        if not sev or sev not in ("critical","high","medium","low"):
            sev = _cvss_to_severity(cvss)
        top_cves.append({
            "id":       ioc.get("cve") or ioc.get("value", ""),
            "title":    ioc.get("description") or ioc.get("tags") or "",
            "vendor":   ioc.get("vendor", ""),
            "product":  ioc.get("product", ""),
            "cvss":     round(cvss, 1),
            "severity": sev,
            "kev":      ioc.get("source") == "CISA KEV",
        })

    # ── Top IPs by confidence ───────────────────────────────────────────────
    abuse_ips = [
        ioc for ioc in enriched
        if ioc.get("type") == "ip" and ioc.get("source") == "AbuseIPDB"
    ]
    top_ips_raw = sorted(abuse_ips, key=lambda x: -_safe_float(x.get("confidence", 0)))[:10]
    top_ips = []
    for ioc in top_ips_raw:
        cc   = ioc.get("country", "")
        cats = ioc.get("abuse_categories") or []
        if not cats:
            from pull_iocs import ABUSEIPDB_CATEGORIES
            cats = [ABUSEIPDB_CATEGORIES.get(c, str(c)) for c in (ioc.get("categories_raw") or []) if c]
        top_ips.append({
            "ip":         ioc["value"],
            "confidence": int(_safe_float(ioc.get("confidence", 0))),
            "country":    ioc.get("country_full") or country_display(cc) or cc,
            "org":        ioc.get("org") or ioc.get("isp", ""),
            "categories": cats,
        })

    # ── Top malware families (by IOC count) ─────────────────────────────────
    malware_count:   Counter          = Counter()
    malware_sources: dict[str, set]   = defaultdict(set)
    malware_types:   dict[str, set]   = defaultdict(set)
    for ioc in enriched:
        if ioc.get("source") not in ("OTX", "ThreatFox"):
            continue
        name = (ioc.get("malware") or "").strip()
        if not name or name.lower() in ("none", "unknown", ""):
            continue
        malware_count[name] += 1
        malware_sources[name].add(ioc.get("source", ""))
        dt = _ioc_display_type(ioc)
        if dt:
            malware_types[name].add(dt)

    top_malware = [
        {
            "name":    name,
            "iocs":    count,
            "sources": sorted(malware_sources[name]),
            "types":   sorted(malware_types[name]),
        }
        for name, count in malware_count.most_common(10)
    ]

    # ── Top actors with the most MISP data ──────────────────────────────────
    actor_iocs = [ioc for ioc in enriched if ioc.get("type") == "threat_actor"]
    top_actors = []
    for ioc in actor_iocs[:10]:
        name = ioc.get("apt") or ioc.get("value", "")
        cc   = ioc.get("country", "")
        top_actors.append({
            "name":    name,
            "origin":  ioc.get("country_full") or country_display(cc) or cc or "Unknown",
            "status":  _actor_status(ioc.get("description", "")),
            "tactics": _derive_tactics(ioc),
        })

    # ── Top origin countries ─────────────────────────────────────────────────
    origins = build_origins_json(enriched)
    top_origins = [
        {"country": o["country"], "events": o["events"], "pct": o["pct"]}
        for o in origins["items"][:10]
    ]

    # ── Summary counts ───────────────────────────────────────────────────────
    critical_cves  = sum(1 for ioc in enriched if ioc.get("type") == "cve" and _safe_float(ioc.get("cvss", 0)) >= 9.0)
    kev_count      = sum(1 for ioc in enriched if ioc.get("source") == "CISA KEV")
    malicious_ips  = len(abuse_ips)
    unique_malware = len(malware_count)
    unique_actors  = len({ioc.get("value") for ioc in actor_iocs if ioc.get("value")})

    # IOC type breakdown (OTX + ThreatFox only)
    ioc_types: Counter = Counter()
    for ioc in enriched:
        if ioc.get("source") in ("OTX", "ThreatFox"):
            dt = _ioc_display_type(ioc)
            if dt:
                ioc_types[dt] += 1

    return {
        "updated":   _now_iso(),
        "week":      iso_week,
        "period":    period,
        "summary": {
            "criticalCves":      critical_cves,
            "kevCves":           kev_count,
            "maliciousIps":      malicious_ips,
            "uniqueMalware":     unique_malware,
            "uniqueActors":      unique_actors,
            "iocsByType":        dict(ioc_types.most_common()),
        },
        "topCves":       top_cves,
        "topIps":        top_ips,
        "topMalware":    top_malware,
        "topActors":     top_actors,
        "topOrigins":    top_origins,
        "mostSeenIocs":  most_seen[:10],
    }


# ---------------------------------------------------------------------------
# Newsletter — top 3 per category, no API calls, uses existing enriched data
# ---------------------------------------------------------------------------

def _newsletter_entry(ioc: dict, sources: set, ioc_type: str) -> dict:
    cc = ioc.get("country", "")
    return {
        "value":      ioc["value"],
        "type":       ioc_type,
        "malware":    (ioc.get("malware") or ioc.get("description") or "").strip(),
        "actor":      (ioc.get("actor") or "Unknown").strip() or "Unknown",
        "confidence": int(min(max(_safe_float(ioc.get("confidence", 0)), 0), 100)),
        "country":    ioc.get("country_full") or country_display(cc) or cc,
        "source":     ioc.get("source", ""),
        "sources":    sorted(sources),
        "seenIn":     len(sources),
        "firstSeen":  (ioc.get("date") or "")[:10],
    }


def build_newsletter_json(enriched: list[dict], raw_iocs: list[dict]) -> dict:
    """
    Top 3 most-seen IOCs per category (CVE, IP, Domain, Hash/URL) — no extra API calls.
    Sorted within each bucket by cross-source count then confidence.
    The combined 12-item list is ordered: most critical first (CVEs by CVSS,
    others by cross-source count then confidence).
    """
    now        = datetime.now(timezone.utc)
    iso_week   = now.strftime("%Y-W%V")
    week_start = now - timedelta(days=now.weekday())
    week_end   = week_start + timedelta(days=6)
    period     = f"{week_start.strftime('%b %-d')} – {week_end.strftime('%b %-d, %Y')}"

    # Cross-source seen-count index from raw (pre-dedup) list — no API calls
    source_map: dict[tuple, set] = defaultdict(set)
    for ioc in raw_iocs:
        key = (ioc.get("type", ""), ioc.get("value", ""))
        if key[0] and key[1]:
            source_map[key].add(ioc.get("source", ""))

    def _sources(ioc):
        key = (ioc.get("type", ""), ioc.get("value", ""))
        return source_map.get(key, {ioc.get("source", "")})

    def _sort_key(ioc):
        return (-len(_sources(ioc)), -_safe_float(ioc.get("confidence", 0)))

    # ── CVEs: top 3 by CVSS (most critical first) ───────────────────────────
    cve_pool = [i for i in enriched if i.get("type") == "cve" and i.get("value")]
    cve_pool.sort(key=lambda x: -_safe_float(x.get("cvss", 0)))
    top_cves = []
    for ioc in cve_pool[:3]:
        cvss = _safe_float(ioc.get("cvss", 0))
        top_cves.append({
            "value":     ioc.get("cve") or ioc.get("value", ""),
            "type":      "CVE",
            "title":     ioc.get("description") or ioc.get("tags") or "",
            "vendor":    ioc.get("vendor", ""),
            "product":   ioc.get("product", ""),
            "cvss":      round(cvss, 1),
            "severity":  _cvss_to_severity(cvss),
            "kev":       ioc.get("source") == "CISA KEV",
            "published": (ioc.get("published") or ioc.get("date", ""))[:10],
            "source":    ioc.get("source", ""),
            "sources":   sorted(_sources(ioc)),
            "seenIn":    len(_sources(ioc)),
        })

    # ── IPs: top 3 by cross-source count then confidence ────────────────────
    ip_pool = [i for i in enriched if i.get("type") == "ip"
               and i.get("source") == "AbuseIPDB"]
    ip_pool.sort(key=_sort_key)
    top_ips = []
    for ioc in ip_pool[:3]:
        cc   = ioc.get("country", "")
        cats = ioc.get("abuse_categories") or []
        if not cats:
            from pull_iocs import ABUSEIPDB_CATEGORIES
            cats = [ABUSEIPDB_CATEGORIES.get(c, str(c))
                    for c in (ioc.get("categories_raw") or []) if c]
        top_ips.append({
            "value":      ioc["value"],
            "type":       "IP",
            "confidence": int(_safe_float(ioc.get("confidence", 0))),
            "country":    ioc.get("country_full") or country_display(cc) or cc,
            "org":        ioc.get("org") or ioc.get("isp", ""),
            "categories": cats,
            "source":     ioc.get("source", ""),
            "sources":    sorted(_sources(ioc)),
            "seenIn":     len(_sources(ioc)),
            "lastSeen":   (ioc.get("last_seen") or ioc.get("date", ""))[:10],
        })

    # ── Domains: top 3 from OTX + ThreatFox ────────────────────────────────
    domain_pool = [i for i in enriched
                   if i.get("type") == "domain"
                   and i.get("source") in ("OTX", "ThreatFox")]
    domain_pool.sort(key=_sort_key)
    top_domains = [_newsletter_entry(i, _sources(i), "Domain") for i in domain_pool[:3]]

    # ── Hashes & URLs: top 3 combined ───────────────────────────────────────
    hash_url_pool = [i for i in enriched
                     if i.get("type") in ("hash", "url", "ip_port")
                     and i.get("source") in ("OTX", "ThreatFox")]
    hash_url_pool.sort(key=_sort_key)
    top_other = []
    for ioc in hash_url_pool[:3]:
        dt = _ioc_display_type(ioc) or ioc.get("type", "")
        top_other.append(_newsletter_entry(ioc, _sources(ioc), dt))

    # ── Combined 12: CVEs first (most critical), then others by seenIn/conf ─
    all_items = (
        [{"category": "CVE",    **e} for e in top_cves]
      + [{"category": "IP",     **e} for e in top_ips]
      + [{"category": "Domain", **e} for e in top_domains]
      + [{"category": "Other",  **e} for e in top_other]
    )

    # Collect summary metadata
    malware_families = sorted({
        e.get("malware", "") for e in (top_domains + top_other)
        if e.get("malware") and e["malware"].lower() not in ("", "none", "unknown")
    })
    named_actors = sorted({
        e.get("actor", "") for e in (top_domains + top_other)
        if e.get("actor") and e["actor"].lower() not in ("unknown", "")
    })

    return {
        "updated":  _now_iso(),
        "week":     iso_week,
        "period":   period,
        "count":    len(all_items),
        "summary": {
            "topCveCount":     len(top_cves),
            "topIpCount":      len(top_ips),
            "topDomainCount":  len(top_domains),
            "topOtherCount":   len(top_other),
            "malwareFamilies": malware_families,
            "namedActors":     named_actors,
        },
        "topCves":    top_cves,
        "topIps":     top_ips,
        "topDomains": top_domains,
        "topOther":   top_other,
        "items":      all_items,
    }


# ---------------------------------------------------------------------------
# SIEM ingest-ready feed
# ---------------------------------------------------------------------------

# Maps internal type → STIX 2.1 / SIEM-standard indicator type
SIEM_TYPE_MAP = {
    "ip":           "ipv4-addr",
    "ip_port":      "ipv4-addr:port",
    "domain":       "domain-name",
    "url":          "url",
    "hash":         "file-hash",
    "cve":          "vulnerability",
    "threat_actor": "threat-actor",
}

SIEM_SEVERITY_SCORE = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def build_siem_json(enriched: list[dict]) -> dict:
    """
    SIEM-ingest-ready JSON.  Each event uses standardised field names
    compatible with Splunk CIM, Elastic ECS, and QRadar.
    Also written as parallel .ndjson (one event per line) for log-shipper
    direct ingest — the pipeline writes that file alongside this one.
    """
    now = datetime.now(timezone.utc)
    events = []

    for ioc in enriched:
        ioc_type = ioc.get("type", "")
        if not ioc_type:
            continue

        siem_type   = SIEM_TYPE_MAP.get(ioc_type, ioc_type)
        severity    = (ioc.get("severity") or "low").lower()
        sev_score   = SIEM_SEVERITY_SCORE.get(severity, 1)
        conf        = int(min(max(_safe_float(ioc.get("confidence", 0)), 0), 100))
        cvss        = _safe_float(ioc.get("cvss", 0))

        # Tags: merge category, malware, actor, tags field
        tags = []
        if ioc.get("category") and ioc["category"] != "other":
            tags.append(ioc["category"])
        if ioc.get("malware"):
            tags.append(ioc["malware"])
        if ioc.get("actor") and ioc["actor"].lower() not in ("unknown", ""):
            tags.append(ioc["actor"])
        raw_tags = ioc.get("tags", "")
        if raw_tags:
            tags += [t.strip() for t in raw_tags.split(",") if t.strip()]
        tags = sorted(set(t for t in tags if t))

        event = {
            # Identity
            "indicator":        ioc["value"],
            "indicator_type":   siem_type,
            "source":           ioc.get("source", ""),
            # Classification
            "severity":         severity,
            "severity_score":   sev_score,
            "confidence":       conf,
            "category":         ioc.get("category", "other"),
            # Threat context
            "malware_family":   ioc.get("malware", ""),
            "threat_actor":     ioc.get("actor", "") or ioc.get("apt", ""),
            "tags":             tags,
            "description":      ioc.get("description", ""),
            # Temporal
            "first_seen":       ioc.get("date", ""),
            "last_seen":        ioc.get("last_seen", "") or ioc.get("date", ""),
            "ingested_at":      now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            # Geo / network (IPs)
            "src_ip":           ioc["value"] if ioc_type in ("ip", "ip_port") else "",
            "country_code":     ioc.get("country", ""),
            "country":          ioc.get("country_full", ""),
            "asn":              ioc.get("asn", ""),
            "org":              ioc.get("org", ""),
            # CVE fields
            "cve_id":           ioc.get("cve", ""),
            "cvss_score":       round(cvss, 1) if cvss else None,
            "cvss_severity":    ioc.get("cvss_severity", ""),
            "vendor":           ioc.get("vendor", ""),
            "product":          ioc.get("product", ""),
            "kev":              ioc.get("source") == "CISA KEV",
            # Hash
            "hash_type":        ioc.get("hash_type", ""),
            # Feed metadata
            "feed":             "komoto-threat-intel",
            "tlp":              "WHITE",
        }
        # Strip empty strings to keep events lean
        event = {k: v for k, v in event.items() if v not in ("", None, [])}
        events.append(event)

    # Sort: critical first, then by confidence desc
    events.sort(key=lambda e: (
        -SIEM_SEVERITY_SCORE.get(e.get("severity", "low"), 1),
        -e.get("confidence", 0),
    ))

    return {
        "generated":    now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "feed":         "komoto-threat-intel",
        "tlp":          "WHITE",
        "format":       "json",
        "event_count":  len(events),
        "schema":       "komoto/siem/v1",
        "events":       events,
    }


# ---------------------------------------------------------------------------
# Main builder
# ---------------------------------------------------------------------------

def build_all_site_feeds(
    enriched:    list[dict],
    raw_iocs:    list[dict],
    sources_hit: set[str] | None = None,
    output_dir:  Path | None = None,
) -> dict[str, dict]:
    """
    Build all 6 site JSON feeds and write them to output_dir.
    Returns dict of filename → data.
    """
    out = output_dir or OUTPUT_DIR
    out.mkdir(parents=True, exist_ok=True)

    if sources_hit is None:
        sources_hit = {ioc.get("source", "") for ioc in enriched if ioc.get("source")}

    logger.info("[SiteFeeds] Computing most-seen IOCs (pre-dedup)...")
    most_seen = compute_most_seen(raw_iocs)

    logger.info("[SiteFeeds] Building cves.json...")
    cves_data = build_cves_json(enriched)

    logger.info("[SiteFeeds] Building ips.json...")
    ips_data = build_ips_json(enriched)

    logger.info("[SiteFeeds] Building iocs.json...")
    iocs_data = build_iocs_json(enriched)

    logger.info("[SiteFeeds] Building actors.json...")
    actors_data = build_actors_json(enriched)

    logger.info("[SiteFeeds] Building origins.json...")
    origins_data = build_origins_json(enriched)

    logger.info("[SiteFeeds] Building stats.json...")
    stats_data = build_stats_json(enriched, raw_iocs, most_seen, sources_hit)

    logger.info("[SiteFeeds] Building weekly.json...")
    weekly_data = build_weekly_json(enriched, most_seen)

    logger.info("[SiteFeeds] Building newsletter.json...")
    newsletter_data = build_newsletter_json(enriched, raw_iocs)

    logger.info("[SiteFeeds] Building siem_feed.json...")
    siem_data = build_siem_json(enriched)

    feeds = {
        "cves.json":       cves_data,
        "ips.json":        ips_data,
        "iocs.json":       iocs_data,
        "actors.json":     actors_data,
        "origins.json":    origins_data,
        "stats.json":      stats_data,
        "weekly.json":     weekly_data,
        "newsletter.json": newsletter_data,
        "siem_feed.json":  siem_data,
    }

    for filename, data in feeds.items():
        path = out / filename
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        count = (data.get("count") or data.get("event_count")
                 or data.get("total") or len(data.get("items", [])))
        logger.info(f"[SiteFeeds] Wrote {path}  ({count} items)")

    # NDJSON for log-shipper / SIEM direct ingest (one event per line)
    ndjson_path = out / "siem_feed.ndjson"
    ndjson_path.write_text(
        "\n".join(json.dumps(e, ensure_ascii=False) for e in siem_data["events"]),
        encoding="utf-8",
    )
    logger.info(f"[SiteFeeds] Wrote {ndjson_path}  ({siem_data['event_count']} events)")

    logger.info(
        f"[SiteFeeds] Done — "
        f"{cves_data['count']} CVEs, "
        f"{ips_data['count']} IPs, "
        f"{iocs_data['count']} IOCs, "
        f"{len(actors_data['items'])} actors, "
        f"week={weekly_data['week']}"
    )
    return feeds


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    # Quick smoke-test with dummy data
    dummy = [
        {
            "type": "cve", "value": "CVE-2025-0282", "cve": "CVE-2025-0282",
            "source": "CISA KEV", "description": "Stack-based Buffer Overflow in Ivanti",
            "vendor": "Ivanti", "product": "Connect Secure", "cvss": 9.8,
            "cvss_severity": "critical", "published": "2025-01-08",
            "date": "2025-01-08", "severity": "critical", "confidence": "",
            "tags": "", "country": "", "country_full": "", "actor": "",
            "malware": "", "categories_raw": [], "abuse_categories": [],
            "last_seen": "", "usage_type": "", "isp": "", "org": "",
            "aliases": "", "targets": "", "synonyms": "", "refs": "",
            "attribution_confidence": "", "state_sponsor": "", "victims": "",
            "city": "", "asn": "", "resolved_ip": "", "c2_ip": "",
            "hash_type": "", "apt": "",
        },
    ]
    result = build_all_site_feeds(dummy, dummy, {"CISA KEV"})
    print(json.dumps(result["stats.json"], indent=2))
