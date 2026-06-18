"""
attack_map.py
Deterministic MITRE ATT&CK (Enterprise) mapping for enriched IOCs.

No external API calls — pure keyword/category lookups, so it is free to run on
every IOC, every pipeline run. Adds an ``attack`` field of the form:

    [{"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact"}, ...]

The mapping is intentionally conservative: it only attaches techniques that are
strongly implied by the IOC's threat category or explicit keywords, to keep
false-positive technique tags low. A later (credit-consuming) Claude pass can
refine/extend these; this module is the always-on baseline.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Technique catalog — id → (name, tactic)
# ---------------------------------------------------------------------------
TECHNIQUE_CATALOG: dict[str, tuple[str, str]] = {
    "T1566":     ("Phishing",                              "Initial Access"),
    "T1566.001": ("Spearphishing Attachment",             "Initial Access"),
    "T1566.002": ("Spearphishing Link",                   "Initial Access"),
    "T1190":     ("Exploit Public-Facing Application",     "Initial Access"),
    "T1203":     ("Exploitation for Client Execution",    "Execution"),
    "T1204":     ("User Execution",                        "Execution"),
    "T1059":     ("Command and Scripting Interpreter",     "Execution"),
    "T1068":     ("Exploitation for Privilege Escalation", "Privilege Escalation"),
    "T1105":     ("Ingress Tool Transfer",                 "Command and Control"),
    "T1071":     ("Application Layer Protocol",            "Command and Control"),
    "T1095":     ("Non-Application Layer Protocol",        "Command and Control"),
    "T1219":     ("Remote Access Software",                "Command and Control"),
    "T1486":     ("Data Encrypted for Impact",             "Impact"),
    "T1490":     ("Inhibit System Recovery",               "Impact"),
    "T1496":     ("Resource Hijacking",                    "Impact"),
    "T1498":     ("Network Denial of Service",             "Impact"),
    "T1499":     ("Endpoint Denial of Service",            "Impact"),
    "T1056":     ("Input Capture",                         "Collection"),
    "T1056.001": ("Keylogging",                            "Collection"),
    "T1005":     ("Data from Local System",                "Collection"),
    "T1041":     ("Exfiltration Over C2 Channel",          "Exfiltration"),
}

# ---------------------------------------------------------------------------
# Category → techniques (categories produced by enrich._categorize)
# ---------------------------------------------------------------------------
CATEGORY_TECHNIQUES: dict[str, list[str]] = {
    "phishing":      ["T1566"],
    "malware":       ["T1204", "T1059"],
    "ransomware":    ["T1486", "T1490"],
    "ddos":          ["T1498", "T1499"],
    "c2":            ["T1071", "T1095"],
    "cryptojacking": ["T1496"],
    "spyware":       ["T1056", "T1005", "T1041"],
    "exploit":       ["T1190", "T1203"],
    # "other" → no technique (avoids false positives)
}

# ---------------------------------------------------------------------------
# Keyword → techniques (refinements layered on top of the category mapping)
# ---------------------------------------------------------------------------
KEYWORD_TECHNIQUES: dict[str, list[str]] = {
    "cobalt strike": ["T1071", "T1059"],
    "beacon":        ["T1071"],
    "metasploit":    ["T1059", "T1071"],
    "meterpreter":   ["T1059", "T1071"],
    "mirai":         ["T1498"],
    "flood":         ["T1498"],
    "botnet":        ["T1498"],
    "keylog":        ["T1056.001"],
    "infostealer":   ["T1005", "T1056", "T1041"],
    "stealer":       ["T1005", "T1041"],
    "backdoor":      ["T1219", "T1071"],
    "rat ":          ["T1219"],
    "remote access": ["T1219"],
    "loader":        ["T1105", "T1204"],
    "dropper":       ["T1105", "T1204"],
    "xmrig":         ["T1496"],
    "miner":         ["T1496"],
    "coinhive":      ["T1496"],
    "spearphish":    ["T1566.001", "T1566.002"],
    "rce":           ["T1190", "T1203"],
    "lpe":           ["T1068"],
    "privilege escalation": ["T1068"],
}


def map_attack(ioc: dict) -> list[dict]:
    """Return a deduplicated list of ATT&CK technique dicts for an IOC.

    Order: category-derived techniques first, then keyword refinements.
    """
    ids: list[str] = []

    for tid in CATEGORY_TECHNIQUES.get(ioc.get("category", ""), []):
        if tid not in ids:
            ids.append(tid)

    haystack = " ".join([
        str(ioc.get("description", "")),
        str(ioc.get("tags", "")),
        str(ioc.get("malware", "")),
        str(ioc.get("value", "")),
    ]).lower()

    for kw, tids in KEYWORD_TECHNIQUES.items():
        if kw in haystack:
            for tid in tids:
                if tid not in ids:
                    ids.append(tid)

    out = []
    for tid in ids:
        name, tactic = TECHNIQUE_CATALOG.get(tid, ("", ""))
        if name:
            out.append({"id": tid, "name": name, "tactic": tactic})
    return out


def annotate_attack(iocs: list[dict]) -> int:
    """Add an ``attack`` field to each IOC in-place. Returns count tagged."""
    tagged = 0
    for ioc in iocs:
        techniques = map_attack(ioc)
        ioc["attack"] = techniques
        if techniques:
            tagged += 1
    logger.info(f"[ATT&CK] Tagged {tagged}/{len(iocs)} IOCs with techniques")
    return tagged


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    samples = [
        {"type": "ip", "value": "1.2.3.4", "category": "c2", "description": "Cobalt Strike beacon"},
        {"type": "hash", "value": "abc", "category": "ransomware", "description": "LockBit ransom note"},
        {"type": "domain", "value": "evil.test", "category": "phishing", "description": "spearphish credential harvest"},
        {"type": "ip", "value": "9.9.9.9", "category": "other", "description": "scanner"},
    ]
    annotate_attack(samples)
    import json
    print(json.dumps(samples, indent=2))
