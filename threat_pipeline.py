"""
threat_pipeline.py
Single entry point for the Komoto threat intel pipeline.

Flow:
  1. Pull raw IOCs from open-source feeds          (pull_iocs.py)
  2. Enrich each IOC                               (enrich.py)
  3. Deduplicate + write master JSON               (build_master_feed.py)
  4. Build site-ready JSON feeds                   (build_site_feeds.py)
  5. Push site feeds + master feed to R2           (push_r2.py)

Outputs:
  feeds/<DATE>/master_threat_feed_<DATE>.json
  output/threats/{cves,ips,iocs,actors,origins,stats}.json
"""

import logging
import sys
from datetime import datetime
from pathlib import Path

import pytz

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
DATE     = datetime.now(pytz.timezone("America/Denver")).strftime("%Y-%m-%d")
LOG_FILE = Path("threat.log")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, mode="a", encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Pipeline module imports
# ---------------------------------------------------------------------------
try:
    from pull_iocs         import pull_all
    from enrich            import enrich_all
    from build_master_feed import build_master_feed
    from build_site_feeds  import build_all_site_feeds, compute_most_seen
    from push_r2           import push_site_feeds, push_master_feed
except ImportError as e:
    logger.error(f"Failed to import pipeline module: {e}")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Paths  — master feed includes the date so each day's file is distinct
# ---------------------------------------------------------------------------
MASTER_OUTPUT = Path(f"feeds/{DATE}/master_threat_feed_{DATE}.json")
SITE_OUTPUT   = Path("output/threats")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _cap_iocs(iocs: list[dict], limit: int) -> list[dict]:
    """Keep the first `limit` IOCs per source for quick test runs."""
    from collections import defaultdict
    buckets: dict[str, list] = defaultdict(list)
    for ioc in iocs:
        src = ioc.get("source", "")
        if len(buckets[src]) < limit:
            buckets[src].append(ioc)
    result = [ioc for bucket in buckets.values() for ioc in bucket]
    logger.info(f"[Quick] Capped to {len(result)} IOCs ({limit}/source)")
    return result


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

def run_pipeline(skip_r2: bool = False, quick: bool = False):
    logger.info("=" * 64)
    logger.info(f"  Komoto Threat Intel Pipeline — {DATE}")
    logger.info("=" * 64)

    # ── Step 1: Pull ─────────────────────────────────────────────────────────
    logger.info("\n[Step 1] Pulling IOCs from open-source feeds...")
    try:
        raw_iocs = pull_all()
    except Exception as e:
        logger.error(f"Pull step failed: {e}")
        sys.exit(1)

    if not raw_iocs:
        logger.error("No IOCs pulled. Check API keys and network connectivity.")
        sys.exit(1)

    logger.info(f"  → {len(raw_iocs)} raw IOCs pulled")

    if quick:
        raw_iocs = _cap_iocs(raw_iocs, limit=100)

    sources_hit = {ioc.get("source", "") for ioc in raw_iocs if ioc.get("source")}
    logger.info(f"  → Sources online: {sorted(sources_hit)}")

    # Most-seen IOCs BEFORE deduplication
    logger.info("\n[Pre-dedup] Computing most-seen IOCs...")
    most_seen = compute_most_seen(raw_iocs, top_n=20)
    if most_seen:
        logger.info("  Top duplicates (pre-dedup):")
        for entry in most_seen[:5]:
            logger.info(
                f"    [{entry['type']}] {entry['value']}  "
                f"×{entry['count']}  sources={entry['sources']}"
            )

    # ── Step 2: Enrich ───────────────────────────────────────────────────────
    logger.info("\n[Step 2] Enriching IOCs...")
    try:
        enriched = enrich_all(raw_iocs)
    except Exception as e:
        logger.error(f"Enrichment step failed: {e}")
        sys.exit(1)

    logger.info(f"  → {len(enriched)} IOCs enriched")

    # ── Step 3: Master feed ──────────────────────────────────────────────────
    logger.info(f"\n[Step 3] Building master feed → {MASTER_OUTPUT}")
    try:
        master = build_master_feed(enriched, str(MASTER_OUTPUT))
    except Exception as e:
        logger.error(f"Master feed step failed: {e}")
        sys.exit(1)

    s = master["summary"]
    logger.info(f"  → {s['unique_iocs']} unique IOCs  (from {s['total_iocs']} raw)")
    logger.info(f"  → By type:     {s['by_type']}")
    logger.info(f"  → By severity: {s['by_severity']}")

    deduped_enriched = master["iocs"]

    # ── Step 4: Site feeds ───────────────────────────────────────────────────
    logger.info(f"\n[Step 4] Building site JSON feeds → {SITE_OUTPUT}/")
    try:
        feeds = build_all_site_feeds(
            enriched    = deduped_enriched,
            raw_iocs    = raw_iocs,
            sources_hit = sources_hit,
            output_dir  = SITE_OUTPUT,
        )
    except Exception as e:
        logger.error(f"Site feeds step failed: {e}")
        sys.exit(1)

    stats = feeds["stats.json"]
    logger.info(
        f"  → criticalCves={stats['criticalCves']}  "
        f"maliciousIps={stats['maliciousIps']}  "
        f"iocsThisWeek={stats['iocsThisWeek']}  "
        f"threatActors={stats['threatActors']}"
    )

    # ── Step 5: Push to R2 ───────────────────────────────────────────────────
    if skip_r2:
        logger.info("\n[Step 5] R2 push skipped (--no-r2 flag).")
    else:
        logger.info("\n[Step 5] Pushing to Cloudflare R2...")

        logger.info("  → Uploading site feeds...")
        push_site_feeds(SITE_OUTPUT, DATE)

        logger.info("  → Uploading master feed + updating manifest...")
        push_master_feed(
            master_feed_path = MASTER_OUTPUT,
            master_summary   = s,
            date_str         = DATE,
            keep_days        = 30,
        )

    # ── Summary ──────────────────────────────────────────────────────────────
    logger.info("\n" + "=" * 64)
    logger.info("  Pipeline complete!")
    logger.info(f"  Master feed : {MASTER_OUTPUT}")
    logger.info(f"  Site feeds  : {SITE_OUTPUT}/")
    logger.info("=" * 64)


if __name__ == "__main__":
    no_r2 = "--no-r2" in sys.argv
    quick = "--quick" in sys.argv
    run_pipeline(skip_r2=no_r2, quick=quick)
