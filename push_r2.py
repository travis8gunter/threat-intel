"""
push_r2.py
Uploads site feeds + master threat feed to a private Cloudflare R2 bucket.

Bucket layout:
  current.json                              ← points to latest date {"date": "YYYY-MM-DD"}
  manifest.json                             ← global download index (all days)
  YYYY-MM-DD/
    threats/                                ← site feed files (pulled by paywall page)
      cves.json
      ips.json
      iocs.json
      actors.json
      origins.json
      stats.json
      weekly.json
      newsletter.json
      siem_feed.json
      siem_feed.ndjson
    downloads/                              ← downloadable master feed for that day
      master_threat_feed_YYYY-MM-DD.json

Required env vars:
  R2_ACCOUNT_ID        — Cloudflare account ID
  R2_ACCESS_KEY_ID     — R2 API token access key ID
  R2_SECRET_ACCESS_KEY — R2 API token secret
  R2_BUCKET_NAME       — name of your R2 bucket (e.g. "threat-intel-data")
"""

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

R2_ACCOUNT_ID        = os.getenv("R2_ACCOUNT_ID", "")
R2_ACCESS_KEY_ID     = os.getenv("R2_ACCESS_KEY_ID", "")
R2_SECRET_ACCESS_KEY = os.getenv("R2_SECRET_ACCESS_KEY", "")
R2_BUCKET_NAME       = os.getenv("R2_BUCKET_NAME", "")


def _r2_client():
    if not all([R2_ACCOUNT_ID, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY]):
        raise ValueError("R2_ACCOUNT_ID, R2_ACCESS_KEY_ID, and R2_SECRET_ACCESS_KEY must be set.")
    return boto3.client(
        "s3",
        endpoint_url=f"https://{R2_ACCOUNT_ID}.r2.cloudflarestorage.com",
        aws_access_key_id=R2_ACCESS_KEY_ID,
        aws_secret_access_key=R2_SECRET_ACCESS_KEY,
        config=Config(signature_version="s3v4"),
        region_name="auto",
    )


def _upload(client, key: str, data: bytes, content_type: str = "application/json"):
    client.put_object(
        Bucket=R2_BUCKET_NAME,
        Key=key,
        Body=data,
        ContentType=content_type,
        CacheControl="no-cache, no-store, must-revalidate",
    )
    logger.info(f"[R2] ✓ {key}  ({len(data):,} bytes)")


def _list_objects(client, prefix: str = "") -> list[dict]:
    """List all objects under a prefix (handles pagination)."""
    results = []
    kwargs = {"Bucket": R2_BUCKET_NAME, "Prefix": prefix}
    try:
        while True:
            resp = client.list_objects_v2(**kwargs)
            results.extend(resp.get("Contents", []))
            if not resp.get("IsTruncated"):
                break
            kwargs["ContinuationToken"] = resp["NextContinuationToken"]
    except ClientError as e:
        logger.warning(f"[R2] Could not list objects: {e}")
    return results


def delete_objects(client, keys: list[str]):
    """Batch-delete a list of R2 keys."""
    if not keys:
        return
    for i in range(0, len(keys), 1000):
        batch = [{"Key": k} for k in keys[i:i + 1000]]
        client.delete_objects(Bucket=R2_BUCKET_NAME, Delete={"Objects": batch})
        logger.info(f"[R2] Deleted {len(batch)} objects")


# ---------------------------------------------------------------------------
# Site feeds upload
# ---------------------------------------------------------------------------

def push_site_feeds(site_feeds_dir: Path, date_str: str) -> bool:
    """Upload site JSON/NDJSON files to {date_str}/threats/ in R2."""
    if not R2_BUCKET_NAME:
        logger.error("[R2] R2_BUCKET_NAME not set. Skipping upload.")
        return False

    try:
        client = _r2_client()
    except ValueError as e:
        logger.error(f"[R2] {e}")
        return False

    files = sorted(site_feeds_dir.glob("*.json")) + sorted(site_feeds_dir.glob("*.ndjson"))
    if not files:
        logger.warning(f"[R2] No JSON/NDJSON files found in {site_feeds_dir}")
        return False

    for f in files:
        ct = "application/x-ndjson" if f.suffix == ".ndjson" else "application/json"
        _upload(client, f"{date_str}/threats/{f.name}", f.read_bytes(), ct)

    # Write root current.json so the website always knows the latest date
    current = json.dumps({"date": date_str, "path": date_str}, ensure_ascii=False).encode()
    _upload(client, "current.json", current)

    logger.info(f"[R2] Site feeds uploaded ({len(files)} files → {date_str}/threats/)")
    return True


# ---------------------------------------------------------------------------
# Master feed upload + manifest
# ---------------------------------------------------------------------------

def push_master_feed(
    master_feed_path: Path,
    master_summary: dict,
    date_str: str,
    keep_days: int = 30,
) -> bool:
    """
    Upload the master threat feed to {date_str}/downloads/master_threat_feed_{date_str}.json
    and update the root manifest.json.
    """
    if not R2_BUCKET_NAME:
        logger.error("[R2] R2_BUCKET_NAME not set. Skipping upload.")
        return False

    try:
        client = _r2_client()
    except ValueError as e:
        logger.error(f"[R2] {e}")
        return False

    feed_bytes = master_feed_path.read_bytes()
    dated_key  = f"{date_str}/downloads/master_threat_feed_{date_str}.json"

    _upload(client, dated_key, feed_bytes)

    # Fetch existing root manifest
    old_manifest_entries: list[dict] = []
    try:
        resp = client.get_object(Bucket=R2_BUCKET_NAME, Key="manifest.json")
        old_manifest = json.loads(resp["Body"].read())
        old_manifest_entries = old_manifest.get("feeds", [])
    except ClientError:
        pass

    # Build entry for today
    s = master_summary
    size_bytes = len(feed_bytes)
    new_entry = {
        "filename":    f"master_threat_feed_{date_str}.json",
        "key":         dated_key,
        "date":        date_str,
        "label":       datetime.strptime(date_str, "%Y-%m-%d").strftime("%B %-d, %Y"),
        "total_iocs":  s.get("total_iocs", 0),
        "unique_iocs": s.get("unique_iocs", 0),
        "by_type":     s.get("by_type", {}),
        "by_severity": s.get("by_severity", {}),
        "size_bytes":  size_bytes,
        "size_label":  f"{size_bytes / 1_048_576:.1f} MB",
    }

    # Merge: update today's entry if it already exists, otherwise prepend
    entries = [e for e in old_manifest_entries if e.get("date") != date_str]
    entries = [new_entry] + entries

    # Keep only the most recent N days
    entries = entries[:keep_days]

    manifest = {
        "updated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "count":   len(entries),
        "feeds":   entries,
    }
    manifest_bytes = json.dumps(manifest, indent=2, ensure_ascii=False).encode()
    _upload(client, "manifest.json", manifest_bytes)

    logger.info(f"[R2] Master feed + manifest uploaded  ({len(entries)} entries in manifest)")
    return True


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    site_dir    = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path("output/threats").resolve()
    master_path = Path(sys.argv[2]).resolve() if len(sys.argv) > 2 else None
    date        = sys.argv[3] if len(sys.argv) > 3 else datetime.now(timezone.utc).strftime("%Y-%m-%d")

    # Refuse to upload from outside the project directory
    cwd = Path.cwd().resolve()
    if not str(site_dir).startswith(str(cwd)):
        print(f"ERROR: site_dir '{site_dir}' is outside the project directory.")
        sys.exit(1)

    ok = push_site_feeds(site_dir, date)
    if master_path and master_path.exists():
        ok &= push_master_feed(master_path, {}, date)
    sys.exit(0 if ok else 1)
