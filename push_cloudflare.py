"""
push_cloudflare.py
Uploads the site JSON feeds to Cloudflare Pages via the Direct Upload API.

Required env vars:
  CF_ACCOUNT_ID   — your Cloudflare account ID
  CF_API_TOKEN    — API token with Pages:Edit permission
  CF_PROJECT_NAME — your Pages project name (e.g. "my-site")

Optional:
  CF_BRANCH       — branch to deploy to (default: "main")
"""

import hashlib
import json
import logging
import os
from pathlib import Path

import requests
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

CF_ACCOUNT_ID   = os.getenv("CF_ACCOUNT_ID", "")
CF_API_TOKEN    = os.getenv("CF_API_TOKEN", "")
CF_PROJECT_NAME = os.getenv("CF_PROJECT_NAME", "")
CF_BRANCH       = os.getenv("CF_BRANCH", "main")

CF_BASE = "https://api.cloudflare.com/client/v4"


def _cf_headers() -> dict:
    return {"Authorization": f"Bearer {CF_API_TOKEN}"}


def _file_hash(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def push_files_to_pages(files: dict[str, bytes]) -> dict:
    """
    Upload a dict of { "/threats/cves.json": bytes, ... } to Cloudflare Pages.

    Uses the Pages Direct Upload API (single multipart deployment).
    Returns the parsed JSON response from Cloudflare.
    """
    if not all([CF_ACCOUNT_ID, CF_API_TOKEN, CF_PROJECT_NAME]):
        logger.error("[CF] Missing CF_ACCOUNT_ID, CF_API_TOKEN, or CF_PROJECT_NAME. Skipping upload.")
        return {"success": False, "errors": ["Missing Cloudflare credentials"]}

    # Build manifest { "/path": "sha256hash" }
    manifest: dict[str, str] = {}
    hash_map: dict[str, tuple[str, bytes]] = {}   # hash → (path, content)

    for path, content in files.items():
        h = _file_hash(content)
        manifest[path] = h
        hash_map[h] = (path, content)

    # Multipart form: manifest + one field per file (named by its hash)
    form_parts = [
        ("manifest", (None, json.dumps(manifest), "application/json")),
    ]
    for h, (rel_path, content) in hash_map.items():
        # Strip leading slash for the filename part of the form field
        form_parts.append(
            (h, (rel_path.lstrip("/"), content, "application/octet-stream"))
        )

    url = f"{CF_BASE}/accounts/{CF_ACCOUNT_ID}/pages/projects/{CF_PROJECT_NAME}/deployments"
    params = {"branch": CF_BRANCH}

    logger.info(f"[CF] Uploading {len(files)} files to Pages project '{CF_PROJECT_NAME}' ({CF_BRANCH})...")

    try:
        resp = requests.post(
            url,
            headers=_cf_headers(),
            files=form_parts,
            params=params,
            timeout=60,
        )
        result = resp.json()
    except Exception as e:
        logger.error(f"[CF] Upload failed: {e}")
        return {"success": False, "errors": [str(e)]}

    if result.get("success"):
        deployment = result.get("result", {})
        deploy_url = deployment.get("url", "")
        logger.info(f"[CF] Deployment created: {deploy_url}")
    else:
        errors = result.get("errors", [])
        logger.error(f"[CF] Upload failed: {errors}")

    return result


def push_directory(output_dir: Path, prefix: str = "/threats") -> dict:
    """
    Read all .json files from output_dir and upload them with the given path prefix.
    E.g. output/threats/cves.json → /threats/cves.json
    """
    files: dict[str, bytes] = {}

    for json_file in sorted(output_dir.glob("*.json")):
        remote_path = f"{prefix}/{json_file.name}"
        files[remote_path] = json_file.read_bytes()
        logger.debug(f"[CF] Queued: {remote_path}  ({len(files[remote_path])} bytes)")

    if not files:
        logger.warning(f"[CF] No JSON files found in {output_dir}")
        return {"success": False, "errors": ["No files to upload"]}

    return push_files_to_pages(files)


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    output_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("output/threats")
    if not output_path.exists():
        print(f"Output directory not found: {output_path}")
        sys.exit(1)

    result = push_directory(output_path)
    print(json.dumps(result, indent=2))
