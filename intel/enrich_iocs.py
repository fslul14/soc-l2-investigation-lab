#!/usr/bin/env python3
"""
enrich_iocs.py: look up IOCs from investigation/iocs.csv in VirusTotal and AbuseIPDB.

API keys come from environment variables only (never from files in the repo):
  VT_API_KEY         VirusTotal API key   (free tier: 4 requests/minute, 500/day)
  ABUSEIPDB_API_KEY  AbuseIPDB API key    (free tier: 1,000 checks/day)

Only rows with enrich=yes in the IOC file are looked up, to save free-tier quota.
VirusTotal handles ip, domain, url and file hashes; AbuseIPDB handles ip.

Writes:
  intel/enrichment-results.csv  (raw values, for tools)
  intel/enrichment-results.md   (defanged, for people)

Usage, from the repo root with the venv active:
  python intel/enrich_iocs.py --dry-run   # no API calls: checks parsing and output
  python intel/enrich_iocs.py             # real lookups (about 1-2 minutes)
"""
import argparse
import base64
import csv
import os
import sys
import time
from datetime import datetime, timezone

import requests

VT_BASE = "https://www.virustotal.com/api/v3"
ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"

# For each IOC type VirusTotal supports: (API path segment, web UI path segment).
VT_PATHS = {
    "ip": ("ip_addresses", "ip-address"),
    "domain": ("domains", "domain"),
    "url": ("urls", "url"),
    "sha256": ("files", "file"),
    "sha1": ("files", "file"),
    "md5": ("files", "file"),
}

# Output columns, in order.
FIELDS = [
    "type", "value", "context",
    "vt_status", "vt_malicious", "vt_suspicious", "vt_harmless", "vt_undetected", "vt_detail", "vt_link",
    "abuse_status", "abuse_score", "abuse_reports", "abuse_last_reported", "abuse_country", "abuse_isp", "abuse_usage",
]


class RateLimiter:
    """Makes sure calls are at least `min_interval` seconds apart."""

    def __init__(self, min_interval):
        self.min_interval = min_interval
        self.last_call = 0.0

    def wait(self):
        elapsed = time.monotonic() - self.last_call
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        self.last_call = time.monotonic()


def defang(ioc_type, value):
    """Make network indicators non-clickable in human-readable output."""
    if ioc_type not in ("ip", "domain", "url"):
        return value
    return value.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")


def load_iocs(path):
    """Read the IOC CSV and keep only rows marked enrich=yes."""
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    return [r for r in rows if r.get("enrich", "").strip().lower() == "yes"]


def get_with_retry(session, url, limiter, **kwargs):
    """GET through the rate limiter. On HTTP 429 (too many requests), wait 60 s and retry once."""
    for attempt in (1, 2):
        limiter.wait()
        resp = session.get(url, timeout=30, **kwargs)
        if resp.status_code != 429 or attempt == 2:
            return resp
        print("    rate limited (HTTP 429); waiting 60 s, then retrying once", file=sys.stderr)
        time.sleep(60)


def vt_detail(ioc_type, attrs):
    """Pick the one or two most useful descriptive fields for each object type."""
    if ioc_type in ("sha256", "sha1", "md5"):
        label = attrs.get("popular_threat_classification", {}).get("suggested_threat_label", "")
        parts = [attrs.get("type_description", ""), label, attrs.get("meaningful_name", "")]
    elif ioc_type == "ip":
        parts = [attrs.get("country", ""), attrs.get("as_owner", "")]
    elif ioc_type == "domain":
        parts = [f"reputation {attrs.get('reputation', 'n/a')}", attrs.get("registrar", "")]
    else:  # url
        parts = [f"reputation {attrs.get('reputation', 'n/a')}"]
    return "; ".join(str(p) for p in parts if p)


def vt_lookup(session, limiter, ioc_type, value):
    """Look up one indicator in VirusTotal (lookup only; never submits anything for scanning)."""
    api_segment, gui_segment = VT_PATHS[ioc_type]
    if ioc_type == "url":
        # VirusTotal identifies a URL by its URL-safe base64 encoding, without '=' padding.
        object_id = base64.urlsafe_b64encode(value.encode()).decode().strip("=")
    else:
        object_id = value
    result = {}

    resp = get_with_retry(session, f"{VT_BASE}/{api_segment}/{object_id}", limiter)
    if resp.status_code == 404:
        result["vt_status"] = "not found"
        return result
    if resp.status_code != 200:
        result["vt_status"] = f"error HTTP {resp.status_code}"
        return result

    data = resp.json().get("data", {})
    attrs = data.get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    # The web UI link uses VirusTotal's own object id (for URLs that is a SHA-256 of the URL).
    result["vt_link"] = f"https://www.virustotal.com/gui/{gui_segment}/{data.get('id', object_id)}"
    result.update({
        "vt_status": "ok",
        "vt_malicious": stats.get("malicious", 0),
        "vt_suspicious": stats.get("suspicious", 0),
        "vt_harmless": stats.get("harmless", 0),
        "vt_undetected": stats.get("undetected", 0),
        "vt_detail": vt_detail(ioc_type, attrs),
    })
    return result


def abuse_lookup(session, limiter, ip):
    """Look up one IP in AbuseIPDB, counting reports from the last 365 days."""
    resp = get_with_retry(session, ABUSE_URL, limiter, params={"ipAddress": ip, "maxAgeInDays": 365})
    if resp.status_code != 200:
        return {"abuse_status": f"error HTTP {resp.status_code}"}
    data = resp.json().get("data", {})
    return {
        "abuse_status": "ok",
        "abuse_score": data.get("abuseConfidenceScore", ""),
        "abuse_reports": data.get("totalReports", ""),
        "abuse_last_reported": data.get("lastReportedAt") or "",
        "abuse_country": data.get("countryCode") or "",
        "abuse_isp": data.get("isp") or "",
        "abuse_usage": data.get("usageType") or "",
    }


def write_csv(path, results):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        for row in results:
            writer.writerow({k: row.get(k, "") for k in FIELDS})


def md_cell(text):
    """Keep table cells on one line and stop '|' from breaking the Markdown table."""
    return str(text).replace("|", "\\|").replace("\n", " ")


def write_markdown(path, results, dry_run):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# IOC enrichment results",
        "",
        f"Generated {generated} by `intel/enrich_iocs.py`" + (" (dry run: no API calls made)." if dry_run else "."),
        "",
        "Sources: VirusTotal API v3 (lookups only, nothing submitted) and AbuseIPDB API v2 `check`.",
        "",
        "**Read with care:** reputation reflects the run date, not the 2016 incident. Cloud IPs get "
        "reassigned and domains expire, so a clean result today does not clear the indicator, and a "
        "dirty one may describe a later tenant. Indicators are defanged.",
        "",
        "| Type | Indicator | VT malicious / suspicious / harmless / undetected | VT detail | AbuseIPDB score | AbuseIPDB reports (365 d) | Country / ISP | Status |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in results:
        vt = ""
        if r.get("vt_status") == "ok":
            vt = " / ".join(str(r.get(k, "")) for k in ("vt_malicious", "vt_suspicious", "vt_harmless", "vt_undetected"))
        where = " / ".join(x for x in (str(r.get("abuse_country", "")), str(r.get("abuse_isp", ""))) if x)
        status = "; ".join(f"{name}: {r[key]}" for name, key in (("VT", "vt_status"), ("AbuseIPDB", "abuse_status")) if r.get(key))
        cells = [r["type"], defang(r["type"], r["value"]), vt, r.get("vt_detail", ""),
                 r.get("abuse_score", ""), r.get("abuse_reports", ""), where, status]
        lines.append("| " + " | ".join(md_cell(c) for c in cells) + " |")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def main():
    parser = argparse.ArgumentParser(description="Enrich IOCs with VirusTotal and AbuseIPDB.")
    parser.add_argument("--iocs", default="investigation/iocs.csv", help="IOC CSV with type,value,...,enrich columns")
    parser.add_argument("--out-csv", default="intel/enrichment-results.csv")
    parser.add_argument("--out-md", default="intel/enrichment-results.md")
    parser.add_argument("--dry-run", action="store_true", help="parse and write outputs without calling any API")
    args = parser.parse_args()

    vt_key = os.environ.get("VT_API_KEY", "").strip()
    abuse_key = os.environ.get("ABUSEIPDB_API_KEY", "").strip()

    # One session per service, each carrying only its own key.
    vt_session = requests.Session()
    vt_session.headers.update({"x-apikey": vt_key, "Accept": "application/json"})
    abuse_session = requests.Session()
    abuse_session.headers.update({"Key": abuse_key, "Accept": "application/json"})

    vt_limiter = RateLimiter(16)     # 4 requests/minute = one per 15 s, plus a 1 s margin
    abuse_limiter = RateLimiter(2)   # well inside 1,000/day; just being polite

    iocs = load_iocs(args.iocs)
    print(f"{len(iocs)} indicators marked enrich=yes in {args.iocs}")
    results = []
    for i, ioc in enumerate(iocs, 1):
        ioc_type = ioc["type"].strip().lower()
        value = ioc["value"].strip()
        print(f"[{i}/{len(iocs)}] {ioc_type}: {defang(ioc_type, value)}")
        row = {"type": ioc_type, "value": value, "context": ioc.get("context", "")}

        if ioc_type in VT_PATHS:
            if args.dry_run:
                row["vt_status"] = "skipped (dry run)"
            elif not vt_key:
                row["vt_status"] = "skipped (VT_API_KEY not set)"
            else:
                try:
                    row.update(vt_lookup(vt_session, vt_limiter, ioc_type, value))
                except requests.RequestException as exc:
                    row["vt_status"] = f"error: {type(exc).__name__}"

        if ioc_type == "ip":
            if args.dry_run:
                row["abuse_status"] = "skipped (dry run)"
            elif not abuse_key:
                row["abuse_status"] = "skipped (ABUSEIPDB_API_KEY not set)"
            else:
                try:
                    row.update(abuse_lookup(abuse_session, abuse_limiter, value))
                except requests.RequestException as exc:
                    row["abuse_status"] = f"error: {type(exc).__name__}"

        results.append(row)

    write_csv(args.out_csv, results)
    write_markdown(args.out_md, results, args.dry_run)
    print(f"Wrote {args.out_csv} and {args.out_md}")


if __name__ == "__main__":
    main()
