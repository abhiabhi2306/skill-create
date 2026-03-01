#!/usr/bin/env python3
"""
google_scan.py — Scan Google-owned IPs (excluding Google Cloud) for open web
ports and take screenshots of live hosts.

Requirements:
    pip install requests playwright
    playwright install chromium

Usage examples:
    python google_scan.py                          # scan everything (millions of IPs)
    python google_scan.py --limit 5000             # quick sample of 5,000 IPs
    python google_scan.py --limit 50000 --timeout 0.8 --scan-workers 1500
    python google_scan.py --out results --limit 10000 --shot-workers 8
"""

from __future__ import annotations

import argparse
import ipaddress
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed, wait, FIRST_COMPLETED
from pathlib import Path

import requests

# ─── defaults ────────────────────────────────────────────────────────────────

# All known Google / Alphabet ASNs (non-cloud corporate + service infrastructure)
# Google Cloud ranges are excluded separately via cloud.json regardless of ASN.
GOOGLE_ASNS = [
    15169,   # Google LLC — primary (Search, Gmail, Maps, YouTube infra, APIs)
    19527,   # Google LLC — corporate internal network
    36040,   # YouTube LLC
    36385,   # Google IT production systems
    36492,   # Google Fiber backbone
    43515,   # Google Global Cache (ISP peering / CDN edge nodes)
    139070,  # Google LLC — APAC region
    36411,   # Googlebot / crawler egress IPs
    22577,   # Google Inc. (legacy allocation)
    26910,   # Google corporate #2 (GOOG-CORP-2)
    394507,  # Google Fiber broadband customers
    6432,    # Doubleclick Inc. (Google Ads / Display infrastructure)
    32381,   # Google Fiber #2
    41264,   # Google (RIPE / Europe)
    45566,   # Google (APAC / Australia)
    55023,   # Google Asia-Pacific
    16591,   # Google Fiber residential
    396982,  # Google LLC — additional block (cloud.json will filter GCP parts)
]

# BGP prefix APIs (BGPView primary, RIPE Stat fallback)
BGPVIEW_URL  = "https://api.bgpview.io/asn/{asn}/prefixes"
RIPE_STAT_URL = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"

CLOUD_URL    = "https://www.gstatic.com/ipranges/cloud.json"
TARGET_PORTS = [80, 443, 5000, 8080, 8000]

SCAN_WORKERS = 1000   # concurrent TCP-connect threads
SHOT_WORKERS = 5      # concurrent headless-browser instances (RAM-heavy)
SCAN_TIMEOUT = 1.0    # seconds per port connect attempt
MAX_PENDING  = 15_000 # futures held in memory at once (controls RAM usage)
PROGRESS_EVERY = 5_000

# ─── IP range helpers ─────────────────────────────────────────────────────────

def fetch_ipv4_cidrs(url: str) -> set:
    """Fetch IPv4 CIDR blocks from a Google-style JSON range file."""
    r = requests.get(url, timeout=20)
    r.raise_for_status()
    nets = set()
    for prefix in r.json().get("prefixes", []):
        v4 = prefix.get("ipv4Prefix")
        if v4:
            nets.add(ipaddress.ip_network(v4, strict=False))
    return nets


def fetch_asn_prefixes(asn: int, session: requests.Session) -> set:
    """
    Return the set of IPv4 networks announced by `asn`.
    Tries BGPView first; falls back to RIPE Stat on any failure.
    """
    # ── BGPView ──────────────────────────────────────────────────────────────
    try:
        r = session.get(BGPVIEW_URL.format(asn=asn), timeout=20)
        if r.status_code == 200:
            data = r.json()
            if data.get("status") == "ok":
                nets = set()
                for p in data["data"]["ipv4_prefixes"]:
                    cidr = p.get("prefix")
                    if cidr:
                        try:
                            nets.add(ipaddress.ip_network(cidr, strict=False))
                        except ValueError:
                            pass
                return nets
    except Exception:
        pass

    # ── RIPE Stat fallback ───────────────────────────────────────────────────
    try:
        r = session.get(RIPE_STAT_URL.format(asn=asn), timeout=20)
        r.raise_for_status()
        nets = set()
        for p in r.json().get("data", {}).get("prefixes", []):
            cidr = p.get("prefix")
            if cidr and ":" not in cidr:   # IPv4 only
                try:
                    nets.add(ipaddress.ip_network(cidr, strict=False))
                except ValueError:
                    pass
        return nets
    except Exception as e:
        print(f"      [!] AS{asn} both APIs failed: {e}", file=sys.stderr)
        return set()


def google_only_cidrs() -> list:
    """
    Fetch IPv4 prefixes for every Google ASN, then remove anything that
    overlaps with a Google Cloud range (cloud.json).  Uses overlaps() so
    both directions are caught: Google prefix ⊆ cloud block, and cloud
    block ⊆ Google prefix.
    """
    all_google: set = set()

    print(f"[*] Fetching BGP prefixes for {len(GOOGLE_ASNS)} Google ASNs …")
    with requests.Session() as session:
        session.headers.update({"User-Agent": "google-ip-research/1.0"})
        for asn in GOOGLE_ASNS:
            nets = fetch_asn_prefixes(asn, session)
            all_google |= nets
            print(f"    AS{asn:<8} → {len(nets):>4} prefix(es)   "
                  f"(running total: {len(all_google)})")
            time.sleep(0.35)   # be polite to the API

    if not all_google:
        sys.exit("[!] No prefixes fetched from any ASN — check network connectivity and API availability.")

    total_before = sum(n.num_addresses for n in all_google)
    print(f"\n[*] Raw Google prefixes: {len(all_google)} CIDR blocks  "
          f"({total_before:,} addresses)")

    # ── remove Google Cloud ranges ────────────────────────────────────────────
    print("[*] Fetching Google Cloud exclusion list (cloud.json) …",
          end=" ", flush=True)
    cloud = fetch_ipv4_cidrs(CLOUD_URL)
    print(f"{len(cloud)} blocks")

    cloud_list = list(cloud)
    # overlaps() catches both directions:
    #   • Google prefix ⊆ Cloud prefix  (subnet_of)
    #   • Cloud prefix ⊆ Google prefix  (supernet — missed by subnet_of alone)
    only = {
        g for g in all_google
        if not any(g.overlaps(c) for c in cloud_list)
    }
    excluded = len(all_google) - len(only)
    only = sorted(only, key=lambda n: n.network_address)

    total = sum(n.num_addresses for n in only)
    print(f"[*] Excluded {excluded} cloud-overlapping block(s)")
    print(f"[*] Google-only: {len(only)} CIDR blocks  ({total:,} addresses)\n")
    return only


def iter_hosts(cidrs: list, limit: int = 0):
    """Generator: yield individual host IP strings across all CIDR blocks."""
    count = 0
    for net in cidrs:
        # /32 has no hosts() per RFC; yield the address itself
        addrs = [net.network_address] if net.prefixlen == 32 else net.hosts()
        for ip in addrs:
            yield str(ip)
            count += 1
            if limit and count >= limit:
                return


# ─── port scanning ────────────────────────────────────────────────────────────

def check_port(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def scan_ip(ip: str, timeout: float) -> tuple:
    """Return (ip, [open_ports])."""
    open_ports = [p for p in TARGET_PORTS if check_port(ip, p, timeout)]
    return ip, open_ports


def run_scan(cidrs: list, limit: int, workers: int, timeout: float) -> tuple:
    """
    Bounded-memory parallel port scan.
    Never holds more than MAX_PENDING futures in RAM at once.
    """
    hits: list = []
    scanned = 0
    t0 = time.perf_counter()

    gen = iter_hosts(cidrs, limit)
    pending: set = set()
    exhausted = False

    ex = ThreadPoolExecutor(max_workers=workers)
    try:
        while not exhausted or pending:

            # Fill up the in-flight window
            while not exhausted and len(pending) < MAX_PENDING:
                ip = next(gen, None)
                if ip is None:
                    exhausted = True
                    break
                pending.add(ex.submit(scan_ip, ip, timeout))

            if not pending:
                break

            # Wait for at least one to finish (poll every 0.5 s)
            done, pending = wait(pending, timeout=0.5,
                                 return_when=FIRST_COMPLETED)

            for fut in done:
                try:
                    host, open_ports = fut.result()
                except Exception:
                    continue
                scanned += 1
                if open_ports:
                    hits.append((host, open_ports))
                    print(f"  [+] {host:<18}  open: {open_ports}")
                if scanned % PROGRESS_EVERY == 0:
                    elapsed = time.perf_counter() - t0
                    rate    = scanned / elapsed if elapsed else 0
                    print(f"  … {scanned:>10,} scanned | "
                          f"{rate:>8,.0f} IPs/s | "
                          f"{len(hits)} live hosts found",
                          flush=True)

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted — using results collected so far.")
    finally:
        try:
            ex.shutdown(wait=False, cancel_futures=True)  # Python 3.9+
        except TypeError:
            ex.shutdown(wait=False)  # Python 3.8 fallback

    elapsed = time.perf_counter() - t0
    rate    = scanned / elapsed if elapsed else 0
    print(f"\n[*] Scan complete: {scanned:,} IPs in {elapsed:.1f}s "
          f"({rate:,.0f} IPs/s)  —  {len(hits)} hosts with open ports")
    return hits, scanned


# ─── screenshots ──────────────────────────────────────────────────────────────

def build_urls(ip: str, ports: list) -> list:
    urls = []
    for p in ports:
        if p == 443:
            urls.append(f"https://{ip}")
        elif p == 80:
            urls.append(f"http://{ip}")
        else:
            urls.append(f"http://{ip}:{p}")
    return urls


def screenshot_url(url: str, out_dir: Path) -> str | None:
    """Open a headless Chromium, navigate, screenshot, return saved path."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("[!] playwright not installed — run: pip install playwright && playwright install chromium",
              file=sys.stderr)
        return None

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--disable-extensions",
                ],
            )
            ctx = browser.new_context(
                ignore_https_errors=True,
                viewport={"width": 1280, "height": 900},
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
            )
            page = ctx.new_page()
            page.set_default_timeout(15_000)

            try:
                page.goto(url, wait_until="domcontentloaded")
            except Exception:
                # try a lighter wait condition as fallback
                try:
                    page.goto(url, wait_until="commit")
                except Exception:
                    ctx.close()
                    browser.close()
                    return None

            # Safe filename (max 200 chars)
            safe = (
                url.replace("://", "_")
                   .replace("/", "_")
                   .replace(":", "_")
                   .strip("_")
            )[:200]
            fname = out_dir / f"{safe}.png"
            page.screenshot(path=str(fname), full_page=False)
            browser.close()
        return str(fname)

    except Exception as e:
        print(f"  [!] screenshot failed  {url}  — {e}", file=sys.stderr)
        return None


def run_screenshots(hits: list, out_dir: Path, workers: int) -> int:
    tasks = [
        (url, out_dir)
        for ip, ports in hits
        for url in build_urls(ip, ports)
    ]
    print(f"\n[*] Taking {len(tasks)} screenshot(s) with {workers} browser instance(s) …")
    saved = 0
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(screenshot_url, url, out_dir): url
                for url, _ in tasks}
        for fut in as_completed(futs):
            r = fut.result()
            if r:
                saved += 1
                print(f"  [saved] {r}")
    return saved


# ─── entry point ──────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="Scan Google-only IPs for open web ports and screenshot them.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    ap.add_argument(
        "--out", default="screenshots",
        help="Directory to save screenshots and hit list",
    )
    ap.add_argument(
        "--scan-workers", type=int, default=SCAN_WORKERS,
        help="Number of concurrent port-scan threads",
    )
    ap.add_argument(
        "--shot-workers", type=int, default=SHOT_WORKERS,
        help="Number of concurrent headless browser instances",
    )
    ap.add_argument(
        "--timeout", type=float, default=SCAN_TIMEOUT,
        help="TCP connect timeout per port (seconds)",
    )
    ap.add_argument(
        "--limit", type=int, default=0,
        help="Max number of IPs to scan (0 = all — can be millions)",
    )
    ap.add_argument(
        "--no-screenshot", action="store_true",
        help="Skip screenshots; only output hits.txt",
    )
    args = ap.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    # ── fetch ranges ──────────────────────────────────────────────────────────
    try:
        cidrs = google_only_cidrs()
    except Exception as e:
        sys.exit(f"[!] Failed to fetch IP ranges: {e}")

    if args.limit:
        print(f"[*] Scan limit: {args.limit:,} IPs\n")
    else:
        total = sum(n.num_addresses for n in cidrs)
        print(f"[*] No limit set — scanning all {total:,} IPs  "
              f"(use --limit N for a faster run)\n")

    # ── port scan ─────────────────────────────────────────────────────────────
    print(f"[*] Ports: {TARGET_PORTS}   Workers: {args.scan_workers}   "
          f"Timeout: {args.timeout}s\n")

    hits, _ = run_scan(cidrs, args.limit, args.scan_workers, args.timeout)

    # ── persist hits ──────────────────────────────────────────────────────────
    hits_file = out_dir / "hits.txt"
    with hits_file.open("w") as f:
        for ip, ports in hits:
            f.write(f"{ip}\t{','.join(map(str, ports))}\n")
    print(f"[*] Hit list saved → {hits_file}")

    if not hits:
        print("[*] No open ports found. Exiting.")
        return

    # ── screenshots ───────────────────────────────────────────────────────────
    if not args.no_screenshot:
        saved = run_screenshots(hits, out_dir, args.shot_workers)
        print(f"\n[✓] Done — {saved} screenshot(s) saved to '{out_dir}/'")
    else:
        print(f"\n[✓] Done — hits written to '{hits_file}' (screenshots skipped)")


if __name__ == "__main__":
    main()
