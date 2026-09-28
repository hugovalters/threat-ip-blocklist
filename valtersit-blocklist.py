#!/usr/bin/env python3
# Copyright 2026 Valters Capital, SIA
# Licensed under the Apache License, Version 2.0.
# ValtersIT is a trademark of Valters Capital, SIA — see NOTICE.
# Maintained by Hugo Valters

"""
ValtersIT Threat-IP Blocklist Importer

Pulls the ValtersIT malicious-IP threat feed (GET /api/v1/ip/feed) and
renders it into a format your firewall can load: nftables, ipset, fail2ban,
pfSense (URL Table alias), or MikroTik RouterOS address-lists.

Unlike the scanner tools in this project, this tool sends nothing about
your system to the API at all - it only pulls data down. The only
destructive action it can take is local: writing/loading firewall rules on
this host with --apply (nftables/ipset only; pfSense and MikroTik targets
are normally a different box, so those formats are always just files you
import there yourself).

Note on the feed's exact response shape: at the time this tool was written,
GET /api/v1/ip/feed could be confirmed to exist and to be plan-gated, but
its precise JSON schema could not be verified against a real key. Parsing
below is deliberately defensive (it looks for several plausible field
names) - run with --debug once against your real key and, if it doesn't
find anything, adjust FEED_LIST_KEYS / FEED_IP_KEYS below to match what your
account actually returns.
"""

from __future__ import annotations

import argparse
import ipaddress
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import valtersit_client as vit  # noqa: E402

# Candidate keys for locating the list of entries / the IP field within an
# entry - see the module docstring above.
FEED_LIST_KEYS = ("data", "results", "ips", "feed", "items")
FEED_IP_KEYS = ("ip", "ip_address", "address", "indicator")


# ---------------------------------------------------------------------------
# Fetch
# ---------------------------------------------------------------------------

def extract_items(body) -> list[dict]:
    if isinstance(body, list):
        raw = body
    elif isinstance(body, dict):
        raw = None
        for key in FEED_LIST_KEYS:
            if isinstance(body.get(key), list):
                raw = body[key]
                break
        if raw is None:
            return []
    else:
        return []

    out = []
    for entry in raw:
        if isinstance(entry, str):
            out.append({"ip": entry})
            continue
        if not isinstance(entry, dict):
            continue
        ip = None
        for key in FEED_IP_KEYS:
            if entry.get(key):
                ip = entry[key]
                break
        if ip:
            out.append({"ip": ip})
    return out


def fetch_feed(limit: int, max_pages: int, debug: bool = False) -> list[dict]:
    all_items = []
    page = 1
    while True:
        status, body = vit.api_get("/ip/feed", params={"limit": limit, "page": page})
        if debug and page == 1:
            import json as _json
            print("[debug] raw first-page response:", file=sys.stderr)
            print(_json.dumps(body, indent=2)[:4000], file=sys.stderr)
        if status is None or not (200 <= status < 300):
            print("[!] " + vit.explain_status(status, body), file=sys.stderr)
            sys.exit(1)

        items = extract_items(body)
        if not items:
            break
        all_items.extend(items)

        total_pages = body.get("total_pages") if isinstance(body, dict) else None
        if total_pages:
            if page >= total_pages:
                break
        elif len(items) < limit:
            break

        page += 1
        if page > max_pages:
            print(
                "[!] Stopped after {} pages (--max-pages). Increase it to fetch "
                "more of the feed.".format(max_pages),
                file=sys.stderr,
            )
            break
    return all_items


def classify_ip(raw: str):
    """Return (normalised_str, version) or (None, None) if unparsable.
    Accepts bare IPs and CIDR ranges."""
    try:
        net = ipaddress.ip_network(raw.strip(), strict=False)
    except ValueError:
        return None, None
    if net.num_addresses == 1:
        return str(net.network_address), net.version
    return str(net), net.version


def dedupe(seq):
    seen = set()
    out = []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def split_v4_v6(items: list[dict]):
    v4, v6, skipped = [], [], 0
    for entry in items:
        normalised, version = classify_ip(entry["ip"])
        if normalised is None:
            skipped += 1
            continue
        (v4 if version == 4 else v6).append(normalised)
    return dedupe(v4), dedupe(v6), skipped


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------

def render_nftables(v4, v6, list_name) -> str:
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    lines = [
        "#!/usr/sbin/nft -f",
        "# ValtersIT threat-IP blocklist - generated {}".format(now),
        "# Load with: nft -f <this file>   (or pipe it in: nft -f -)",
        "# Fully replaces this table each time it's regenerated, so stale",
        "# entries are removed automatically - just reload to refresh.",
        "#",
        "# NOTE: this defines its own standalone 'inet {}' table with its own".format(list_name),
        "# input hook at priority 0. If you already manage input filtering via",
        "# another nftables table (ufw, firewalld, ...), check rule ordering",
        "# rather than assuming this integrates automatically - or copy just",
        "# the `set` block into your own table/chain instead.",
        "",
        "table inet {} {{".format(list_name),
    ]
    if v4:
        elements = ",\n            ".join(v4)
        lines.append(
            "    set blocklist_v4 {{\n        type ipv4_addr\n        flags interval\n"
            "        elements = {{\n            {}\n        }}\n    }}\n".format(elements)
        )
    if v6:
        elements = ",\n            ".join(v6)
        lines.append(
            "    set blocklist_v6 {{\n        type ipv6_addr\n        flags interval\n"
            "        elements = {{\n            {}\n        }}\n    }}\n".format(elements)
        )
    chain = ["    chain input {", "        type filter hook input priority 0; policy accept;"]
    if v4:
        chain.append("        ip saddr @blocklist_v4 counter drop")
    if v6:
        chain.append("        ip6 saddr @blocklist_v6 counter drop")
    chain.append("    }")
    lines.append("\n".join(chain))
    lines.append("}")
    return "\n".join(lines) + "\n"


def render_ipset(v4, v6, list_name) -> str:
    lines = ["create {} hash:net family inet -exist".format(list_name), "flush {}".format(list_name)]
    lines += ["add {} {}".format(list_name, ip) for ip in v4]
    if v6:
        v6_name = list_name + "6"
        lines += ["create {} hash:net family inet6 -exist".format(v6_name), "flush {}".format(v6_name)]
        lines += ["add {} {}".format(v6_name, ip) for ip in v6]
    return "\n".join(lines) + "\n"


def render_fail2ban(all_ips, jail) -> str:
    single_ips = [ip for ip in all_ips if "/" not in ip]
    skipped_ranges = len(all_ips) - len(single_ips)
    lines = [
        "#!/bin/sh",
        "# ValtersIT threat-IP blocklist -> fail2ban jail '{}'".format(jail),
        "# Requires the jail to already exist - fail2ban-client set <jail> banip",
        "# fails otherwise. CIDR ranges are not supported by 'banip' and are",
        "# skipped ({} skipped this run).".format(skipped_ranges),
        "",
    ]
    lines += ["fail2ban-client set {} banip {}".format(jail, ip) for ip in single_ips]
    return "\n".join(lines) + "\n"


def render_pfsense(all_ips) -> str:
    # pfSense's "URL Table (IPs)" alias type consumes exactly this: one
    # IP or CIDR per line. Host this file somewhere pfSense can fetch on a
    # schedule and point a URL Table alias at it - see README.
    return "\n".join(all_ips) + "\n"


def render_mikrotik(all_ips, list_name) -> str:
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    lines = [
        "# ValtersIT threat-IP blocklist - generated {}".format(now),
        "# Import with: /import file-name=valtersit-blocklist.rsc",
        "/ip firewall address-list",
        "remove [find list={}]".format(list_name),
    ]
    lines += ['add list={} address={} comment="ValtersIT feed"'.format(list_name, ip) for ip in all_ips]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Apply locally (nftables / ipset only)
# ---------------------------------------------------------------------------

def apply_locally(fmt: str, content: str):
    cmd = ["nft", "-f", "-"] if fmt == "nftables" else ["ipset", "restore", "-!"]
    try:
        proc = subprocess.run(cmd, input=content, text=True, capture_output=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        print("[!] Failed to run {}: {}".format(cmd[0], exc), file=sys.stderr)
        sys.exit(1)
    if proc.returncode != 0:
        print("[!] {} failed:\n{}".format(cmd[0], proc.stderr), file=sys.stderr)
        sys.exit(1)
    print("[+] Applied via {}.".format(cmd[0]))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Import the ValtersIT threat-IP feed into your firewall.")
    parser.add_argument("--format", required=True,
                         choices=["nftables", "ipset", "fail2ban", "pfsense", "mikrotik"])
    parser.add_argument("--output", help="Write to this file instead of stdout.")
    parser.add_argument("--apply", action="store_true",
                         help="nftables/ipset only: load the generated ruleset directly on this host.")
    parser.add_argument("--yes", action="store_true", help="Skip the confirmation prompt before --apply.")
    parser.add_argument("--jail", default="valtersit-threat-ip",
                         help="fail2ban jail name to target (must already exist). Default: valtersit-threat-ip")
    parser.add_argument("--list-name", default="valtersit_threat_ip",
                         help="Set/table/list name used in nftables, ipset and MikroTik output.")
    parser.add_argument("--limit", type=int, default=500,
                         help="Rows per API request (Standard plan max 500, Pro max 1000). Default 500.")
    parser.add_argument("--max-pages", type=int, default=50)
    parser.add_argument("--debug", action="store_true", help="Print the raw first-page API response to stderr.")
    args = parser.parse_args()

    items = fetch_feed(args.limit, args.max_pages, debug=args.debug)
    if not items:
        print(
            "[!] No entries returned by the feed (or none could be parsed - "
            "re-run with --debug and check FEED_LIST_KEYS/FEED_IP_KEYS at the "
            "top of this script against the real response shape).",
            file=sys.stderr,
        )
        sys.exit(1)

    v4, v6, skipped = split_v4_v6(items)
    print(
        "[i] {} IPv4 + {} IPv6 entries ({} unparsable skipped) from the ValtersIT threat-IP feed.".format(
            len(v4), len(v6), skipped
        ),
        file=sys.stderr,
    )

    renderers = {
        "nftables": lambda: render_nftables(v4, v6, args.list_name),
        "ipset": lambda: render_ipset(v4, v6, args.list_name),
        "fail2ban": lambda: render_fail2ban(v4 + v6, args.jail),
        "pfsense": lambda: render_pfsense(v4 + v6),
        "mikrotik": lambda: render_mikrotik(v4 + v6, args.list_name),
    }
    content = renderers[args.format]()

    if args.output:
        Path(args.output).write_text(content)
        print("[+] Wrote {}".format(args.output), file=sys.stderr)
    else:
        print(content)

    if args.apply:
        if args.format not in ("nftables", "ipset"):
            print(
                "[!] --apply only supports nftables/ipset - pfSense and MikroTik "
                "targets are normally a different host; import the generated "
                "file there instead.",
                file=sys.stderr,
            )
            sys.exit(2)
        if not args.yes:
            answer = input(
                "This will load {} blocked address(es) into this host's {} "
                "configuration now. Continue? [y/N] ".format(len(v4) + len(v6), args.format)
            ).strip().lower()
            if answer != "y":
                print("Aborted - nothing applied.")
                sys.exit(1)
        apply_locally(args.format, content)


if __name__ == "__main__":
    main()
