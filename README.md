# Threat-IP Blocklist Importer

Auto-import a live malicious-IP blocklist into nftables, ipset, fail2ban,
pfSense and MikroTik RouterOS. Open source, privacy-first — powered by the
ValtersIT Threat-IP feed (`GET /api/v1/ip/feed`, Standard plan and above).

> Part of the ValtersIT platform — CVE & Threat-IP data you can query or run yourself.
> Explore both API and scanners: https://www.valtersit.com/platform/
> Scanner plans & pricing: https://www.valtersit.com/cve/pricing/#scanners

## What it does

Pulls the ValtersIT threat-IP feed and renders it into whichever firewall
format you need: a ready-to-load `nftables` ruleset, an `ipset` restore
file, `fail2ban-client banip` commands, a plain list for a pfSense URL Table
alias, or a MikroTik RouterOS `.rsc` script. For nftables and ipset it can
also apply the result directly on this host with `--apply`.

This tool is the mirror image of the scanners in the ValtersIT platform: it
sends nothing about your system to the API — it only pulls threat data down.

## Your data stays yours

- **What we receive:** nothing about your system. This tool makes exactly
  one kind of call to the API — a read-only `GET /api/v1/ip/feed` — and
  sends no information about your host, network, or firewall.
- **What it does not do:** it never touches any other firewall rule, chain,
  or table beyond the one it explicitly creates/replaces (named
  `valtersit_threat_ip` by default, override with `--list-name`); it never
  applies anything without either `--yes` or an explicit interactive
  confirmation; and for pfSense/MikroTik it never connects to that device at
  all — it only ever writes a local file for you to import there yourself.
- **Audit it yourself.** This is open source — two files, ~300 lines total.
  Read `valtersit-blocklist.py` and `valtersit_client.py`; there is nothing
  else running.

The feed's JSON shape can differ slightly between plans. The parser handles
the common variants, and `--debug` prints the raw first response so you can
confirm it matches your account (adjust `FEED_LIST_KEYS` / `FEED_IP_KEYS` at
the top of the script if needed).

## Install

Clone the repository:

```bash
# GitHub
git clone https://github.com/hugovalters/threat-ip-blocklist
cd threat-ip-blocklist

# GitLab
git clone https://gitlab.com/valtersit/threat-ip-blocklist
cd threat-ip-blocklist
```

Or, one-liner (no git required):

```bash
# GitHub
mkdir -p threat-ip-blocklist && cd threat-ip-blocklist
curl -fsSLO https://raw.githubusercontent.com/hugovalters/threat-ip-blocklist/main/valtersit-blocklist.py
curl -fsSLO https://raw.githubusercontent.com/hugovalters/threat-ip-blocklist/main/valtersit_client.py

# GitLab
mkdir -p threat-ip-blocklist && cd threat-ip-blocklist
curl -fsSLO https://gitlab.com/valtersit/threat-ip-blocklist/-/raw/main/valtersit-blocklist.py
curl -fsSLO https://gitlab.com/valtersit/threat-ip-blocklist/-/raw/main/valtersit_client.py
```

Set your API key — either method works:

```bash
# Method 1: environment variable (recommended)
export VALTERSIT_API_KEY="vit_v1_your_key_here"

# Method 2: edit one line directly in valtersit_client.py
#   API_KEY = "vit_v1_your_key_here"
```

This feature requires a **Standard plan or above** — see
[valtersit.com/cve/pricing](https://www.valtersit.com/cve/pricing/#scanners).

Run it (pick a format):

```bash
python3 valtersit-blocklist.py --format nftables --debug   # first run: verify the response shape
python3 valtersit-blocklist.py --format nftables --output blocklist.nft
python3 valtersit-blocklist.py --format ipset --apply --yes
```

Requires only a stock Python 3 interpreter (3.7+). No `pip install`.

## Sample output

```
$ python3 valtersit-blocklist.py --format nftables
[i] 4 IPv4 + 1 IPv6 entries (0 unparsable skipped) from the ValtersIT threat-IP feed.
#!/usr/sbin/nft -f
# ValtersIT threat-IP blocklist - generated 2026-09-25T15:00:00Z
# Load with: nft -f <this file>   (or pipe it in: nft -f -)
...
table inet valtersit_threat_ip {
    set blocklist_v4 {
        type ipv4_addr
        flags interval
        elements = {
            203.0.113.5,
            203.0.113.6
        }
    }
    chain input {
        type filter hook input priority 0; policy accept;
        ip saddr @blocklist_v4 counter drop
    }
}
```

**What to do next:** `nft -f blocklist.nft` (or `--apply` to skip the file),
then confirm it's active with `nft list table inet valtersit_threat_ip`.
Re-run on a schedule — the generated table fully replaces itself each time,
so stale entries are dropped automatically.

## Schedule it

Cron, every 6 hours, applying directly to this host's nftables:

```
0 */6 * * * cd /opt/threat-ip-blocklist && VALTERSIT_API_KEY=vit_v1_xxx /usr/bin/python3 valtersit-blocklist.py --format nftables --apply --yes >> /var/log/valtersit-blocklist.log 2>&1
```

One-liner:

```bash
VALTERSIT_API_KEY=vit_v1_xxx python3 valtersit-blocklist.py --format nftables --apply --yes
```

For pfSense: host the generated file somewhere reachable (a small cron job
regenerating a static file behind a webserver works well), then point a
**Firewall > Aliases > URL Table (IPs)** alias at that URL with a refresh
frequency — pfSense re-fetches it on its own schedule.

For MikroTik: schedule `/tool fetch` to pull a regenerated `.rsc` and
`/import` it via `/system scheduler`, or push it via your own deployment
process.

## Setup paths

**Clean new system:** install Python 3, plus whichever of `nftables` /
`ipset` you intend to use (already present on most modern Linux distros).
Clone this repo, set `VALTERSIT_API_KEY`, run once by hand with `--debug` to
confirm the feed's shape matches this tool's parsing, then schedule it.

**Existing production system:** `--apply` only ever touches the single
table/set this tool owns (default name `valtersit_threat_ip`) — it does not
modify, flush, or reorder any of your existing rules. Even so, treat any
tool that can drop traffic at the firewall as something to dry-run first:
generate with `--output` and inspect the file, or run once without `--apply`
before adding it to cron. For fail2ban, the target `--jail` must already
exist (`fail2ban-client set <jail> banip <ip>` doesn't create jails).

## Authorised use only

Run this against firewalls you own or are authorised to administer.
`--apply` requires an explicit interactive confirmation unless you pass
`--yes` (for cron/CI use) — read that prompt before automating it in a way
that can't be reviewed.

Licensed under Apache-2.0 (see `LICENSE` and `NOTICE`); provided without
warranty of any kind. "ValtersIT" and the ValtersIT logo are trademarks of
Valters Capital, SIA and are not licensed for use.

## Questions or a bug?

Please **don't** open GitHub/GitLab issues — I don't monitor them.
Reach me through the contact form instead: https://www.valtersit.com/contacts/
Maintained by Hugo Valters