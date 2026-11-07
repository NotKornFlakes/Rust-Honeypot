#!/usr/bin/env python3
"""Ask URLhaus and AbuseIPDB whether they already knew the honeypot's download addresses and IPs.

Run it by hand from the repository root:

    python3 analysis/threat_intel_lookup.py           # shows what it would look up, sends nothing
    python3 analysis/threat_intel_lookup.py --send    # does the lookups after you type yes

What it sends, and nothing else:
  - URLhaus, with your Auth-Key: each download address to the URL lookup
    (POST https://urlhaus-api.abuse.ch/v1/url/), and each address's server, the host name or IP
    and nothing more, to the host lookup (POST https://urlhaus-api.abuse.ch/v1/host/).
  - AbuseIPDB, with your API key: each visitor IP to the check lookup
    (GET https://api.abuseipdb.com/api/v2/check).

It never submits or reports anything, never contacts a download address or any other host, and
refuses redirects. It never sends log contents: no commands, usernames, passwords or times.
Passwords are read once, only to leave out your own test visits, as the notebook does.

Keys come from the URLHAUS_AUTH_KEY and ABUSEIPDB_KEY environment variables, or it asks for them
without echoing. They're never written down or printed.

Results go to ~/honeypot-logs/intel/lookups.json, readable only by you. They hold full IPs and
addresses, so safety rule 4 applies: never commit or publish the file. Entries older than 30 days
are dropped each time this runs, matching KEEP_DAYS in deploy/daily-logs.sh. The notebook reads
the file and turns every IP and address into an opaque ID straight away.
"""

import argparse
import getpass
import ipaddress
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

LOG_DIR = Path.home() / "honeypot-logs"
OUT_FILE = LOG_DIR / "intel" / "lookups.json"
KEEP_DAYS = 30  # the same as deploy/daily-logs.sh
OWN_TEST_PASSWORD = "not-on-the-list"  # my own test visits used this password
REPORT_DAYS = 365  # the longest look-back AbuseIPDB allows
FREE_DAILY_CHECKS = 1000

URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/url/"
URLHAUS_HOST = "https://urlhaus-api.abuse.ch/v1/host/"
ABUSEIPDB_CHECK = "https://api.abuseipdb.com/api/v2/check"
# The only requests this script can make. Anything else is refused before it's sent.
ALLOWED = {("POST", URLHAUS_URL), ("POST", URLHAUS_HOST), ("GET", ABUSEIPDB_CHECK)}
USER_AGENT = "honeypot-lookup/1"


class NoRedirects(urllib.request.HTTPRedirectHandler):
    """A redirect could point anywhere, including a download address, so none are followed."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # urllib then raises HTTPError for the 3xx response


OPENER = urllib.request.build_opener(NoRedirects)


def call(method, endpoint, headers, query=None, form=None):
    """Make one allowed lookup and return its JSON. Refuses any other endpoint."""
    if (method, endpoint) not in ALLOWED:
        raise SystemExit(f"Refused {method} {endpoint}: it isn't one of the three lookup endpoints.")
    url = endpoint + ("?" + query if query else "")
    body = urllib.parse.urlencode(form).encode() if form is not None else None
    request = urllib.request.Request(url, data=body, method=method,
                                     headers={"User-Agent": USER_AGENT, **headers})
    with OPENER.open(request, timeout=30) as response:
        return json.load(response), response.headers


def now():
    return datetime.now(timezone.utc)


def parse_time(text):
    """URLhaus writes '2019-01-19 01:33:26 UTC', AbuseIPDB '2019-07-23T17:29:38+00:00'."""
    if not text:
        return None
    text = text.strip()
    if text.endswith(" UTC"):
        return datetime.strptime(text, "%Y-%m-%d %H:%M:%S UTC").replace(tzinfo=timezone.utc)
    return datetime.fromisoformat(text)


def defang(text):
    """For the screen: no full IPs and no working links."""
    text = re.sub(r"\b(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}\b", r"\1[.]\2[.]x[.]x", text)
    text = re.sub(r"(?i)\bhttp", "hxxp", text)
    text = re.sub(r"(hxxps?://)([A-Za-z0-9.-]+)", lambda m: m[1] + m[2].replace(".", "[.]"), text)
    return re.sub(r"(?<=/)(?=[A-Za-z0-9]*\d)(?=[A-Za-z0-9]*[A-Za-z])[A-Za-z0-9]{8,}(?=/)", "<id>", text)


def is_public_ip(text):
    try:
        return ipaddress.ip_address(text).is_global
    except ValueError:
        return False


def server_of(address):
    """The host part of a download address, read from its text. Nothing is contacted.

    Returns (host, reason): reason is set when the address shouldn't be looked up at all.
    """
    if "://" not in address:  # a bare host, as tftp takes it
        host = address.strip()
        if not re.fullmatch(r"[A-Za-z0-9.-]+", host):
            return None, "not a plain host name"
    else:
        try:
            parts = urllib.parse.urlsplit(address)
            host = parts.hostname
        except ValueError:
            return None, "can't be read as a URL"
        if parts.scheme.lower() not in ("http", "https"):
            return None, "not an http or https address"
        if "@" in parts.netloc:
            return None, "it holds a user name or password"
        if parts.query or parts.fragment:
            return None, "it has a query string, which can carry the target's details"
        if not host:
            return None, "no host"
    if re.fullmatch(r"[\d.]+", host) and not is_public_ip(host):
        return None, "its server isn't a public IP"
    return host.lower(), None


def read_logs(log_dir):
    """Visitor IPs and download addresses, each with the first time the honeypot saw it."""
    raw = []
    for path in sorted(log_dir.glob("visits-*.jsonl")):
        with path.open(encoding="utf-8", errors="replace") as f:
            for line in f:
                try:
                    raw.append(json.loads(line))
                except json.JSONDecodeError:
                    pass  # a line cut off while the log was being copied
    own = {v["source_ip"] for v in raw if v.get("password") == OWN_TEST_PASSWORD}
    ips, addresses, left_out = {}, {}, Counter()
    for v in raw:
        ip, seen = v["source_ip"], datetime.fromtimestamp(v["time"], timezone.utc)
        if ip in own:
            continue
        if not is_public_ip(ip):
            left_out["non-public IP"] += 1
            continue
        ips[ip] = min(ips.get(ip, seen), seen)
        for address in (v.get("shell") or {}).get("urls") or []:
            addresses[address] = min(addresses.get(address, seen), seen)
    return ips, addresses, len(own), left_out


def load_results(path):
    if not path.exists():
        return {"format": 1, "urlhaus": {}, "abuseipdb": {}}
    data = json.loads(path.read_text())
    cutoff = now() - timedelta(days=KEEP_DAYS)
    for section in ("urlhaus", "abuseipdb"):
        data[section] = {k: r for k, r in data.get(section, {}).items()
                         if parse_time(r["checked_at"]) >= cutoff}
    return data


def save_results(path, data):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    temp = path.with_suffix(".tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f, indent=1, sort_keys=True)
    os.replace(temp, path)


def get_key(variable, name):
    key = os.environ.get(variable) or getpass.getpass(f"{name} key (not shown, not saved): ")
    if not key.strip():
        raise SystemExit(f"No {name} key given.")
    return key.strip()


def urlhaus_lookups(addresses, key, results):
    """One URL lookup per http(s) address and one host lookup per server."""
    hosts = {}
    for address, (host, first_seen) in addresses.items():
        record = {"checked_at": now().isoformat(), "first_seen_here": first_seen.isoformat(),
                  "kind": "url" if "://" in address else "host"}
        if record["kind"] == "url":
            data, _ = call("POST", URLHAUS_URL, {"Auth-Key": key}, form={"url": address})
            payloads = data.get("payloads") or []
            added = parse_time(data.get("date_added"))
            record["url"] = {
                "status": data.get("query_status"), "date_added": data.get("date_added"),
                "before_us": bool(added and added < first_seen), "url_status": data.get("url_status"),
                "last_online": data.get("last_online"), "threat": data.get("threat"),
                "tags": data.get("tags") or [], "payloads": len(payloads),
                "signatures": sorted({p["signature"] for p in payloads if p.get("signature")}),
                "reference": data.get("urlhaus_reference"),
            }
            time.sleep(1)
        if host not in hosts:
            data, _ = call("POST", URLHAUS_HOST, {"Auth-Key": key}, form={"host": host})
            hosts[host] = data
            time.sleep(1)
        data = hosts[host]
        seen = parse_time(data.get("firstseen"))
        record["host"] = {
            # The documentation's own example spells the status key "query_staus".
            "status": data.get("query_status") or data.get("query_staus"),
            "firstseen": data.get("firstseen"), "before_us": bool(seen and seen < first_seen),
            "url_count": data.get("url_count"), "reference": data.get("urlhaus_reference"),
        }
        results["urlhaus"][address] = record
        print(f"  {defang(address)}: URL {record.get('url', {}).get('status', '(not a URL)')}, "
              f"server {record['host']['status']}")


def abuseipdb_checks(ips, key, results, out_file, limit):
    done, remaining = 0, None
    for ip, first_seen in ips.items():
        if done >= limit:
            print(f"  Stopped at --limit {limit}.")
            break
        query = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": REPORT_DAYS}) + "&verbose"
        try:
            data, headers = call("GET", ABUSEIPDB_CHECK, {"Key": key, "Accept": "application/json"},
                                 query=query)
        except urllib.error.HTTPError as e:
            if e.code == 429:
                reset = e.headers.get("X-RateLimit-Reset")
                when = datetime.fromtimestamp(int(reset), timezone.utc).strftime("%b %d %H:%M UTC") if reset else "later"
                print(f"  AbuseIPDB's daily limit is used up. Run this again after {when}; it carries on "
                      "where it stopped.")
                break
            raise
        d = data["data"]
        times = sorted(t for t in (parse_time(r.get("reportedAt")) for r in d.get("reports") or []) if t)
        results["abuseipdb"][ip] = {
            "checked_at": now().isoformat(), "first_seen_here": first_seen.isoformat(),
            "score": d.get("abuseConfidenceScore"), "total_reports": d.get("totalReports"),
            "distinct_users": d.get("numDistinctUsers"), "last_reported": d.get("lastReportedAt"),
            "first_reported": times[0].isoformat() if times else None,
            "reports_before_us": sum(t < first_seen for t in times),
            "usage_type": d.get("usageType"), "is_tor": d.get("isTor"),
            "is_whitelisted": d.get("isWhitelisted"),
        }
        done += 1
        remaining = headers.get("X-RateLimit-Remaining", remaining)
        if done % 25 == 0:
            save_results(out_file, results)
            print(f"  {done} checked…")
        time.sleep(0.2)
    print(f"  {done} IPs checked this run." + (f" AbuseIPDB says {remaining} checks are left today."
                                              if remaining is not None else ""))


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--send", action="store_true", help="do the lookups (without it, nothing is sent)")
    parser.add_argument("--yes", action="store_true", help="don't ask before sending")
    parser.add_argument("--only", choices=["urlhaus", "abuseipdb"], help="use only one service")
    parser.add_argument("--refresh", action="store_true", help="look up again what's already in the results")
    parser.add_argument("--limit", type=int, default=FREE_DAILY_CHECKS, help="most AbuseIPDB checks this run")
    parser.add_argument("--logs", type=Path, default=LOG_DIR)
    parser.add_argument("--out", type=Path, default=OUT_FILE)
    args = parser.parse_args()

    ips, found, own_count, left_out = read_logs(args.logs)
    results = load_results(args.out)
    addresses, skipped = {}, []
    for address, first_seen in sorted(found.items(), key=lambda kv: kv[1]):
        host, reason = server_of(address)
        if reason:
            skipped.append((address, reason))
        else:
            addresses[address] = (host, first_seen)
    if not args.refresh:
        addresses = {a: v for a, v in addresses.items() if a not in results["urlhaus"]}
        ips = {ip: t for ip, t in ips.items() if ip not in results["abuseipdb"]}
    use_urlhaus, use_abuseipdb = args.only in (None, "urlhaus"), args.only in (None, "abuseipdb")

    print(f"Left out: {own_count} of my own test IPs and every address only they used"
          + "".join(f", {n} visits from a {why}" for why, n in left_out.items()) + ".")
    for address, reason in skipped:
        print(f"Won't look up {defang(address)}: {reason}.")
    already = len(results["urlhaus"]) + len(results["abuseipdb"])
    if already and not args.refresh:
        print(f"Already in {args.out} from the last {KEEP_DAYS} days, so not looked up again: "
              f"{len(results['urlhaus'])} addresses, {len(results['abuseipdb'])} IPs (--refresh redoes them).")
    if use_urlhaus:
        n_hosts = len({h for h, _ in addresses.values()})
        n_urls = sum("://" in a for a in addresses)
        print(f"\nURLhaus: {n_urls} URL lookups and {n_hosts} server lookups.")
        for address, (_, first_seen) in addresses.items():
            print(f"  {defang(address):70} first seen here {first_seen:%b %d %H:%M} UTC")
    if use_abuseipdb:
        n = min(len(ips), args.limit)
        print(f"\nAbuseIPDB: {n} IP checks, each asking for {REPORT_DAYS} days of reports. A free account "
              f"has {FREE_DAILY_CHECKS:,} a day; a later run carries on where this one stops.")
    if not ((use_urlhaus and addresses) or (use_abuseipdb and ips)):
        print("\nNothing new to look up.")
        return
    if not args.send:
        print("\nNothing was sent. Add --send to do these lookups.")
        return
    if not args.yes and input("\nSend these lookups? Type yes: ").strip().lower() != "yes":
        print("Nothing was sent.")
        return

    try:
        if use_urlhaus and addresses:
            print("\nURLhaus:")
            urlhaus_lookups(addresses, get_key("URLHAUS_AUTH_KEY", "URLhaus Auth-Key"), results)
            save_results(args.out, results)
        if use_abuseipdb and ips:
            print("\nAbuseIPDB:")
            abuseipdb_checks(ips, get_key("ABUSEIPDB_KEY", "AbuseIPDB API"), results, args.out, args.limit)
    except urllib.error.HTTPError as e:
        print(f"Stopped: {e.code} {e.reason} from {urllib.parse.urlsplit(e.url).hostname}. "
              "401 or 403 usually means a wrong key.", file=sys.stderr)
    except urllib.error.URLError as e:
        print(f"Stopped: couldn't reach the service ({e.reason}).", file=sys.stderr)
    finally:
        save_results(args.out, results)

    u, a = results["urlhaus"].values(), results["abuseipdb"].values()
    print(f"\nSaved to {args.out}.")
    if u:
        known = sum(r.get("url", {}).get("status") == "ok" or r["host"]["status"] == "ok" for r in u)
        early = sum(r.get("url", {}).get("before_us") or r["host"]["before_us"] for r in u)
        print(f"URLhaus knew {known} of {len(u)} addresses (the URL or its server), {early} before the honeypot saw them.")
    if a:
        reported = sum((r["total_reports"] or 0) > 0 for r in a)
        early = sum(r["reports_before_us"] > 0 for r in a)
        print(f"AbuseIPDB had reports from the past {REPORT_DAYS} days for {reported} of {len(a)} IPs, "
              f"{early} of them from before the honeypot first saw the IP.")


if __name__ == "__main__":
    main()
