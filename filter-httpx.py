#!/usr/bin/env python3
"""
Filter output httpx JSONL -> alive.txt (5 aturan).

Pemakaian:
    python3 filter-httpx.py <httpx.json> [-o OUT_DIR]

Output:
    alive.txt              host aktif (scheme://host[:port], path dibuang)
    redirect-external.txt  tujuan redirect lintas host
    restricted.txt         host 401/403
    dropped.txt            host 404/502/503
"""
import argparse
import json
import os
import sys
from collections import defaultdict
from urllib.parse import urlsplit


def final_url(row):
    if row.get("final_url"):
        return row["final_url"]
    chain = row.get("chain") or []
    if chain:
        url = chain[-1].get("request-url")
        if url:
            return url
    return row.get("location") or row.get("url") or ""


def split_url(url):
    s = urlsplit(url)
    scheme = (s.scheme or "http").lower()
    host = (s.hostname or "").lower()
    port = s.port
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        port = None
    return scheme, host, port


def hostport(url):
    scheme, host, port = split_url(url)
    if not host:
        return ""
    return f"{scheme}://{host}" + (f":{port}" if port else "")


def is_same_host(row, target):
    h = (urlsplit(target).hostname or "").lower()
    return (not h) or h == (row.get("host") or "").lower()


def canonical_rank(row):
    # pakai port asli (jangan dinormalisasi dulu), biar 80 menang atas 8080
    parsed = urlsplit(final_url(row))
    scheme = (parsed.scheme or "http").lower()
    return (
        0 if scheme == "https" else 1,
        {443: 0, 80: 1, 8080: 2, 8000: 3, 8443: 4}.get(parsed.port, 9),
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input", help="httpx JSONL")
    ap.add_argument("-o", "--out", default=None, help="output directory")
    args = ap.parse_args()

    out_dir = args.out or "."
    os.makedirs(out_dir, exist_ok=True)
    rows = []
    with open(args.input, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                sys.exit(f"baris {lineno} bukan JSON valid: {exc}")

    if not rows:
        sys.exit("input kosong")

    alive_rows, external, restricted, dropped = [], [], [], []

    for row in rows:
        sc = row.get("status_code")
        if sc == 200:
            alive_rows.append(row)
        elif sc is not None and 300 <= sc < 400:
            target = row.get("location") or final_url(row)
            if is_same_host(row, target):
                # same-host redirect yang kepotong -maxr: tetap hidup
                alive_rows.append(row)
            else:
                external.append(row)
        elif sc in (401, 403):
            restricted.append(row)
        else:
            dropped.append(row)

    # aturan 5: host sama + body hash sama -> duplikat antar port
    groups = defaultdict(list)
    for row in alive_rows:
        md5 = (row.get("hash") or {}).get("body_md5", "")
        groups[(row.get("host"), md5)].append(row)

    kept, collapsed = [], []
    for group in groups.values():
        if len(group) > 1:
            group = sorted(group, key=canonical_rank)
            kept.append(group[0])
            collapsed.extend(group[1:])
        else:
            kept.append(group[0])

    # normalisasi ke host:port, path dibuang
    entries = {hostport(final_url(r)) for r in kept}
    entries.discard("")

    # kalau host punya https, buang varian http default port
    by_host = defaultdict(set)
    for e in entries:
        scheme, host, port = split_url(e)
        by_host[host].add((scheme, port))

    alive = set()
    for host, variants in by_host.items():
        has_https = ("https", None) in variants
        for scheme, port in variants:
            if scheme == "http" and port is None and has_https:
                continue
            alive.add(f"{scheme}://{host}" + (f":{port}" if port else ""))

    external_urls = sorted({final_url(r) for r in external if final_url(r)})
    restricted_targets = sorted({hostport(final_url(r)) for r in restricted} - {""})

    with open(f"{out_dir}/alive.txt", "w", encoding="utf-8") as fh:
        fh.write("\n".join(sorted(alive)) + "\n")
    with open(f"{out_dir}/redirect-external.txt", "w", encoding="utf-8") as fh:
        fh.write("\n".join(external_urls) + "\n")
    with open(f"{out_dir}/restricted.txt", "w", encoding="utf-8") as fh:
        fh.write("\n".join(restricted_targets) + "\n")
    with open(f"{out_dir}/dropped.txt", "w", encoding="utf-8") as fh:
        fh.write("\n".join(sorted({f"{r.get('host')}:{r.get('port')} -> {r.get('status_code')}" for r in dropped})) + "\n")

    print(f"input rows          : {len(rows)}")
    print(f"alive rows          : {len(alive_rows)}")
    print(f"  same-host 3xx     : {sum(1 for r in alive_rows if (r.get('status_code') or 0) >= 300)}")
    print(f"  collapsed dupe    : {len(collapsed)}")
    print(f"alive.txt           : {len(alive)} host")
    print(f"redirect external   : {len(external_urls)} target")
    print(f"restricted          : {len(restricted_targets)} host")
    print(f"dropped             : {len(dropped)} baris")
    print(f"out dir             : {out_dir}")


if __name__ == "__main__":
    main()
