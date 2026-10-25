#!/usr/bin/env python3
"""
alive.py - cek host langsung lewat HTTP/HTTPS, tanpa httpx.

Alur:
    subs.txt (daftar host) -> script -> alive.txt

Cara kerja:
- Port HTTP (80, 8000, 8008, 8080, 8081, 8088, 8888) dicek pakai skema http.
- Port HTTPS (443, 4443, 8443, 9443) dicek pakai skema https.
- Status 502, 503, 504 dibuang.
- Status lain masuk alive.txt.
- Host tanpa respons (timeout, TLS gagal, koneksi ditolak) tidak masuk.
- Host sama + hash body sama -> simpan satu, prioritas https 443.
- Redirect tidak diikuti, jadi host external tidak pernah ikut.

Pemakaian:
    python3 alive.py subs.txt
    python3 alive.py subs.txt -o hasil -t 8 -j 64
    python3 alive.py subs.txt --http-ports 80,8080 --https-ports 443
"""
import argparse
import hashlib
import http.client
import os
import socket
import ssl
import sys
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlsplit

DEFAULT_HTTP_PORTS = (80, 8000, 8008, 8080, 8081, 8088, 8888)
DEFAULT_HTTPS_PORTS = (443, 4443, 8443, 9443)

EXCLUDED_STATUS = {502, 503, 504}

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

DEFAULT_MAX_BODY = 262144
DEFAULT_TIMEOUT = 10.0
DEFAULT_THREADS = 32

PORT_PRIORITY = {443: 0, 80: 1, 8443: 2, 8080: 3, 8000: 4, 8888: 5}


def normalize_host(line):
    """Terima 'a.com', 'a.com:8080', atau 'https://a.com/x' -> 'a.com'."""
    value = line.strip()
    if not value or value.startswith("#"):
        return ""
    if "://" in value:
        value = urlsplit(value).hostname or ""
    elif "/" in value:
        value = value.split("/", 1)[0]
    if value.count(":") == 1:
        head, tail = value.rsplit(":", 1)
        if tail.isdigit():
            value = head
    return value.strip().strip(".").lower()


def parse_ports(text, fallback):
    if not text:
        return tuple(fallback)
    ports = []
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        if not part.isdigit():
            sys.exit(f"port tidak valid: {part!r}")
        port = int(part)
        if not 1 <= port <= 65535:
            sys.exit(f"port di luar rentang: {port}")
        if port not in ports:
            ports.append(port)
    return tuple(ports)


def probe(host, port, tls, timeout, user_agent, max_body):
    """Satu request GET ke '/', body dibaca maksimal max_body byte."""
    scheme = "https" if tls else "http"
    started = time.monotonic()
    conn = None
    try:
        if tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.set_alpn_protocols(["http/1.1"])
            conn = http.client.HTTPSConnection(
                host, port, timeout=timeout, context=context
            )
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)

        conn.request(
            "GET",
            "/",
            headers={
                "User-Agent": user_agent,
                "Accept": "*/*",
                "Accept-Encoding": "identity",
                "Connection": "close",
            },
        )
        response = conn.getresponse()

        digest = hashlib.md5()
        size = 0
        while size < max_body:
            chunk = response.read(min(65536, max_body - size))
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)

        return {
            "host": host,
            "port": port,
            "scheme": scheme,
            "status": response.status,
            "md5": digest.hexdigest(),
            "size": size,
            "ms": int((time.monotonic() - started) * 1000),
        }
    except (socket.timeout, TimeoutError):
        return {"host": host, "port": port, "scheme": scheme, "error": "timeout"}
    except ssl.SSLError as exc:
        reason = getattr(exc, "reason", None) or type(exc).__name__
        return {"host": host, "port": port, "scheme": scheme, "error": f"tls: {reason}"}
    except (ConnectionError, OSError) as exc:
        return {"host": host, "port": port, "scheme": scheme, "error": type(exc).__name__}
    except http.client.HTTPException as exc:
        return {
            "host": host,
            "port": port,
            "scheme": scheme,
            "error": f"http: {type(exc).__name__}",
        }
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def hostport(row):
    """scheme://host, tanpa :80 dan :443 karena sudah diwakili skema."""
    host = row["host"]
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    if (row["scheme"] == "http" and row["port"] == 80) or (
        row["scheme"] == "https" and row["port"] == 443
    ):
        return f"{row['scheme']}://{host}"
    return f"{row['scheme']}://{host}:{row['port']}"


def canonical_rank(row):
    """Wakil kalau isinya sama: https 443 dulu, lalu http 80, lalu port umum."""
    port = row["port"]
    return (
        0 if row["scheme"] == "https" else 1,
        PORT_PRIORITY.get(port, 9),
        port,
    )


def dedupe(rows):
    """Dedupe per host pakai hash body. Host beda tidak pernah digabung."""
    groups = defaultdict(list)
    for row in rows:
        groups[(row["host"], row["md5"])].append(row)

    kept = []
    collapsed = 0
    for group in groups.values():
        if len(group) > 1:
            group = sorted(group, key=canonical_rank)
            collapsed += len(group) - 1
        kept.append(group[0])
    return kept, collapsed


def human_list(code_counts):
    if not code_counts:
        return "-"
    items = [f"{status} x{count}" for status, count in sorted(code_counts.items())]
    return ", ".join(items)


def main():
    parser = argparse.ArgumentParser(
        description="Cek host langsung via HTTP/HTTPS, hasilnya alive.txt"
    )
    parser.add_argument("input", help="daftar host, satu per baris")
    parser.add_argument("-o", "--out", default=None, help="folder output (default: .)")
    parser.add_argument(
        "-t", "--timeout", type=float, default=DEFAULT_TIMEOUT, help="timeout detik"
    )
    parser.add_argument(
        "-j", "--threads", type=int, default=DEFAULT_THREADS, help="jumlah worker"
    )
    parser.add_argument(
        "--http-ports",
        default=None,
        help="port yang dicek pakai http (pisah koma)",
    )
    parser.add_argument(
        "--https-ports",
        default=None,
        help="port yang dicek pakai https (pisah koma)",
    )
    parser.add_argument(
        "--max-body",
        type=int,
        default=DEFAULT_MAX_BODY,
        help="batas byte body untuk hash (default 262144)",
    )
    parser.add_argument("--user-agent", default=DEFAULT_UA, help="User-Agent")
    parser.add_argument("-q", "--quiet", action="store_true", help="tanpa progress")
    args = parser.parse_args()

    http_ports = parse_ports(args.http_ports, DEFAULT_HTTP_PORTS)
    https_ports = parse_ports(args.https_ports, DEFAULT_HTTPS_PORTS)
    if args.timeout <= 0:
        sys.exit("timeout harus lebih dari 0")
    if args.threads < 1:
        sys.exit("threads minimal 1")
    if args.max_body < 1:
        sys.exit("max-body minimal 1")

    out_dir = args.out or "."
    os.makedirs(out_dir, exist_ok=True)

    hosts = []
    seen = set()
    with open(args.input, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            host = normalize_host(line)
            if not host or host in seen:
                continue
            seen.add(host)
            hosts.append(host)

    if not hosts:
        sys.exit("daftar host kosong")

    jobs = [
        (host, port, False) for host in hosts for port in http_ports
    ] + [(host, port, True) for host in hosts for port in https_ports]

    results = []
    errors = Counter()
    done = 0
    total = len(jobs)

    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = [
            pool.submit(
                probe, host, port, tls, args.timeout, args.user_agent, args.max_body
            )
            for host, port, tls in jobs
        ]
        for future in as_completed(futures):
            row = future.result()
            results.append(row)
            done += 1
            if not args.quiet and (done % 50 == 0 or done == total):
                sys.stderr.write(f"\rprobe {done}/{total}")
                sys.stderr.flush()
    if not args.quiet:
        sys.stderr.write("\n")

    alive_rows = []
    excluded = Counter()
    for row in results:
        if row.get("error"):
            errors[row["error"]] += 1
            continue
        if row["status"] in EXCLUDED_STATUS:
            excluded[row["status"]] += 1
            continue
        alive_rows.append(row)

    kept, collapsed = dedupe(alive_rows)
    alive = sorted({hostport(row) for row in kept})

    with open(f"{out_dir}/alive.txt", "w", encoding="utf-8") as handle:
        handle.write("\n".join(alive) + "\n")

    print(f"host unik         : {len(hosts)}")
    print(f"port http         : {','.join(str(p) for p in http_ports)}")
    print(f"port https        : {','.join(str(p) for p in https_ports)}")
    print(f"total probe       : {total}")
    print(f"tanpa respons     : {sum(errors.values())}  {human_list(dict(errors))}")
    print(f"dibuang 502/503/504: {sum(excluded.values())}  {human_list(dict(excluded))}")
    print(f"respons diterima  : {len(alive_rows)}")
    print(f"duplikat isi sama : {collapsed}")
    print(f"alive.txt         : {len(alive)} host")
    print(f"out dir           : {out_dir}")


if __name__ == "__main__":
    main()
