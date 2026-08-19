#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from pathlib import Path

SCHEMA = "desarrollamo.miweb.v1"
UA = "MiWeb/1.0 (+https://github.com/amoedo7/MiWeb)"


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_title = False
        self.title_parts: list[str] = []
        self.meta: dict[str, str] = {}
        self.canonical = None
        self.h1_count = 0
        self.images = 0
        self.images_without_alt = 0
        self.lang = None

    def handle_starttag(self, tag, attrs):
        a = {str(k).lower(): v for k, v in attrs}
        tag = tag.lower()
        if tag == "html":
            self.lang = a.get("lang")
        elif tag == "title":
            self.in_title = True
        elif tag == "meta":
            key = (a.get("name") or a.get("property") or "").lower()
            if key and a.get("content") is not None:
                self.meta[key] = a.get("content") or ""
        elif tag == "link" and (a.get("rel") or "").lower() == "canonical":
            self.canonical = a.get("href")
        elif tag == "h1":
            self.h1_count += 1
        elif tag == "img":
            self.images += 1
            if "alt" not in a:
                self.images_without_alt += 1

    def handle_endtag(self, tag):
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.title_parts.append(data)

    @property
    def title(self):
        value = " ".join("".join(self.title_parts).split())
        return value or None


def fetch(url: str, timeout: float = 8.0, max_bytes: int = 2_000_000) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"})
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(max_bytes)
            return {
                "ok": True,
                "status": getattr(r, "status", 200),
                "final_url": r.geturl(),
                "headers": dict(r.headers.items()),
                "body": body,
                "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
            }
    except urllib.error.HTTPError as e:
        body = e.read(max_bytes) if e.fp else b""
        return {"ok": False, "status": e.code, "final_url": e.geturl(), "headers": dict(e.headers.items()), "body": body, "elapsed_ms": round((time.perf_counter() - started) * 1000, 1), "error": "HTTPError"}
    except Exception as exc:
        return {"ok": False, "status": None, "final_url": url, "headers": {}, "body": b"", "elapsed_ms": round((time.perf_counter() - started) * 1000, 1), "error": exc.__class__.__name__}


def header_lookup(headers: dict, name: str) -> str | None:
    wanted = name.lower()
    for k, v in headers.items():
        if k.lower() == wanted:
            return v
    return None


def analyze_html(body: bytes, content_type: str | None) -> dict:
    if not body:
        return {}
    charset = "utf-8"
    if content_type and "charset=" in content_type.lower():
        charset = content_type.lower().split("charset=", 1)[1].split(";", 1)[0].strip()
    try:
        text = body.decode(charset, errors="replace")
    except LookupError:
        text = body.decode("utf-8", errors="replace")
    p = PageParser()
    try:
        p.feed(text)
    except Exception:
        pass
    return {
        "title": p.title,
        "meta_description": p.meta.get("description"),
        "canonical": p.canonical,
        "lang": p.lang,
        "h1_count": p.h1_count,
        "images": p.images,
        "images_without_alt": p.images_without_alt,
        "open_graph": {
            "title": p.meta.get("og:title"),
            "description": p.meta.get("og:description"),
            "image": p.meta.get("og:image"),
        },
    }


def resource_check(url: str) -> dict:
    r = fetch(url, timeout=5, max_bytes=32_000)
    return {"url": url, "status": r.get("status"), "ok": bool(r.get("status") and 200 <= r["status"] < 400), "elapsed_ms": r.get("elapsed_ms")}


def build_score(http: dict, seo: dict, sec: dict, resources: dict) -> int:
    score = 0
    if http.get("status") and 200 <= http["status"] < 400: score += 20
    if http.get("https"): score += 15
    if seo.get("title"): score += 10
    if seo.get("meta_description"): score += 10
    if seo.get("canonical"): score += 5
    if seo.get("h1_count") == 1: score += 5
    if seo.get("images", 0) == 0 or seo.get("images_without_alt", 0) == 0: score += 5
    score += sum(4 for key in ("hsts", "csp", "nosniff", "referrer_policy", "frame_protection") if sec.get(key))
    if resources.get("robots", {}).get("ok"): score += 5
    if resources.get("sitemap", {}).get("ok"): score += 5
    return min(score, 100)


def self_test_report() -> dict:
    sample = b'<html lang="es"><head><title>Demo</title><meta name="description" content="x"><link rel="canonical" href="https://example.com"></head><body><h1>Hola</h1><img src="x" alt="x"></body></html>'
    seo = analyze_html(sample, "text/html; charset=utf-8")
    return {"schema": SCHEMA, "self_test": True, "seo": seo}


def audit(target: str, light: bool) -> dict:
    parsed = urllib.parse.urlparse(target)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("La URL debe comenzar con http:// o https://")
    r = fetch(target)
    headers = r.get("headers", {})
    final_url = r.get("final_url") or target
    content_type = header_lookup(headers, "Content-Type")
    seo = analyze_html(r.get("body", b""), content_type) if content_type is None or "html" in content_type.lower() else {}
    csp = header_lookup(headers, "Content-Security-Policy")
    security_headers = {
        "hsts": bool(header_lookup(headers, "Strict-Transport-Security")),
        "csp": bool(csp),
        "nosniff": (header_lookup(headers, "X-Content-Type-Options") or "").lower() == "nosniff",
        "referrer_policy": bool(header_lookup(headers, "Referrer-Policy")),
        "permissions_policy": bool(header_lookup(headers, "Permissions-Policy")),
        "frame_protection": bool(header_lookup(headers, "X-Frame-Options")) or bool(csp and "frame-ancestors" in csp.lower()),
    }
    base = urllib.parse.urljoin(final_url, "/")
    resources = {}
    if not light:
        resources = {
            "robots": resource_check(urllib.parse.urljoin(base, "robots.txt")),
            "sitemap": resource_check(urllib.parse.urljoin(base, "sitemap.xml")),
        }
    http = {
        "status": r.get("status"),
        "ok": bool(r.get("status") and 200 <= r["status"] < 400),
        "final_url": final_url,
        "https": urllib.parse.urlparse(final_url).scheme == "https",
        "elapsed_ms": r.get("elapsed_ms"),
        "content_type": content_type,
        "error": r.get("error"),
    }
    return {
        "schema": SCHEMA,
        "generated_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "target": target,
        "http": http,
        "security_headers": security_headers,
        "seo": seo,
        "resources": resources,
        "summary": {"score": build_score(http, seo, security_headers, resources), "note": "orientative technical score; not a penetration test or Lighthouse score"},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="MiWeb: auditoría pública no intrusiva de una URL")
    parser.add_argument("url", nargs="?")
    parser.add_argument("--light", action="store_true")
    parser.add_argument("--output")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--compact", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        report = self_test_report()
    else:
        if not args.url:
            parser.error("falta URL")
        report = audit(args.url, args.light)
    text = json.dumps(report, ensure_ascii=False, indent=None if args.compact else 2)
    print(text)
    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
