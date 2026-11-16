#!/usr/bin/env python3
"""Discover public links from explicitly approved sites and publish reviewed advisories.

No LLM/AI claims, no automatic authoritative security findings; advisory publication
requires an explicit reviewer-approved record in review/approved.json.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
import hashlib
import json
import re
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
ALLOWED_CATEGORIES = {"phishing", "financial_fraud", "malicious_apps", "account_takeover", "general"}
CATEGORY_AR = {"phishing": "التصيد الإلكتروني", "financial_fraud": "الاحتيال المالي", "malicious_apps": "التطبيقات الضارة", "account_takeover": "اختراق الحسابات", "general": "تنبيهات عامة"}
KEYWORDS = ("تحذير", "احتيال", "تصيد", "تطبيق", "اختراق", "تنبيه", "تحذيرات", "الأمن", "الاحتيال", "تهديد", "alerts", "threat", "fraud", "phish", "cyber")
UA = "AmanRoidThreatIntel/0.1 (public-links-only; respectful collection)"

def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))

def write_json(path, obj):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.out = []
        self.href = None
        self.parts = []
    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self.href = dict(attrs).get("href")
            self.parts = []
    def handle_data(self, data):
        if self.href is not None:
            self.parts.append(data)
    def handle_endtag(self, tag):
        if tag == "a" and self.href is not None:
            self.out.append((self.href, " ".join(" ".join(self.parts).split())))
            self.href = None
            self.parts = []

def is_allowed(url, source):
    p = urllib.parse.urlsplit(url)
    host = p.hostname or ""
    approved = source["host"].lower()
    return p.scheme == "https" and (host == approved or host.endswith("." + approved)) and p.username is None and p.password is None

def discover():
    sources = load(ROOT / "config/sources.json")["sources"]
    candidate_map = {}
    errors = []
    for source in sources:
        if not source["enabled"]:
            continue
        if not is_allowed(source["url"], source):
            errors.append({"source_id": source["id"], "error": "Invalid source URL or host"})
            continue
        try:
            req = urllib.request.Request(source["url"], headers={"User-Agent": UA, "Accept": "text/html"})
            with urllib.request.urlopen(req, timeout=15) as response:
                if not is_allowed(response.url, source):
                    raise ValueError("Cross-host redirect not allowed")
                if "text/html" not in response.headers.get("Content-Type", "").lower():
                    raise ValueError("Unexpected media type")
                html = response.read(1_000_001)
                if len(html) > 1_000_000:
                    raise ValueError("Response too large")
            parser = Links()
            parser.feed(html.decode("utf-8", errors="replace"))
            for href, title in parser.out:
                url = urllib.parse.urljoin(source["url"], href)
                if not is_allowed(url, source):
                    continue
                p = urllib.parse.urlsplit(url)
                url = urllib.parse.urlunsplit((p.scheme, p.netloc, p.path, p.query, ""))
                if url == source["url"] or not title or not any(term in title.lower() for term in KEYWORDS):
                    continue
                identity = hashlib.sha256(url.encode()).hexdigest()[:18]
                candidate_map[identity] = {"id": identity, "source_id": source["id"], "title_from_page": title[:220], "url": url, "status": "pending_review"}
        except Exception as exc:
            errors.append({"source_id":source["id"], "error":f"{type(exc).__name__}: {str(exc)[:180]}"})
    # Candidate list is unverified; it is never exposed as confirmed advisories.
    output = {"collected_at": datetime.now(timezone.utc).isoformat(), "candidates": sorted(candidate_map.values(), key=lambda x:x["id"]), "errors": errors}
    write_json(ROOT / "review/candidates.json", output)
    print(f"Discovered {len(candidate_map)} unverified links; source errors: {len(errors)}")

def validated(record, sources):
    mandatory = ("id", "title_ar", "summary_ar", "guidance_ar", "category", "country", "source_id", "source_url", "published_at", "reviewed_at", "reviewed_by", "evidence_status")
    for field in mandatory:
        if not isinstance(record.get(field), str) or not record[field].strip():
            raise ValueError(f"Missing/invalid field {field}")
    if record["category"] not in ALLOWED_CATEGORIES:
        raise ValueError("Invalid category")
    if record["country"] != "JO":
        raise ValueError("Only JO enabled in MVP")
    if record["evidence_status"] not in ("confirmed_official_advisory", "general_awareness"):
        raise ValueError("Unsupported evidence status")
    src = sources.get(record["source_id"])
    if not src or not is_allowed(record["source_url"], src):
        raise ValueError("Source URL outside allowlist")
    for date_field in ("published_at", "reviewed_at"):
        datetime.fromisoformat(record[date_field].replace("Z", "+00:00"))
    if record.get("active_in_jordan") is True and record["evidence_status"] != "confirmed_official_advisory":
        raise ValueError("Local active claims must be tied to confirmed official evidence")
    return {key: record[key] for key in mandatory} | {"category_ar": CATEGORY_AR[record["category"]], "active_in_jordan":record.get("active_in_jordan", False)}

def publish():
    sources = {s["id"]:s for s in load(ROOT / "config/sources.json")["sources"]}
    approved = load(ROOT / "review/approved.json")["advisories"]
    ids = set()
    result = []
    for item in approved:
        entry = validated(item, sources)
        if entry["id"] in ids:
            raise ValueError("Duplicate advisory id")
        ids.add(entry["id"])
        result.append(entry)
    result.sort(key=lambda x:x["published_at"], reverse=True)
    output = {"schema_version":1, "country":"JO", "generated_at":datetime.now(timezone.utc).isoformat(), "status":"ready" if result else "awaiting_reviewed_advisories", "disclaimer_ar":"هذه ملخصات توعوية تستند إلى مصادر منشورة، وليست إشعارات حكومية رسمية. تحقق من المصدر الأصلي وتاريخ النشر.", "advisories":result}
    write_json(ROOT / "site/data/advisories.json", output)
    print(f"Published {len(result)} reviewed advisories")

def main():
    p=argparse.ArgumentParser()
    p.add_argument("command", choices=("discover", "publish"))
    args=p.parse_args()
    (discover if args.command == "discover" else publish)()
if __name__ == "__main__":
    main()
