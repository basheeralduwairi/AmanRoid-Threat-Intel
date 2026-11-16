#!/usr/bin/env python3
"""Collect, validate, and publish review-gated Jordan security advisories.

Remote HTML is untrusted evidence. The collector never publishes collected
text or AI output; publication is limited to explicitly human-approved
records in ``review/approved.json``.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from html.parser import HTMLParser
import hashlib
import json
from pathlib import Path
import re
import time
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_VERSION = 2
MAX_INDEX_BYTES = 1_000_000
MAX_ARTICLE_BYTES = 1_500_000
MAX_CANDIDATES_PER_SOURCE = 20
UA = "AmanRoidThreatIntel/1.0 (+review-gated; public-links-only)"
ALLOWED_CATEGORIES = {"phishing", "financial_fraud", "malicious_apps", "account_takeover", "general"}
CATEGORY_AR = {
    "phishing": "التصيد الإلكتروني",
    "financial_fraud": "الاحتيال المالي",
    "malicious_apps": "التطبيقات الضارة",
    "account_takeover": "اختراق الحسابات",
    "general": "تنبيهات عامة",
}
GEOGRAPHIC_RELEVANCE = {"confirmed_jordan", "potentially_relevant_global", "not_jordan_specific", "unknown"}
CONFIDENCE_LEVELS = {"high", "medium", "low", "unassessed"}
KEYWORDS = (
    "تحذير", "احتيال", "تصيد", "تطبيق", "اختراق", "تنبيه", "تحذيرات", "الأمن",
    "الاحتيال", "تهديد", "alerts", "threat", "fraud", "phish", "cyber",
)


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load(path: str | Path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json(path: str | Path, obj) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def parse_datetime(value: str | None) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def source_hosts(source: dict) -> set[str]:
    return {str(host).lower().strip().rstrip(".") for host in source.get("allowed_hosts", [source.get("host", "")]) if host}


def canonical_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(url.strip())
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        return ""
    host = parsed.hostname.lower().rstrip(".")
    port = parsed.port
    netloc = host if port in (None, 443) else f"{host}:{port}"
    path = parsed.path or "/"
    if path != "/":
        path = re.sub(r"/{2,}", "/", path).rstrip("/") or "/"
    query = urllib.parse.urlencode(sorted(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)))
    return urllib.parse.urlunsplit(("https", netloc, path, query, ""))


def is_allowed(url: str, source: dict) -> bool:
    parsed = urllib.parse.urlsplit(url)
    host = (parsed.hostname or "").lower().rstrip(".")
    return (
        parsed.scheme.lower() == "https"
        and host in source_hosts(source)
        and parsed.username is None
        and parsed.password is None
        and canonical_url(url) != ""
    )


class LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[tuple[str, str]] = []
        self._href: str | None = None
        self._parts: list[str] = []

    def handle_starttag(self, tag, attrs) -> None:
        if tag.lower() == "a":
            self._href = dict(attrs).get("href")
            self._parts = []

    def handle_data(self, data) -> None:
        if self._href is not None:
            self._parts.append(data)

    def handle_endtag(self, tag) -> None:
        if tag.lower() == "a" and self._href is not None:
            self.links.append((self._href, " ".join(" ".join(self._parts).split())))
            self._href = None
            self._parts = []


class ArticleParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []
        self.title_parts: list[str] = []
        self.meta_dates: list[str] = []
        self._skip = 0
        self._in_title = False

    def handle_starttag(self, tag, attrs) -> None:
        tag = tag.lower()
        attrs_map = dict(attrs)
        if tag in {"script", "style", "noscript", "svg", "template"}:
            self._skip += 1
        if tag == "title":
            self._in_title = True
        if tag in {"meta", "time"}:
            value = attrs_map.get("content") or attrs_map.get("datetime")
            key = (attrs_map.get("property") or attrs_map.get("name") or "").lower()
            if value and ("date" in key or "published" in key or "time" in key):
                self.meta_dates.append(value.strip())

    def handle_endtag(self, tag) -> None:
        tag = tag.lower()
        if tag in {"script", "style", "noscript", "svg", "template"} and self._skip:
            self._skip -= 1
        if tag == "title":
            self._in_title = False

    def handle_data(self, data) -> None:
        if self._skip:
            return
        value = " ".join(data.split())
        if value:
            self.parts.append(value)
            if self._in_title:
                self.title_parts.append(value)


def extract_date(values: list[str]) -> str | None:
    for value in values:
        match = re.search(r"20\d{2}[-/]\d{1,2}[-/]\d{1,2}", value)
        if match:
            raw = match.group(0).replace("/", "-")
            try:
                return datetime.strptime(raw, "%Y-%m-%d").date().isoformat()
            except ValueError:
                pass
    return None


def fetch_public(url: str, source: dict, max_bytes: int) -> dict:
    if not is_allowed(url, source):
        raise ValueError("URL is outside the configured HTTPS source allowlist")
    request = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "text/html,application/xhtml+xml"})
    started = time.monotonic()
    with urllib.request.urlopen(request, timeout=20) as response:
        final_url = response.geturl()
        content_type = response.headers.get("Content-Type", "").lower()
        if not is_allowed(final_url, source):
            raise ValueError("Cross-host redirect is not allowed")
        if "text/html" not in content_type and "application/xhtml" not in content_type:
            raise ValueError("Unexpected source media type")
        body = response.read(max_bytes + 1)
        if len(body) > max_bytes:
            raise ValueError("Source response exceeded the configured size limit")
        return {
            "body": body,
            "final_url": canonical_url(final_url),
            "content_type": content_type,
            "http_status": getattr(response, "status", 200),
            "bytes": len(body),
            "latency_ms": round((time.monotonic() - started) * 1000),
        }


def extract_article(url: str, source: dict) -> dict:
    fetched = fetch_public(url, source, MAX_ARTICLE_BYTES)
    parser = ArticleParser()
    parser.feed(fetched["body"].decode("utf-8", errors="replace"))
    text = " ".join(parser.parts)
    return {
        "original_url": fetched["final_url"],
        "retrieved_at": now_iso(),
        "published_at": extract_date(parser.meta_dates),
        "title": " ".join(parser.title_parts)[:300],
        "excerpt": text[:4000],
        "content_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "content_type": fetched["content_type"],
        "bytes": fetched["bytes"],
        "latency_ms": fetched["latency_ms"],
    }


def candidate_id(source_id: str, url: str) -> str:
    return hashlib.sha256(f"{source_id}|{url}".encode("utf-8")).hexdigest()[:24]


def discover() -> None:
    configured = load(ROOT / "config/sources.json")
    sources = configured.get("sources", [])
    candidates: dict[str, dict] = {}
    fingerprints: dict[str, str] = {}
    failures: list[dict] = []
    source_status: list[dict] = []

    for source in sources:
        source_id = source.get("id", "unknown")
        status = {
            "source_id": source_id,
            "name_ar": source.get("name_ar", source_id),
            "url": source.get("url"),
            "checked_at": now_iso(),
            "status": "disabled" if not source.get("enabled", False) else "pending",
            "candidate_count": 0,
            "article_failures": 0,
            "error": None,
        }
        if not source.get("enabled", False):
            source_status.append(status)
            continue
        if not is_allowed(source.get("url", ""), source):
            status.update(status="failed", error="Invalid configured source URL or host")
            failures.append({"source_id": source_id, "error": status["error"]})
            source_status.append(status)
            continue
        try:
            index = fetch_public(source["url"], source, MAX_INDEX_BYTES)
            parser = LinkParser()
            parser.feed(index["body"].decode("utf-8", errors="replace"))
            status.update(
                status="ok",
                final_url=index["final_url"],
                http_status=index["http_status"],
                content_type=index["content_type"],
                bytes=index["bytes"],
                latency_ms=index["latency_ms"],
            )
            seen_urls: set[str] = set()
            eligible = []
            for href, title in parser.links:
                url = canonical_url(urllib.parse.urljoin(source["url"], href or ""))
                if not url or url in seen_urls or url == canonical_url(source["url"]):
                    continue
                if not title or not any(keyword in title.lower() for keyword in KEYWORDS) or not is_allowed(url, source):
                    continue
                seen_urls.add(url)
                eligible.append((url, title[:300]))
                if len(eligible) >= int(source.get("max_candidates", MAX_CANDIDATES_PER_SOURCE)):
                    break
            for url, title in eligible:
                evidence = {
                    "original_url": url,
                    "discovered_from_url": canonical_url(source["url"]),
                    "discovered_title": title,
                    "retrieved_at": now_iso(),
                    "published_at": None,
                    "title": title,
                    "excerpt": "",
                    "content_sha256": None,
                }
                try:
                    if source.get("collect_article", True):
                        evidence.update(extract_article(url, source))
                except Exception as exc:
                    status["article_failures"] += 1
                    evidence["collection_error"] = f"{type(exc).__name__}: {str(exc)[:180]}"
                fingerprint = evidence.get("content_sha256") or url
                item_id = candidate_id(source_id, url)
                duplicate_of = fingerprints.get(fingerprint)
                if not duplicate_of:
                    fingerprints[fingerprint] = item_id
                candidates[item_id] = {
                    "schema_version": SCHEMA_VERSION,
                    "id": item_id,
                    "source_id": source_id,
                    "source_name_ar": source.get("name_ar", source_id),
                    "source_country": source.get("country", "unknown"),
                    "source_trust_level": source.get("trust_level", "unassessed"),
                    "source_url": url,
                    "title_from_source": title,
                    "evidence": [evidence],
                    "published_at": evidence.get("published_at"),
                    "publication_date_status": "observed" if evidence.get("published_at") else "unknown",
                    "geographic_relevance": "unknown",
                    "confidence": {"level": "unassessed", "score": None, "rationale": "لم تُراجع المادة بعد من محرر بشري."},
                    "review": {"status": "ai_draft_pending", "reviewed_by": None, "reviewed_at": None},
                    "lifecycle": {"status": "current", "first_seen_at": now_iso(), "last_seen_at": now_iso()},
                    "status": "duplicate" if duplicate_of else "pending_review",
                    "duplicate_of": duplicate_of,
                }
            status["candidate_count"] = len(eligible)
        except Exception as exc:
            status.update(status="failed", error=f"{type(exc).__name__}: {str(exc)[:180]}")
            failures.append({"source_id": source_id, "error": status["error"]})
        source_status.append(status)

    collected_at = now_iso()
    write_json(ROOT / "review/candidates.json", {
        "schema_version": SCHEMA_VERSION,
        "collected_at": collected_at,
        "status": "completed_with_failures" if failures else "completed",
        "candidates": sorted(candidates.values(), key=lambda item: item["id"]),
        "source_failures": failures,
    })
    write_json(ROOT / "review/source-status.json", {"schema_version": 1, "checked_at": collected_at, "sources": source_status})
    print(f"Collected {len(candidates)} evidence records; source failures: {len(failures)}")


def _require_text(record: dict, field: str) -> str:
    value = record.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Missing/invalid field {field}")
    return value.strip()


def freshness_for(record: dict, evaluated_at: str | None = None) -> dict:
    evaluated = parse_datetime(evaluated_at) or datetime.now(timezone.utc)
    lifecycle = record.get("lifecycle") if isinstance(record.get("lifecycle"), dict) else {}
    if lifecycle.get("status") == "historical":
        return {"status": "historical", "reason_ar": "سجل تاريخي معتمد، وليس دليلاً على نشاط حالي."}
    expires = parse_datetime(record.get("expires_at"))
    published = parse_datetime(record.get("published_at"))
    if expires:
        return {"status": "stale" if expires < evaluated else "fresh", "expires_at": record.get("expires_at"), "reason_ar": "انتهت مدة صلاحية هذا السجل." if expires < evaluated else "ضمن مدة الصلاحية المحددة."}
    if not published:
        return {"status": "unknown", "reason_ar": "لا يوجد تاريخ نشر قابل للتحقق."}
    max_age = int(record.get("freshness_max_age_days", 30))
    age_days = max(0, (evaluated - published).days)
    stale = age_days > max_age
    return {"status": "stale" if stale else "fresh", "age_days": age_days, "max_age_days": max_age, "reason_ar": "قديمة زمنياً؛ لا تُعرض كتحذير حالي." if stale else "ضمن مدة الحداثة المحددة."}


def validated(record: dict, sources: dict[str, dict], require_approved: bool = True) -> dict:
    for field in ("id", "title_ar", "summary_ar", "guidance_ar", "category", "country", "source_id"):
        _require_text(record, field)
    if record["category"] not in ALLOWED_CATEGORIES:
        raise ValueError("Invalid category")
    if record["country"] != "JO":
        raise ValueError("Only JO-enabled records can be published")
    source = sources.get(record["source_id"])
    if not source:
        raise ValueError("Unknown source_id")
    source_url = _require_text(record, "source_url")
    if not is_allowed(source_url, source):
        raise ValueError("Source URL outside the configured allowlist")
    published_at = record.get("published_at")
    if published_at is not None and parse_datetime(published_at) is None:
        raise ValueError("Invalid published_at")
    if published_at is None and record.get("publication_date_status") != "unknown":
        raise ValueError("Unknown publication dates must be explicitly labelled")
    evidence = record.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        raise ValueError("At least one evidence record is required")
    for item in evidence:
        if not isinstance(item, dict) or not is_allowed(item.get("original_url", ""), source):
            raise ValueError("Evidence contains a URL outside the source allowlist")
        if parse_datetime(item.get("retrieved_at")) is None:
            raise ValueError("Evidence must preserve retrieved_at")
    if record.get("geographic_relevance") not in GEOGRAPHIC_RELEVANCE:
        raise ValueError("Invalid geographic_relevance")
    confidence = record.get("confidence")
    if not isinstance(confidence, dict) or confidence.get("level") not in CONFIDENCE_LEVELS:
        raise ValueError("Invalid confidence indicator")
    review = record.get("review")
    if not isinstance(review, dict):
        raise ValueError("Review record is required")
    if require_approved and review.get("status") != "human_approved":
        raise ValueError("Only explicitly human-approved records can be published")
    if require_approved:
        _require_text(review, "reviewed_by")
        if parse_datetime(review.get("reviewed_at")) is None:
            raise ValueError("Human approval requires reviewed_at")
    active = record.get("active_in_jordan")
    if active is True and (record.get("evidence_status") != "confirmed_official_advisory" or record.get("geographic_relevance") != "confirmed_jordan"):
        raise ValueError("Active Jordan claims require confirmed official evidence")
    if active not in (True, False, None):
        raise ValueError("active_in_jordan must be true, false, or null")
    entry = dict(record)
    entry["schema_version"] = SCHEMA_VERSION
    entry["category_ar"] = CATEGORY_AR[record["category"]]
    entry["freshness"] = freshness_for(record)
    entry["publication"] = {"status": "approved", "approved_at": review.get("reviewed_at"), "approved_by": review.get("reviewed_by")}
    return entry


def publish() -> None:
    configured = load(ROOT / "config/sources.json")
    sources = {item["id"]: item for item in configured.get("sources", [])}
    approved = load(ROOT / "review/approved.json").get("advisories", [])
    result: list[dict] = []
    ids: set[str] = set()
    fingerprints: set[str] = set()
    for item in approved:
        entry = validated(item, sources, require_approved=True)
        if entry["id"] in ids:
            raise ValueError(f"Duplicate advisory id: {entry['id']}")
        fingerprint = hashlib.sha256(f"{entry['source_id']}|{canonical_url(entry['source_url'])}|{entry.get('published_at')}".encode()).hexdigest()
        if fingerprint in fingerprints:
            raise ValueError(f"Duplicate advisory source/date fingerprint: {entry['id']}")
        ids.add(entry["id"])
        fingerprints.add(fingerprint)
        result.append(entry)
    generated_at = now_iso()
    result.sort(key=lambda item: item.get("published_at") or "", reverse=True)
    current = [item for item in result if item["lifecycle"].get("status") != "historical"]
    historical = [item for item in result if item["lifecycle"].get("status") == "historical"]
    source_status = load(ROOT / "review/source-status.json") if (ROOT / "review/source-status.json").exists() else {"sources": []}
    output = {
        "schema_version": SCHEMA_VERSION,
        "country": "JO",
        "feed_status": "ready" if result else "awaiting_reviewed_advisories",
        "generated_at": generated_at,
        "publication": {"reviewed_count": len(result), "current_count": len(current), "historical_count": len(historical), "human_approval_required": True},
        "collection": {"last_checked_at": source_status.get("checked_at"), "source_status": source_status.get("sources", [])},
        "disclaimer_ar": "هذه ملخصات توعوية تستند إلى مصادر منشورة ومراجعة بشرياً، وليست إشعارات حكومية رسمية. تحقق من المصدر الأصلي وتاريخ النشر وحالة الحداثة.",
        "advisories": result,
    }
    write_json(ROOT / "site/data/advisories.json", output)
    history_path = ROOT / "review/history.json"
    history = load(history_path).get("records", []) if history_path.exists() else []
    history_by_id = {item.get("id"): item for item in history if item.get("id")}
    for item in result:
        old = history_by_id.get(item["id"], {})
        history_by_id[item["id"]] = {"id": item["id"], "first_published_at": old.get("first_published_at", generated_at), "last_published_at": generated_at, "lifecycle_status": item["lifecycle"].get("status", "current"), "source_url": item["source_url"], "reviewed_by": item["review"].get("reviewed_by")}
    write_json(history_path, {"schema_version": 1, "records": sorted(history_by_id.values(), key=lambda x: x["id"])})
    print(f"Published {len(result)} reviewed advisories; current={len(current)} historical={len(historical)}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("discover", "publish"))
    args = parser.parse_args()
    discover() if args.command == "discover" else publish()


if __name__ == "__main__":
    main()
