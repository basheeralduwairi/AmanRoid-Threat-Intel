import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("pipeline", ROOT / "scripts/pipeline.py")
pipeline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pipeline)


def source():
    return {
        "id": "ncsc-jordan",
        "host": "ncsc.jo",
        "allowed_hosts": ["ncsc.jo"],
        "country": "JO",
    }


def approved_record(**overrides):
    record = {
        "id": "demo-1",
        "title_ar": "تنبيه توعوي تجريبي",
        "summary_ar": "ملخص مصدر رسمي للمراجعة.",
        "guidance_ar": "تحقق من المصدر الأصلي ولا تشارك الرموز.",
        "category": "phishing",
        "country": "JO",
        "source_id": "ncsc-jordan",
        "source_url": "https://ncsc.jo/advisory/demo",
        "published_at": "2026-11-15T10:00:00Z",
        "publication_date_status": "observed",
        "evidence": [{
            "original_url": "https://ncsc.jo/advisory/demo",
            "retrieved_at": "2026-11-16T08:00:00Z",
            "published_at": "2026-11-15",
            "content_sha256": "abc",
        }],
        "evidence_status": "general_awareness",
        "geographic_relevance": "unknown",
        "confidence": {"level": "medium", "score": None, "rationale": "مصدر رسمي، لكن لا يثبت نشاطاً محلياً."},
        "active_in_jordan": None,
        "lifecycle": {"status": "current"},
        "review": {"status": "human_approved", "reviewed_by": "reviewer", "reviewed_at": "2026-11-16T09:00:00Z"},
    }
    record.update(overrides)
    return record


class PipelineTests(unittest.TestCase):
    def test_allowlist_rejects_scheme_credentials_and_host_confusion(self):
        src = source()
        self.assertTrue(pipeline.is_allowed("https://ncsc.jo/advisory", src))
        self.assertTrue(pipeline.is_allowed("https://sub.ncsc.jo/advisory", {**src, "allowed_hosts": ["sub.ncsc.jo", "ncsc.jo"]}))
        self.assertFalse(pipeline.is_allowed("http://ncsc.jo/advisory", src))
        self.assertFalse(pipeline.is_allowed("https://ncsc.jo.evil.example/advisory", src))
        self.assertFalse(pipeline.is_allowed("https://user:pass@ncsc.jo/advisory", src))

    def test_ai_or_unreviewed_record_cannot_publish(self):
        record = approved_record(review={"status": "ai_draft_pending"})
        with self.assertRaisesRegex(ValueError, "human-approved"):
            pipeline.validated(record, {"ncsc-jordan": source()})

    def test_active_jordan_claim_requires_confirmed_evidence(self):
        record = approved_record(active_in_jordan=True, geographic_relevance="confirmed_jordan")
        with self.assertRaisesRegex(ValueError, "confirmed official"):
            pipeline.validated(record, {"ncsc-jordan": source()})
        record["evidence_status"] = "confirmed_official_advisory"
        self.assertEqual(pipeline.validated(record, {"ncsc-jordan": source()})["active_in_jordan"], True)

    def test_missing_publication_date_is_explicit(self):
        record = approved_record(published_at=None, publication_date_status="unknown")
        result = pipeline.validated(record, {"ncsc-jordan": source()})
        self.assertEqual(result["freshness"]["status"], "unknown")
        record["publication_date_status"] = "observed"
        with self.assertRaisesRegex(ValueError, "publication dates"):
            pipeline.validated(record, {"ncsc-jordan": source()})

    def test_historical_freshness_is_not_current(self):
        record = approved_record(lifecycle={"status": "historical"})
        self.assertEqual(pipeline.freshness_for(record)["status"], "historical")

    def test_publish_rejects_duplicate_source_date(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "config").mkdir()
            (root / "review").mkdir()
            (root / "site/data").mkdir(parents=True)
            pipeline.write_json(root / "config/sources.json", {"sources": [source()]})
            first = approved_record()
            second = approved_record(id="demo-2")
            pipeline.write_json(root / "review/approved.json", {"advisories": [first, second]})
            pipeline.write_json(root / "review/source-status.json", {"sources": []})
            old_root = pipeline.ROOT
            pipeline.ROOT = root
            try:
                with self.assertRaisesRegex(ValueError, "Duplicate advisory"):
                    pipeline.publish()
            finally:
                pipeline.ROOT = old_root

    def test_stale_advisory_cannot_be_published_as_active(self):
        record = approved_record(
            published_at="2020-01-01T00:00:00Z",
            evidence_status="confirmed_official_advisory",
            geographic_relevance="confirmed_jordan",
            active_in_jordan=True,
            lifecycle={"status": "historical"},
        )
        with self.assertRaisesRegex(ValueError, "Outdated"):
            pipeline.validated(record, {"ncsc-jordan": source()})

    def test_lifecycle_for_old_source_is_historical(self):
        self.assertEqual(pipeline.lifecycle_for("2020-01-01T00:00:00Z")["status"], "historical")

    def test_empty_publish_is_valid_and_nonfictional(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "config").mkdir()
            (root / "review").mkdir()
            (root / "site/data").mkdir(parents=True)
            pipeline.write_json(root / "config/sources.json", {"sources": [source()]})
            pipeline.write_json(root / "review/approved.json", {"advisories": []})
            old_root = pipeline.ROOT
            pipeline.ROOT = root
            try:
                pipeline.publish()
                feed = pipeline.load(root / "site/data/advisories.json")
                self.assertEqual(feed["feed_status"], "awaiting_reviewed_advisories")
                self.assertEqual(feed["advisories"], [])
                self.assertTrue(feed["publication"]["human_approval_required"])
            finally:
                pipeline.ROOT = old_root


if __name__ == "__main__":
    unittest.main()
