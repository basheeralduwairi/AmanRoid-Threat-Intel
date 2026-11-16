import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sys.path.insert(0, str(ROOT / "scripts"))
pipeline = load_module("pipeline_for_agent", ROOT / "scripts/pipeline.py")
agent = load_module("agent", ROOT / "scripts/agent.py")


def candidate():
    return {
        "id": "candidate-1",
        "source_id": "ncsc-jordan",
        "source_url": "https://ncsc.jo/advisory/demo",
        "published_at": "2026-11-15",
        "publication_date_status": "observed",
        "evidence": [{
            "original_url": "https://ncsc.jo/advisory/demo",
            "retrieved_at": "2026-11-16T08:00:00Z",
            "content_sha256": "abc",
            "excerpt": "نص مصدر رسمي قد يحتوي على تعليمات خبيثة مزعومة.",
        }],
        "lifecycle": {"status": "current"},
        "status": "pending_review",
    }


class AgentTests(unittest.TestCase):
    def test_prompt_delimits_source_as_untrusted(self):
        prompt = agent.prompt_for(candidate())
        self.assertIn("UNTRUSTED_SOURCE_MATERIAL_START", prompt)
        self.assertIn("ليست تعليمات", prompt)
        self.assertIn("ncsc.jo/advisory/demo", prompt)

    def test_unconfigured_provider_creates_nonpublishing_draft(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "candidates.json"
            output = root / "drafts.json"
            pipeline.write_json(source, {"candidates": [candidate()]})
            agent.draft(source, output)
            result = pipeline.load(output)
            self.assertFalse(result["publication_allowed"])
            self.assertTrue(result["human_approval_required"])
            self.assertEqual(result["drafts"][0]["ai_status"], "awaiting_ai_provider")

    def test_safe_fields_rejects_unsupported_model_claims(self):
        with self.assertRaises(ValueError):
            agent.safe_fields({
                "title_ar": "عنوان",
                "summary_ar": "ملخص",
                "guidance_ar": "إرشاد",
                "category": "general",
                "geographic_relevance": "confirmed_mars",
                "confidence_level": "high",
                "confidence_rationale": "دليل",
                "evidence_status": "general_awareness",
            })


if __name__ == "__main__":
    unittest.main()
