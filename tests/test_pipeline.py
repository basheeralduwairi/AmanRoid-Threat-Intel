import importlib.util
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('pipeline',ROOT/'scripts/pipeline.py')
pipeline=importlib.util.module_from_spec(spec)
spec.loader.exec_module(pipeline)
class PipelineTests(unittest.TestCase):
    def test_allowlisted_host(self):
        src={'host':'ncsc.jo'}
        self.assertTrue(pipeline.is_allowed('https://www.ncsc.jo/AR/List/Security_Warnings_AR',src))
        self.assertFalse(pipeline.is_allowed('https://ncsc.jo.evil.example/x',src))
        self.assertFalse(pipeline.is_allowed('http://ncsc.jo/x',src))
        self.assertFalse(pipeline.is_allowed('https://example.com/x',src))
    def test_publish_requires_review(self):
        sources={'ncsc-jordan':{'host':'ncsc.jo'}}
        base={'id':'demo','title_ar':'مثال','summary_ar':'ملخص','guidance_ar':'إرشادات','category':'phishing','country':'JO','source_id':'ncsc-jordan','source_url':'https://ncsc.jo/AR/List/Security_Warnings_AR','published_at':'2026-11-15T10:00:00Z','reviewed_at':'2026-11-16T08:00:00Z','reviewed_by':'reviewer','evidence_status':'general_awareness'}
        result=pipeline.validated(base,sources)
        self.assertFalse(result['active_in_jordan'])
        base['active_in_jordan']=True
        with self.assertRaises(ValueError):pipeline.validated(base,sources)
    def test_production_initially_empty(self):
        self.assertEqual(pipeline.load(ROOT/'review/approved.json')['advisories'],[])
if __name__=='__main__':unittest.main()
