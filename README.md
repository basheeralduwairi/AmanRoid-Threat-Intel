# AmanRoid Threat Intelligence — Jordan

Public Arabic RTL advisory site and read-only JSON feed for AmanRoid. The
repository is deliberately separate from the Android application.

## Safety boundary

- Only configured HTTPS allowlisted sources are collected.
- Remote HTML is untrusted evidence; source text cannot issue instructions to
  the collector or AI agent.
- Discovery writes an unverified queue. The optional AI agent writes Arabic
  drafts only; it cannot publish and has no GitHub write credential.
- `review/approved.json` is the sole publication input. Every published record
  requires an explicit human approval record, preserved evidence, source URL,
  dates, geography, confidence, and review status.
- An empty approved set produces a valid empty feed. No simulated or fictional
  threat is published.

## Local commands

Requires Python 3.10+ and the standard library only:

```bash
python scripts/pipeline.py discover
python scripts/agent.py draft
python -m unittest discover -s tests -v
python scripts/pipeline.py publish
python -m http.server --directory site 8000
```

`discover` may access the configured official public pages. It records source
status, collection failures, article evidence, publication-date observations,
content hashes, duplicate relationships, and an unverified candidate queue.

`agent.py` uses no provider by default. To enable an explicitly approved
OpenAI-compatible endpoint locally or in GitHub Actions, provide secrets or
environment variables without committing them:

```text
THREAT_INTEL_AI_ENDPOINT=https://provider.example/v1/chat/completions
THREAT_INTEL_AI_API_KEY=provided-out-of-band
THREAT_INTEL_AI_MODEL=approved-model-name
```

No paid AI service is enabled in the repository. The endpoint is contacted only
when both endpoint and key are present. Provider failures remain non-published
draft errors.

## Human approval procedure

1. Run the daily discovery workflow or inspect its `jordan-review-queue`
   artifact.
2. Review the original source URL, evidence excerpt/hash, publication date,
   geographic relevance, confidence, and wording.
3. Approve explicitly with the helper after checking the source independently:

   ```bash
   python scripts/review.py approve DRAFT_ID \
     --reviewer "reviewer-id" \
     --notes "Checked the original source and evidence." \
     --confirm-original-source \
     --active-in-jordan unknown
   ```

4. Commit the resulting `review/approved.json` change through a reviewed pull
   request. The Pages workflow validates approval again before deployment.

To reject a candidate without publishing it, use the explicit rejection command
and commit `review/rejections.json` through a pull request:

```bash
python scripts/review.py reject DRAFT_ID \
  --reviewer "reviewer-id" \
  --reason "The record is a navigation page, not an advisory." \
  --confirm-not-publish
```

`review-validation.yml` checks approval/rejection files on pull requests and
rejects conflicting decisions. A rejected record can never be published by the
Pages workflow.

The helper refuses drafts without AI output, evidence hashes, or the explicit
confirmation flag. `active_in_jordan=true` additionally requires confirmed
official evidence and `confirmed_jordan` geographic relevance.

## GitHub Actions and Pages

- `daily-threat-discovery.yml` runs on schedule or manually, collects sources,
  prepares non-publishing drafts, runs tests, and uploads the review queue.
- `publish-site.yml` runs on reviewed changes to `main`, validates every record,
  generates the feed, verifies that every entry is human-approved, and deploys
  `site/` through GitHub Pages.
- Optional Actions configuration uses `THREAT_INTEL_AI_ENDPOINT` and
  `THREAT_INTEL_AI_API_KEY` secrets plus `THREAT_INTEL_AI_MODEL` repository
  variable. These are not required for collection or publication of an empty
  feed.

Website: `https://basheeralduwairi.github.io/AmanRoid-Threat-Intel/`

Feed: `https://basheeralduwairi.github.io/AmanRoid-Threat-Intel/data/advisories.json`

## Flutter integration

See [`docs/FLUTTER_INTEGRATION.md`](docs/FLUTTER_INTEGRATION.md) for HTTPS
retrieval, schema validation, last-known-good caching, stale indicators, and
offline behavior. The Android application remains independent and does not
require this feed for scanning or education features.

## Remaining configuration

- GitHub Pages must be enabled for the repository with the GitHub Actions
  source; the deployment workflow performs the actual deployment.
- An AI provider secret is optional and requires separate approval. Until set,
  the daily workflow records `awaiting_ai_provider` drafts and publishes
  nothing.
- Official sources may change layout or block automated retrieval. The source
  status artifact reports failures; it never treats a failed collection as an
  absence of threats.

## Current source assessment

The initial six-record queue was not publication-ready: five records were
NCSC list/navigation pages and one was the CBJ security-marks navigation page;
the latter also exposed a Unicode URL encoding problem. The collector now
targets NCSC `/ListDetails/...` advisory pages, preserves their original dates,
and uses an in-memory cookie jar plus UTF-8 URL canonicalization for the
official Jo-FinCERT alerts page. The eight NCSC records currently discovered
are genuine official advisory pages but date from 2022, so they are classified
as historical/stale and cannot be approved as active current incidents. The
current Jo-FinCERT alerts section contains no alert detail records.
