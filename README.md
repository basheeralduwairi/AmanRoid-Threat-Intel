# AmanRoid Threat Intelligence — Jordan MVP

**A separate static, review-gated advisory site** intended for AmanRoid Flutter. This is an initial working foundation, **not yet an autonomous AI analyst**. Nothing is automatically asserted to be a verified or currently active Jordanian threat.

## Included
- Official public Jordanian source allowlist (`config/sources.json`).
- Daily GitHub Actions HTML link discovery into an **unverified review artifact**, not into the public advisory feed.
- `review/approved.json` as the sole publication source. Human reviewer must verify content, publication date, source and factual active-in-Jordan status.
- Generated `site/data/advisories.json` and Arabic static HTML page.
- Tests preventing unsafe source domains and unreviewed activation.

## Local use (Python 3.10+, standard library only)
```bash
python scripts/pipeline.py discover   # Network access, public pages only
python scripts/pipeline.py publish    # Never publishes unapproved candidates
python -m unittest discover -s tests -v
python -m http.server --directory site 8000
```

## Deploy
1. Create a **separate repository** for public advisory content (e.g. `AmanRoid-Threat-Intel`) rather than exposing private Android source.
2. Add these files to the new repository. Set its default branch to `main` (or adjust workflow).
3. Enable GitHub Pages with source **GitHub Actions**.
4. Run `Jordan advisory discovery (review required)` manually to inspect a candidate artifact.
5. Verify any actual advisory from authoritative original sources; add a documented approved record in `review/approved.json` and review it in a pull request. Never copy claims from untrusted page snippets verbatim into trusted output.
6. Run `Publish reviewed Jordan advisories` and open the Pages URL. Use `/data/advisories.json` as the future read-only Flutter data endpoint.

## Reviewer record example (NOT for publication without real evidence)
Fields: `id`, `title_ar`, `summary_ar`, `guidance_ar`, `category` (`phishing`, `financial_fraud`, `malicious_apps`, `account_takeover`, `general`), `country` (`JO`), `source_id`, `source_url`, `published_at` and `reviewed_at` (ISO 8601), `reviewed_by`, `evidence_status` (`confirmed_official_advisory` or `general_awareness`), optional `active_in_jordan` boolean.

## Security limitations and next tasks
- Link discovery is *not* article extraction, evidence verification, a fully reliable crawler, or LLM summarization. Official sites can change layouts and disallow automated requests. Respect site terms and robots rules; move to approved RSS/API when available.
- Current validation establishes publisher allowlist and basic record completeness; future releases should add stronger source-specific provenance, public feed signing, approval audit records, timestamps for **actual** campaign activity, structured threat lifecycle and anti-replay.
- No advisory is active by default. A historical official page is not evidence of a **current** campaign.
- Hosted JSON may be cached and must use safe error handling in Flutter. Validate schema and caps, avoid remote HTML, use last-good cache and stale indicators. Downloading public advisories should require no device identifiers.
- GitHub schedule can be delayed or skipped; production monitoring should alarm on stale feeds, not claim timely delivery when not checked.
- For AI agent: add optional summary-drafting into a separate candidate field, requiring editorial review; never grant AI a direct publish credential.
