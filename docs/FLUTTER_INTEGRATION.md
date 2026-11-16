# AmanRoid Flutter threat-intelligence contract

The Flutter application may consume the public feed as an optional, read-only
advisory source. It must remain functional when the feed is unavailable.

## Endpoint

`https://basheeralduwairi.github.io/AmanRoid-Threat-Intel/data/advisories.json`

The endpoint is static GitHub Pages content. It does not accept uploads, device
identifiers, scan results, URLs submitted to the phishing checker, or account
credentials.

## Retrieval rules

1. Use HTTPS only and a short connect/read timeout.
2. Do not follow arbitrary URLs from the response. `source_url` may be shown as
   an explicit user action after validating that it is HTTPS.
3. Limit the response body to a safe size, reject invalid JSON, and validate
   `schema_version`, `country == "JO"`, `feed_status`, `publication`, and every
   advisory field before display.
4. Accept only records with `review.status == "human_approved"` and
   `publication.status == "approved"`.
5. Preserve `source_url`, `evidence`, `published_at`, `review.reviewed_at`,
   `geographic_relevance`, `confidence`, `freshness`, and `lifecycle` when
   caching or rendering.
6. Cache the last-known-good validated response locally. Never replace it with
   an invalid, partial, or unreviewed response.
7. If retrieval fails, render the cached feed with an explicit stale/error
   indicator. If there is no cache, show `مصادر التحذيرات قيد الإعداد` or an
   unavailable state; do not invent advisories.
8. Treat `freshness.status == "stale"` and `lifecycle.status == "historical"`
   as display metadata, not as current threat claims.

## Schema summary

```json
{
  "schema_version": 2,
  "country": "JO",
  "feed_status": "awaiting_reviewed_advisories",
  "generated_at": "2026-11-16T00:00:00Z",
  "publication": {
    "human_approval_required": true,
    "reviewed_count": 0,
    "current_count": 0,
    "historical_count": 0
  },
  "advisories": []
}
```

Each non-empty advisory includes Arabic content, a category, source ID and
allowlisted original URL, observed publication date or an explicit unknown
date status, evidence records with retrieval timestamps and hashes, a
geographic relevance value, confidence rationale, review metadata, freshness,
and lifecycle status.

## Local cache guidance

Use a versioned local record such as `amanroid-threat-feed-v2`. Store only the
validated JSON and retrieval metadata. Do not store raw HTML or transmit any
device data to this feed. The cache can be deleted independently from the
security scan history.

## Publication boundary

AI drafts are written to `review/drafts.json` and are never in the public feed.
An authorized human must inspect the original source and evidence, run the
explicit approval helper or edit `review/approved.json` in a reviewed pull
request, and only then may the Pages workflow publish the feed.
