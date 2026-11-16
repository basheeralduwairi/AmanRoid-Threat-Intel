#!/usr/bin/env python3
"""Human approval helper. It is intentionally separate from collection and AI drafting."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path

import pipeline


def approve(draft_id: str, reviewer: str, notes: str, confirm_source: bool, active_in_jordan: str) -> None:
    if not confirm_source:
        raise SystemExit("Approval requires --confirm-original-source after a human checks the source URL and evidence.")
    drafts = pipeline.load(pipeline.ROOT / "review/drafts.json").get("drafts", [])
    draft = next((item for item in drafts if item.get("id") == draft_id), None)
    if not draft:
        raise SystemExit(f"Draft not found: {draft_id}")
    if draft.get("ai_status") != "draft_ready":
        raise SystemExit("Only a provider-produced draft_ready record can be approved; review the source manually instead.")
    if draft.get("source_material_sha256") is None:
        raise SystemExit("Approval requires collected source evidence with a content hash.")
    configured = pipeline.load(pipeline.ROOT / "config/sources.json")
    sources = {item["id"]: item for item in configured.get("sources", [])}
    active = None if active_in_jordan == "unknown" else active_in_jordan == "true"
    record = {
        "schema_version": pipeline.SCHEMA_VERSION,
        "id": draft["id"],
        "title_ar": draft["title_ar"],
        "summary_ar": draft["summary_ar"],
        "guidance_ar": draft["guidance_ar"],
        "category": draft["category"],
        "country": "JO",
        "source_id": draft["source_id"],
        "source_name_ar": next(
            (item.get("name_ar", draft["source_id"]) for item in configured.get("sources", []) if item.get("id") == draft["source_id"]),
            draft["source_id"],
        ),
        "source_url": draft["source_url"],
        "published_at": draft.get("published_at"),
        "publication_date_status": draft.get("publication_date_status", "unknown"),
        "evidence": draft["evidence"],
        "evidence_status": draft.get("evidence_status", "needs_human_review"),
        "geographic_relevance": draft.get("geographic_relevance", "unknown"),
        "confidence": draft["confidence"],
        "active_in_jordan": active,
        "lifecycle": draft.get("lifecycle", {"status": "current"}),
        "ai_draft": {
            "status": "human_reviewed_draft",
            "provider": draft.get("ai_provider"),
            "model": draft.get("ai_model"),
            "generated_at": draft.get("generated_at"),
        },
        "review": {
            "status": "human_approved",
            "reviewed_by": reviewer,
            "reviewed_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "notes": notes,
            "approval_basis": "Human reviewer checked the original source, date, evidence, geography, and wording.",
        },
    }
    pipeline.validated(record, sources, require_approved=True)
    approved_path = pipeline.ROOT / "review/approved.json"
    approved = pipeline.load(approved_path)
    records = [item for item in approved.get("advisories", []) if item.get("id") != draft_id]
    records.append(record)
    pipeline.write_json(approved_path, {"schema_version": pipeline.SCHEMA_VERSION, "advisories": records})
    print(f"Approved {draft_id} for publication review; run the publish workflow separately.")


def reject(draft_id: str, reviewer: str, reason: str, confirm_not_publish: bool) -> None:
    if not confirm_not_publish:
        raise SystemExit("Rejection requires --confirm-not-publish after checking the source and recording the reason.")
    drafts = pipeline.load(pipeline.ROOT / "review/drafts.json").get("drafts", [])
    draft = next((item for item in drafts if item.get("id") == draft_id), None)
    if not draft:
        raise SystemExit(f"Draft not found: {draft_id}")
    if not reason.strip():
        raise SystemExit("A rejection reason is required")
    path = pipeline.ROOT / "review/rejections.json"
    existing = pipeline.load(path) if path.exists() else {"schema_version": 1, "decisions": []}
    decisions = [item for item in existing.get("decisions", []) if item.get("id") != draft_id]
    decisions.append({
        "id": draft_id,
        "decision": "rejected",
        "reviewer": reviewer,
        "reviewed_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "reason": reason.strip(),
        "publication_allowed": False,
    })
    pipeline.write_json(path, {"schema_version": 1, "decisions": decisions})
    print(f"Rejected {draft_id}; it cannot enter the public feed.")


def validate_review_files() -> None:
    configured = pipeline.load(pipeline.ROOT / "config/sources.json")
    sources = {item["id"]: item for item in configured.get("sources", [])}
    approved = pipeline.load(pipeline.ROOT / "review/approved.json").get("advisories", [])
    rejections = pipeline.load(pipeline.ROOT / "review/rejections.json").get("decisions", [])
    approved_ids = {item.get("id") for item in approved}
    rejected_ids = {item.get("id") for item in rejections if item.get("decision") == "rejected"}
    if None in approved_ids or None in rejected_ids:
        raise SystemExit("Every review record requires an id")
    overlap = approved_ids & rejected_ids
    if overlap:
        raise SystemExit(f"Review records cannot be both approved and rejected: {sorted(overlap)}")
    for item in approved:
        pipeline.validated(item, sources, require_approved=True)
    for item in rejections:
        if item.get("decision") != "rejected" or not item.get("reviewer") or not item.get("reason"):
            raise SystemExit("Invalid rejection record")
    print(f"Validated {len(approved)} approvals and {len(rejections)} rejection decisions")


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    approve_parser = sub.add_parser("approve")
    approve_parser.add_argument("draft_id")
    approve_parser.add_argument("--reviewer", required=True)
    approve_parser.add_argument("--notes", required=True)
    approve_parser.add_argument("--confirm-original-source", action="store_true")
    approve_parser.add_argument("--active-in-jordan", choices=("true", "false", "unknown"), default="unknown")
    reject_parser = sub.add_parser("reject")
    reject_parser.add_argument("draft_id")
    reject_parser.add_argument("--reviewer", required=True)
    reject_parser.add_argument("--reason", required=True)
    reject_parser.add_argument("--confirm-not-publish", action="store_true")
    sub.add_parser("validate")
    args = parser.parse_args()
    if args.command == "approve":
        approve(args.draft_id, args.reviewer, args.notes, args.confirm_original_source, args.active_in_jordan)
    elif args.command == "reject":
        reject(args.draft_id, args.reviewer, args.reason, args.confirm_not_publish)
    else:
        validate_review_files()


if __name__ == "__main__":
    main()
