# Research candidate queue

This directory separates **discovery leads** from the canonical, citable catalog
in `../cves/`. A candidate is not evidence that an attack, vulnerability,
incident, or product claim is true.

Last reviewed: 2026-09-02

## Workflow

1. Add a lead to `candidates.yaml` with a stable `candidate-NNNN` ID and the URL
   where it was discovered.
2. Set `status: needs-relevance-review`. Unknown classifications may be empty
   arrays or `null`; do not guess.
3. Decide whether HID is materially involved using
   `../../research/scope-and-inclusion.md`.
4. Locate a primary source. A search result, aggregator, or marketing page alone
   is insufficient for promotion.
5. Record a concise HID relevance statement and review date. Set
   `status: ready-for-entry` only when the lead can satisfy the canonical dataset
   schema and contribution rules.
6. Create the canonical entry as a separate, reviewable change. Mark the queue
   item `duplicate` or remove it once its history is preserved by the resulting
   commit or pull request.

Use `rejected` for out-of-scope or unsupported leads and explain why in
`review_notes`. Rejected records may remain in the queue to prevent repeated
triage. Use `deferred` when the lead may be relevant but cannot yet be verified.
Use `target_record_type: malware-or-campaign` or `resource` for relevant leads
that need a future canonical schema; these cannot be marked `ready-for-entry`.
Use `undetermined` only until triage establishes the appropriate record type.

## Validation

```bash
python scripts/research-tools/validate_research_queue.py
python scripts/research-tools/build_coverage.py --check
```

The queue is validated against
`../schemas/research-candidate.schema.json`. Candidate attack-class references
must also resolve against the project taxonomy.

## Safety

Do not add non-public vulnerability details, secrets, malware binaries,
weaponized HID payloads, firmware blobs, or real keystroke captures. Store URLs
and factual review notes, not downloaded offensive artifacts.
