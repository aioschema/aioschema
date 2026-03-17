# AIOSchema Specification — Which File to Use

This folder contains two editions of the v0.5.5 specification. They are not duplicates.

---

## `AIOSchema_v0_5_5_Specification.md` — **Implementer Edition**

Use this to build a conforming implementation.

- Concise (~872 lines)
- Covers all normative requirements: core block fields, verification procedure, algorithm registry, extension block, anchor formats
- "Technical Preview" status header
- Dual-licensed: CC-BY 4.0 (spec text) / Apache 2.0 (implementations)
- This is the document third-party implementors should read

---

## `as-doc-spec-018f-v0_5.md` — **Founding Provenance Edition**

This is the merged authoritative/review draft, including the founding anchor record.

- Full edition including §18 (Founding Provenance Procedure) and the self-anchoring record for this document
- Used to establish prior art for the specification itself via Bitcoin anchoring
- Contains the `asset_id`: `as-doc-spec-018f-v0.5.5`
- "Public Review Draft — Merged Authoritative Edition" status header
- The anchor timestamp in §18 is independent of the publication decision — it records when this version was created and locked, not when it was published

**For implementation purposes, use the Implementer Edition above.**

---

## Relationship

Both documents describe the same v0.5.5 standard. The Founding Provenance Edition is the canonical legal/anchored record; the Implementer Edition is the trimmed, reader-friendly version derived from it. If there is any discrepancy between the two, the Founding Provenance Edition prevails.
