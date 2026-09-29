# ADR-010: Relicensing to BUSL-1.1 — Source-Available with Per-Version Apache-2.0 Conversion

- **Status:** Accepted
- **Date:** 2026-09-29
- **Predecessors:** — (first licensing ADR; house style per ADR-009)
- **Basis:** Relicensing audit 2026-09-29: Apache-2.0 is referenced in 2
  LICENSE files (root + shipped `ephemora_cell/LICENSE`), `pyproject.toml`
  (`license = {text = "Apache-2.0"}` + OSI classifier), README, and ~12 docs
  (enterprise, architecture/performance diagrams, two whitepapers, LinkedIn
  whitepaper, marketing PR drafts, two internal BEWEISE docs); the file
  headers carried `# SPDX-License-Identifier: Apache-2.0` with a copyright
  line naming the author while the LICENSE appendix named "Ephemora AG (in
  formation)" — a copyright-holder inconsistency, and the shipped
  `ephemora_cell/LICENSE` still contained the stale
  `Copyright [yyyy] [name of copyright owner]` appendix placeholder;
  PyPI releases 1.0.0
  through 1.0.4.3 are published under Apache-2.0; git history shows a single
  human author (Michael Soppa, two email variants), so relicensing future
  versions is legally clean; the open-core model (Cell as the isolation
  layer, Ephemora enterprise edition on top) is stated in the README About
  section and `docs/enterprise.md`; Glama currently grades the server
  "license A".

## Context (verified, not assumed)

1. **The project is Apache-2.0 everywhere it is declared, but inconsistently
   attributed.** Both LICENSE files carry the Apache-2.0 text; the shipped
   `ephemora_cell/LICENSE` still ends with the appendix boilerplate where the
   copyright line was filled at the root but a placeholder survived in the
   package copy's history, and 8 of 23 package files carry
   `# SPDX-License-Identifier: Apache-2.0` (two with
   `# Copyright 2026 Michael Soppa`) while the other 15 carry no header at
   all. A relicensing is the moment to unify all of this in one sweep.
2. **Everything published so far was published under Apache-2.0.** PyPI
   releases 1.0.0–1.0.4.3 (tags v1.0.0…v1.0.4.3, first public release
   2026-08-30) shipped with the Apache-2.0 LICENSE and metadata. Those
   grants are irrevocable; the boundary below is a statement of fact, not a
   recission.
3. **Single human author.** `git log` lists exactly one author identity
   (Michael Soppa, two email variants of the same person). No external
   contributions have been merged, so no contributor-approval process is
   needed for the boundary version — relicensing is legally clean.
4. **The business model is open-core and was always stated that way.**
   README ("About Ephemora") and `docs/enterprise.md` position Cell as the
   isolation layer and the enterprise edition as the operational layer for
   production and regulated deployments. Apache-2.0 gave competitors the
   same right to take the isolation layer itself; BUSL-1.1 closes exactly
   that gap while keeping the code readable, forkable for evaluation, and
   eventually open.
5. **Ecosystem perception is measured.** Glama currently grades the MCP
   server "license A, quality A, maintenance B"; OpenSSF Scorecard credits
   an OSI/FSDG-approved license. A non-OSI license will cost points in
   automated trust surfaces. That cost is accepted deliberately: the point
   of the change is to stop granting unlimited commercial reuse.
6. **BSL-1.1 is the established mechanism for exactly this.** It is
   source-available (code is public and modifiable), restricts production
   use, and converts to a permissive license on a fixed date. The MariaDB
   covenants require a GPL-compatible Change License or a permissive one —
   Apache-2.0 qualifies without limitation.

## Decision

**D1 — License: Business Source License 1.1 (SPDX: BUSL-1.1) with these
four parameters, applied to both LICENSE copies, `pyproject.toml`, and the
SPDX headers of all 23 package files:**

- **Licensor:** Ephemora AG (in formation), Zug, Switzerland
- **Additional Use Grant:** None
- **Change Date:** the fourth anniversary of the first publicly available
  distribution of each version of the Licensed Work (per-version phrasing —
  D3)
- **Change License:** Apache License 2.0

**D2 — Boundary version: the next release (1.0.5).** All versions
≤ 1.0.4.3 remain Apache-2.0 permanently; the change applies from the next
release onward. Forks of pre-boundary code stay Apache-2.0. The version
field stays 1.0.4.3 until the actual release bump.

**D3 — Per-release Change Date.** Each version carries its own Change Date
(four years after that version's first publicly available distribution),
which is how the BSL text is designed to be used; the LICENSE states the
per-version phrasing rather than a single fixed date.

**D4 — Contribution policy.** Contributions are accepted under BUSL-1.1,
with a relicensing grant: by contributing you confirm you have the right to
submit the work and you grant the Licensor a perpetual, irrevocable right to
relicense and enforce. The clause is mirrored in `CONTRIBUTING.md`
("Licensing of Contributions").

## Consequences

- **"Source-available" is the correct public label, not "open source".**
  BUSL-1.1 is not OSI-approved; README and docs switch to source-available
  language, and the OSI classifier is removed from `pyproject.toml`
  (PyPI shows the license via the metadata field, which stays populated).
- **GitHub license detection shows BUSL-1.1** automatically from the LICENSE
  file.
- **Automated trust grades are expected to drop:** Glama's license grade
  (currently A) and the OpenSSF Scorecard license credit will likely be
  withdrawn or downgraded; README badge alt text and prose are updated so
  the claims stay accurate (quality/maintenance grades remain).
- **Non-production use stays free** — evaluation, development, research,
  testing are explicitly within the BSL grant.
- **The Licensor is unrestricted:** Ephemora can sell the enterprise edition
  and commercial licenses without negotiating with itself; the open-core
  model in `docs/enterprise.md` becomes enforceable.
- **Forks of pre-boundary code stay Apache-2.0** (D2); nothing published
  under 1.0.4.3 or earlier changes.
- **Flagged, non-blocking:** legal counsel should confirm the
  "Ephemora AG (in formation)" copyright naming — an entity in formation can
  hold copyright via its founder in the interim, but the naming should be
  revisited at incorporation (the copyright line is uniform across LICENSE,
  headers, and docs in the meantime).
