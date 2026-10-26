# Licensing at a glance

This page explains, in plain terms, what you may do with Ephemora-cell and
when a commercial license is required. It is a **summary, not the license**:
the canonical text is [LICENSE](../LICENSE), which governs in every case
(including where this summary is less precise). The LICENSE itself is
unchanged.

## What Ephemora-cell is licensed under

The Business Source License 1.1 (BUSL-1.1) — **source available, not OSI
open source**. Each published version converts automatically to the Apache
License 2.0 on its Change Date: the fourth anniversary of that version's
first publicly available distribution. The per-version dates are recorded in
[ADR-010](decisions/ADR-010-relicensing-bsl11.md).

## What is free — always

- **Non-production use**: evaluation, development, research, testing,
  prototyping, teaching, personal projects.
- This freedom applies to **individuals and organizations alike**:
  non-production use inside a company (e.g. an internal proof of concept or
  a pilot that is not run operationally) does not require a commercial
  license.
- Copying, modifying and redistributing under the LICENSE terms (with the
  license text kept visible on copies).

## When you need a commercial license

- **Production use before the applicable Change Date.** If you operate the
  software in production — in your own products, services or business
  processes — before that version's Change Date, the LICENSE requires a
  commercial license from the Licensor, unless you hold a separate grant or
  other authorization.
- There is no blanket rule that "any company use is paid": the dividing line
  is production vs. non-production, as the LICENSE states.

To discuss a commercial license, see
[Ephemora for Enterprise](enterprise.md) — or simply start with the
non-production path; the project enforces nothing by telemetry and sends no
data anywhere — the only network path in the package is the host-mediated
egress mediator you grant yourself (ADR-013).

## After the Change Date

Each version becomes available under **Apache-2.0** four years after its
first public distribution, and the rights granted by BUSL-1.1 terminate in
favor of the Apache-2.0 rights. Versions published before the BUSL switch
(**1.0.4.3 and earlier**) were Apache-2.0 from the start and **remain**
Apache-2.0 — that is unchanged.

## Third-party components

The LICENSE covers the Ephemora-cell project only. Embedded or referenced
third-party components (e.g. CPython in the Python guest, QuickJS-ng in the
JavaScript guest, Wasmtime) keep their own licenses; they are itemized in
[THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) and travel with their
license texts inside the distributions.

## No warranty

The Licensed Work is provided on an "AS IS" basis, with all warranties and
conditions disclaimed, in the terms the [LICENSE](../LICENSE) states.

## Contributing

Contributions are welcome under the terms in
[CONTRIBUTING.md](../CONTRIBUTING.md) ("Licensing of Contributions"). Those
terms are being hardened before external contributions are accepted, so the
project can keep offering both source-available and commercial licensing.
