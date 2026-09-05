# Ephemora for Enterprise

[Ephemora Cell](../README.md) is the open-source, Apache-2.0 WASM sandbox
— complete for **isolation**. The Ephemora enterprise edition builds on
Cell's isolation for teams whose question is not "does the sandbox hold?"
but "how do I run, attest and operate it at scale?" Cell is complete for
isolation; the enterprise edition is complete for operation.

## When Cell is enough

Cell is a standalone library, CLI and MCP server with no Ephemora
dependency. It is the right tool when you need:

- Deterministic, enforced isolation for untrusted code (fuel, memory,
  timeout, output caps, I/O budgets — all [measured and verified](security_posture.md))
- A sandbox you embed and operate yourself: single process, single tenant,
  your own logging
- Reproducible evidence you verify yourself: the [8/8 attack-vector suite](https://github.com/MichaelS1011/ephemora-cell#security),
  the [security posture detail](security_posture.md), and execution records with
  `sign()`/`verify()` primitives shipped in Cell (RFC 8785 JCS
  canonicalization, bring-your-own keys)

If those are your requirements, use Cell — no conversation needed, the
[README](../README.md) and [SUPPORT.md](../SUPPORT.md) are the docs.

## Questions worth asking before you scale

These are the operational questions Cell deliberately does not answer for
you. How your team answers them is usually what decides whether an
enterprise conversation makes sense:

- **Who watches the walls?** Cell reports what happened in a run
  (`security_baseline`, I/O budget counters, signable records). Who collects,
  stores and alerts on those artifacts across thousands of runs a day?
- **Multi-tenant boundaries:** Cell isolates one module execution. How do
  you keep concurrent tenants, their sandbox directories and their audit
  trails separate at the process and fleet level?
- **Compliance custody:** Cell produces tamper-evident execution records.
  Where do they live, who can revoke keys, how do you produce evidence for
  an auditor (EU AI Act logging obligations, DORA operational-resilience
  audits, internal SOC2 controls)?
- **Operational tooling:** upgrades of the runtime, engine-pool sizing,
  fleet observability, incident response when a guest misbehaves.

The enterprise edition exists for exactly this layer — built on Cell's
isolation primitives, not around them.

## Contact

- **Enterprise inquiries:** [LinkedIn — Michael Soppa](https://www.linkedin.com/in/michael-soppa)
- **Everything open source:** [GitHub Issues](https://github.com/MichaelS1011/ephemora-cell/issues)
  or [Discussions](https://github.com/MichaelS1011/ephemora-cell/discussions)
- **Security vulnerabilities:** [SECURITY.md](../SECURITY.md) — never via
  public issues
