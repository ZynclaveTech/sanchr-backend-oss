# RFC Process

This document describes the process for proposing and deciding on significant changes to Sanchr's protocols, cryptographic primitives, and wire formats.

## When an RFC Is Required

An RFC is required for:

- Any change to cryptographic primitives or parameters (algorithms, key sizes, curve choices)
- Any change to the OPRF, EKF, or sealed sender protocols
- New wire protocol messages or breaking protobuf changes
- Changes to the threat model or security guarantees
- Addition or removal of trust assumptions

An RFC is **not** required for:

- Bug fixes that do not alter protocol behavior
- Performance improvements that preserve semantics
- Documentation updates
- Internal refactors that do not change public APIs or wire formats
- New non-cryptographic configuration options

## RFC Format

RFCs are stored in `docs/rfcs/` and follow this template:

```markdown
# RFC-NNNN: [Title]

**Author:** [name]
**Status:** Draft | Review | Accepted | Rejected | Superseded
**Created:** YYYY-MM-DD

## Summary

[One paragraph describing the change.]

## Motivation

[Why is this change needed? What problem does it solve?]

## Design

[Technical details of the proposed change. Include protocol diagrams,
message formats, and cryptographic constructions as appropriate.]

## Security Considerations

[Impact on the threat model and formal properties. Which Tamarin models
need updating? Are new attack vectors introduced?]

## Alternatives Considered

[What other approaches were evaluated? Why were they rejected?]

## Migration

[How do existing deployments upgrade? Is the change backward-compatible?
What is the migration path for stored data?]
```

## Process

1. **Draft:** Author opens a pull request adding the RFC document to `docs/rfcs/`. The file is named `NNNN-short-title.md` where NNNN is the next sequential number.

2. **Label:** A core team member labels the PR with `rfc`.

3. **Comment period:** The RFC is open for public comment for a minimum of **7 days**. The author should respond to feedback and update the RFC as needed.

4. **Review:** Core team members review the RFC. For changes affecting cryptographic protocols, **2 approvals from core team members** are required. For non-cryptographic protocol changes, 1 approval is sufficient.

5. **Decision:**
   - **Accepted:** The RFC PR is merged. Implementation issues are created and linked to the RFC.
   - **Rejected:** The PR is closed with a written explanation of the reasoning.
   - **Superseded:** If a newer RFC replaces this one, the status is updated and a link to the superseding RFC is added.

## Status Lifecycle

```
Draft --> Review --> Accepted --> (implemented)
                \-> Rejected
                \-> Superseded by RFC-MMMM
```

## Numbering

RFC numbers are assigned sequentially starting from 0001. Numbers are never reused, even for rejected RFCs.
