# JUSTUS Finance Trust

This public repository is the independent trust boundary for the private
`Rokkxstar/JUSTUS` Phase-5 exit. It deliberately contains no finance
implementation.

The protected workflow:

1. checks out the exact private candidate commit with a read-only token;
2. executes current tests, Golden cases, PostgreSQL cases and all immutable
   accepted-baseline contracts with independent evidence parsing;
3. builds the deterministic candidate twice and verifies a fresh extract;
4. uploads only the candidate ZIP and a machine-readable trust decision;
5. reverifies both on a fresh runner and creates GitHub build-provenance
   attestations before publishing the final artifact.

All third-party Actions are pinned to full commit SHAs. The candidate never
receives an attestation token and no `gh` executable participates in the trust
decision. A PATH-hijacked fake `gh.cmd` is installed as a live tripwire.

Required protected environment: `phase-exit-trust`

- secret `JUSTUS_READ_TOKEN`: fine-grained, read-only, restricted to JUSTUS;
- variable `FINANCE_PO_TRUST_LEDGER_SHA256`:
  `84bd9d65e499c858e4e3c947805c3df9eb19c37bd55e06ebb0031e0f7e3bfb21`;
- required reviewer and main-branch deployment restriction.

The canonical release identity must end in the independently calculated
snapshot prefix `83f99826170b`. A different suffix fails closed.

The accepted candidate contains eight historical Phase-4 JSON fixtures with
CRLF bytes while the rest of the Git tree uses LF. The trusted runner restores
only those eight paths from an LF checkout against individually compiled
SHA-256 values, then requires the complete accepted snapshot hash. This is a
transport reconstruction, not a finance or evidence change.
