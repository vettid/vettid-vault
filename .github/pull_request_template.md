## What changes

## Tested

<!-- What was run, where, and the result. Say what was not run. The vault's
recovery and unlock tests skip without -tags vettid_testcost. -->

## Service interface

<!-- Keep this section if the change touches what a member vault exchanges
with service vaults (handshake, peerwire messages, features, contract,
invitations, ballot documents and bundles, services.json, trust roots, the
vms/* packages service-vault uses); otherwise delete it.
Rules: vettid.org docs/VAULT-SERVICE-INDEPENDENCE.md (R1-R3). -->

- [ ] **Against the previous service release:** how this behaves with a service on the previous supported release, and on the current one:
- [ ] **Negotiable change:** gated on a feature both sides advertise, with the old behaviour kept while the peer lacks it (R1, R3). No connection is ended or refused, and no peer's state is refused: a peer that lacks the feature is held and shown, not ended.
- [ ] **Downgrade rule:** a feature only chooses a format (never one weaker than the current minimum) or opts in to stricter handling. Nothing here lets a service's features or `contract` relax a check that protects the member (R1).
- [ ] **Not negotiable, so service-first or a planned flag day with an owner go** (R1, R3), never gated on a feature:
  - a public document, or a stricter check of what the service signs: this vault check of what the service signs is not stricter than what every supported service release already meets (name the service release that meets it);
  - a new signature suite;
  - rotating Sigstore roots, the timestamp authority or `vote_site_key`;
  - the invitation: the vault still accepts the oldest format a supported service issues.
- [ ] **`vms/*` exported APIs** stay additive: nothing a supported service release uses is removed or changed.
