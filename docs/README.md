# omapac documentation

- [PLAN.md](../PLAN.md): the design, decisions, and implementation plan.
- [CLI reference](cli/): generated from the usage specs by `mise run render`.
  - [omapac](cli/omapac/) the client
  - [omapac-repo](cli/omapac-repo/) the server side a repository runs
  - [packslip](cli/packslip/) the vendor release manifest tool
- Specifications under [spec/](spec/):
  - [packslip](spec/packslip.md): the vendor-neutral signed release manifest.
  - [repository feeds](spec/repository-feeds.md): the signed index, verdicts, and advisories.
  - [build provenance](spec/provenance.md): the envelope, transparency, and the signer gate.
  - [vendor pipeline](spec/vendor-pipeline.md): building a package from a vendor's packslip.
  - [AUR sync gate](spec/sync-gate.md): which upstream commits a repository pulls.
  - [release train](spec/release-train.md): the client side of tested snapshots.
  - [snapshot store](spec/snapshot-store.md): the server side of tested snapshots.
  - [tool channel](spec/tool-channel.md): vetted vendor tools for mise.
- Adoption guides under [adoption/](adoption/), the steps other projects take:
  - [Omarchy](adoption/omarchy.md)
  - [The Omarchy Package Repository](adoption/opr.md)
  - [mise](adoption/mise.md)
- [Snapshot test harness](../harness/README.md) and the
  [mise tool-channel plugin](../plugins/mise-tool-channel/README.md).
