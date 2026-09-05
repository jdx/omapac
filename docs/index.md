---
layout: home
title: Trusted packages for pacman systems

hero:
  name: pacvamp
  text: Trusted packages for pacman systems
  tagline: One interface for distribution repositories, the AUR, policy, provenance, and repeatable machines.
  image:
    src: /logo.svg
    alt: pacvamp vampire logo
  actions:
    - theme: brand
      text: Install Pacvamp
      link: /install
    - theme: alt
      text: Verify trust roots
      link: /trust

features:
  - title: One transaction path
    details: Install, remove, update, and converge packages from repositories and the AUR through one consistent interface.
  - title: Evidence before trust
    details: Verify signed indexes, provenance, transparency records, verdicts, and advisories before packages reach a machine.
  - title: Built for distributions
    details: Layer distro policy over user manifests, publish tested snapshots, and operate independent compatible registries.
---

> [!WARNING]
> This project is not ready to be reviewed and is still very much a work in
> progress. Nothing here is stable, supported, or intended for real use — do not
> depend on it.

## Documentation

- [Install Pacvamp](/install): configure the public repository and install the
  signed Arch package.
- [Import an existing machine](/migration): preview a manifest without granting trust.
- [Understand blocked updates](/update-policy): retained versions, retry times, and review actions.
- [Check active protections](/protection-status): kernel support, policy, feeds, and snapshots.
- [Security acceptance tests](/security-testing): adversarial fixtures and mandatory Linux checks.
- [Trust roots](/trust): independently verify the signing keys used by the
  public Pacvamp registry.
- [Project plan](https://github.com/jdx/pacvamp/blob/main/PLAN.md): the design, decisions, and implementation plan.
- [CLI reference](/cli/pacvamp/): generated from the usage specs by `mise run render`.
  - [pacvamp](cli/pacvamp/) the client
  - [pacvamp-repo](cli/pacvamp-repo/) the server side a repository runs
  - [packslip](https://packslip.dev/cli/) the external vendor release manifest tool
- [Specifications](/spec/packslip):
  - [packslip](spec/packslip.md): the vendor-neutral signed release manifest.
  - [repository feeds](spec/repository-feeds.md): the signed index, verdicts, and advisories.
  - [build provenance](spec/provenance.md): the envelope, transparency, and the signer gate.
  - [vendor pipeline](spec/vendor-pipeline.md): building a package from a vendor's packslip.
  - [AUR sync gate](spec/sync-gate.md): which upstream commits a repository pulls.
  - [release train](spec/release-train.md): the client side of tested snapshots.
  - [snapshot store](spec/snapshot-store.md): the server side of tested snapshots.
  - [tool channel](spec/tool-channel.md): vetted vendor tools for mise.
- [Run an isolated registry](/operations/registry): deploy the publisher,
  immutable snapshot store, signing keys, and Caddy endpoint.
- [Adoption guides](/adoption/omarchy), the steps other projects take:
  - [Omarchy](adoption/omarchy.md)
  - [The Omarchy Package Repository](adoption/opr.md)
  - [mise](adoption/mise.md)
- [Snapshot test harness](https://github.com/jdx/pacvamp/tree/main/harness) and the
  [mise tool-channel plugin](https://github.com/jdx/pacvamp/tree/main/plugins/mise-tool-channel).
