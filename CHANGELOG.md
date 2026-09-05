# Changelog

## [0.1.1](https://github.com/jdx/pacvamp/compare/v0.1.0..v0.1.1) - 2026-09-05

### Bug fixes

- preserve scripted Omarchy package semantics in [#81](https://github.com/jdx/pacvamp/pull/81)
## [0.1.0] - 2026-09-05

### Bug fixes

- confine build reads and use private scratch directories in [#55](https://github.com/jdx/pacvamp/pull/55)
- isolate AUR build runs and lock shared recipe operations in [#61](https://github.com/jdx/pacvamp/pull/61)

### Documentation

- warn that omapac is an experimental spike
- mark project as work in progress
- adoption guides, rendered CLI reference, e2e harness in [#27](https://github.com/jdx/pacvamp/pull/27)
- **plan:** record which follow-ups the stack closed in [#35](https://github.com/jdx/pacvamp/pull/35)
- apply pacvamp branding
- publish branded Open Graph share image in [#51](https://github.com/jdx/pacvamp/pull/51)
- complete social and search metadata in [#52](https://github.com/jdx/pacvamp/pull/52)
- generate page-specific social preview images in [#71](https://github.com/jdx/pacvamp/pull/71)

### Features

- **alpm-db:** pacman.conf parser and vercmp in [#3](https://github.com/jdx/pacvamp/pull/3)
- **alpm-db:** local and sync database readers in [#5](https://github.com/jdx/pacvamp/pull/5)
- **engine:** Engine trait and the pacman CLI engine in [#6](https://github.com/jdx/pacvamp/pull/6)
- **cli:** read-only commands in [#7](https://github.com/jdx/pacvamp/pull/7)
- add pacvamp logo, OG image, and favicons
- **cli:** install and remove in [#8](https://github.com/jdx/pacvamp/pull/8)
- **manifest:** layered config and managed floor in [#9](https://github.com/jdx/pacvamp/pull/9)
- **ledger:** state file in [#10](https://github.com/jdx/pacvamp/pull/10)
- **aur:** rpc, git checkout, .SRCINFO in [#11](https://github.com/jdx/pacvamp/pull/11)
- **aur:** jailed build and install in [#14](https://github.com/jdx/pacvamp/pull/14)
- **update:** update pipeline in [#15](https://github.com/jdx/pacvamp/pull/15)
- **packslip:** spec, verifier, generator in [#16](https://github.com/jdx/pacvamp/pull/16)
- **trust:** index, verdicts, advisories, sidecars in [#17](https://github.com/jdx/pacvamp/pull/17)
- **channel:** snapshots in [#18](https://github.com/jdx/pacvamp/pull/18)
- **omapac-repo:** index and attest in [#19](https://github.com/jdx/pacvamp/pull/19)
- **omapac-repo:** sign gate and vendor pipeline in [#20](https://github.com/jdx/pacvamp/pull/20)
- **omapac-repo:** sync-aur gate, verdict, advisories in [#21](https://github.com/jdx/pacvamp/pull/21)
- **omapac-repo:** snapshot and test harness in [#22](https://github.com/jdx/pacvamp/pull/22)
- **tui:** ratatui pickers in [#23](https://github.com/jdx/pacvamp/pull/23)
- **omapac-repo:** tool channel publisher and omapac tools client in [#25](https://github.com/jdx/pacvamp/pull/25)
- **plugin:** mise tool-channel backend in [#26](https://github.com/jdx/pacvamp/pull/26)
- **update:** release-age floors from index publish times in [#28](https://github.com/jdx/pacvamp/pull/28)
- **update:** one update at a time in [#29](https://github.com/jdx/pacvamp/pull/29)
- **aur:** build AUR dependencies first in [#30](https://github.com/jdx/pacvamp/pull/30)
- **channel:** tested and snapshot labels in info and update in [#31](https://github.com/jdx/pacvamp/pull/31)
- **omapac-repo:** verify transparency log inclusion proofs in [#32](https://github.com/jdx/pacvamp/pull/32)
- **verify:** check the provenance envelope and log entry sidecars in [#33](https://github.com/jdx/pacvamp/pull/33)
- explain update blockers with retained versions and retry actions in [#57](https://github.com/jdx/pacvamp/pull/57)
- preview and import explicitly installed packages into the manifest in [#58](https://github.com/jdx/pacvamp/pull/58)
- report configured and available package protections in doctor in [#59](https://github.com/jdx/pacvamp/pull/59)
- journal package transactions and recover completed ledger writes in [#63](https://github.com/jdx/pacvamp/pull/63)
- supervise AUR builds with time, process, memory and disk limits in [#66](https://github.com/jdx/pacvamp/pull/66)
- retain local AUR build receipts and bind installed artifacts in [#67](https://github.com/jdx/pacvamp/pull/67)
- build AUR packages in isolated read-only Arch images in [#68](https://github.com/jdx/pacvamp/pull/68)

### Maintenance

- bootstrap repository
- scaffold workspace in [#2](https://github.com/jdx/pacvamp/pull/2)
- add manual registry deployment dispatcher in [#45](https://github.com/jdx/pacvamp/pull/45)
- configure Entire search in [#48](https://github.com/jdx/pacvamp/pull/48)
- generate release notes with communique in [#49](https://github.com/jdx/pacvamp/pull/49)
- add Renovate config in [#50](https://github.com/jdx/pacvamp/pull/50)
- automate CLI releases in [#54](https://github.com/jdx/pacvamp/pull/54)
- **release:** bump packslip to v1.0.2 in [#69](https://github.com/jdx/pacvamp/pull/69)
- run mandatory Arch container acceptance tests on pull requests in [#62](https://github.com/jdx/pacvamp/pull/62)
- fix locked setup and streamline checks in [#70](https://github.com/jdx/pacvamp/pull/70)

### Other changes

- Integrate packslip v1 vendor and repackager bundles in [#36](https://github.com/jdx/pacvamp/pull/36)

### Security

- add PLAN.md in [#1](https://github.com/jdx/pacvamp/pull/1)
- **policy:** omapac-policy crate in [#12](https://github.com/jdx/pacvamp/pull/12)
- **aur:** review, approve, lockfile in [#13](https://github.com/jdx/pacvamp/pull/13)
- **cli:** audit in [#24](https://github.com/jdx/pacvamp/pull/24)
- show release version and GitHub stars in [#53](https://github.com/jdx/pacvamp/pull/53)
- enforce adversarial build acceptance checks in CI in [#56](https://github.com/jdx/pacvamp/pull/56)
- enforce conventional commits in [#65](https://github.com/jdx/pacvamp/pull/65)

### Testing

- **e2e:** omapac against real pacman in an Arch container in [#34](https://github.com/jdx/pacvamp/pull/34)
<!-- generated by git-cliff -->
