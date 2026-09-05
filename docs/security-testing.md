# Security acceptance tests

The Linux CI test job sets `PACVAMP_REQUIRE_JAIL=1`. A kernel that cannot
fully enforce the requested Landlock and seccomp rules fails that job;
it cannot silently skip the sandbox tests. Local development may skip
unsupported kernels, with a message.

Run the security boundary tests with:

```sh
PACVAMP_REQUIRE_JAIL=1 cargo test -p pacvamp --all-features --test jail --test aur_build
```

With Docker available, also run `PACVAMP_E2E_CONTAINER=1 bash e2e/run_all_tests`
after building the workspace. The Arch container exercises real makepkg and
fakeroot as a non-root user, including credential and shared-scratch denial.

| Guarantee | Adversarial test |
| --- | --- |
| Network permission does not grant credential-file access | Direct and symlink reads of a fake credential, with network enabled and disabled |
| A build cannot change another build's scratch files | Writes outside its allowed tree are refused |
| Verified sources stay read-only during building | Read succeeds; attempted replacement fails |
| Recipe top-level code is confined in every phase | Source verification, build, and output listing attempt credential reads, parent-environment reads, and unrelated writes |
| Approval belongs to the reviewed commit | A changed recipe cannot reuse an earlier approval |
| Only this build's regular package outputs may be returned | A fake makepkg names an unrelated package; no pacman install occurs |

These tests use synthetic credentials and local fixtures. They verify specific
boundaries, not that arbitrary installed packages are safe. The jail does not
provide a complete process or Unix-socket namespace. Custom build tools outside
the allowed system runtime paths may need a separate, explicitly designed
integration; do not solve compatibility failures by granting filesystem-root access.
