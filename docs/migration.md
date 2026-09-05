# Import an existing machine

Start with a preview:

```sh
pacvamp import
pacvamp import --json
```

Import considers explicitly installed packages only, so dependencies stay
dependencies. It matches names against current repository databases and
queries AUR metadata for foreign packages. Use `--offline` to skip the
AUR lookup. Unknown foreign packages remain unresolved and are not added.

The preview shows missing recorded provenance and marks packages unreviewed.
A repository or AUR name match identifies a possible source for future
operations; it does not authenticate the binary already installed.

Save the additions when the preview matches your intent:

```sh
pacvamp import --write
pacvamp plan
```

Saving changes only your user manifest. Existing declarations in any layer,
including absent entries, holds, and source choices, are preserved. Comments
and settings in the user manifest are retained. Import does not install
anything, change install reasons, create a lockfile approval, or write provenance.
Review AUR recipes with `pacvamp aur review <name>` before approving a commit.
