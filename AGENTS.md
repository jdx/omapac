# Contributor instructions

## Commits

Pull request titles must use [Conventional Commits](https://www.conventionalcommits.org/); intermediate commit subjects should use the same format:

```text
<type>[optional scope][optional !]: <description>
```

Allowed types are `build`, `chore`, `ci`, `docs`, `feat`, `fix`, `perf`, `refactor`, `revert`, `style`, and `test`. Start the description with a lowercase character and keep it concise and imperative. Use `!` before the colon for a breaking change and explain the change in the commit body with a `BREAKING CHANGE:` footer.

Examples:

- `feat(cli): add package audit output`
- `fix!: reject unsigned repository metadata`
- `docs: clarify installation requirements`

CI validates the pull request title and re-runs when it is edited. Because pull
requests are squash-merged using their titles, intermediate commit subjects are
not validated. CI mechanically checks the allowed type, syntax, and
lowercase-leading description; imperative mood and breaking-change details
remain review rules.
