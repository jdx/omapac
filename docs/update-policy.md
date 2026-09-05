# Understanding blocked updates

`pacvamp update -n` and `pacvamp update --json` review AUR candidates and
show which ones unattended policy would block. They may fetch recipes and
signed feeds into the cache, but do not approve commits or install packages.
An interactive update can still ask you to review and approve warnings.

Each hold or AUR blocker includes the installed version that remains, the
reason, and the next action. A timed blocker includes its earliest eligible
UTC time. That time assumes the candidate and policy remain unchanged.
If any finding requires review or a policy change, waiting alone is not
reported as sufficient.

In JSON, `holds` covers repository age floors and configured holds;
`blocked` covers unattended AUR policy. Each contains `name`, `reason`,
`installed`, `eligible_at` (Unix seconds, or null), and `next_step`.
The AUR review command names the exact candidate commit. A preview does
not authorize a later build: execution reviews the candidate again.

Install-script denials remain policy denials even after commit approval.
Unapproved VCS recipes also require review unattended, because their
source content is not necessarily pinned by the recipe commit.
