# Contributing

This repository uses a **Shared Repository + Feature Branch** workflow. Everyone
listed below clones the same repository and pushes branches directly to it
(no forks needed).

## Team

| Role | GitHub username |
| --- | --- |
| Maintainer | [@anonymous-author](https://github.com/anonymous-author) |
| Contributor | [@md-jakir84](https://github.com/md-jakir84) |

## Rules

1. **Nobody pushes directly to `main`.** Branch protection enforces this for
   every collaborator, including admins — direct pushes to `main` are
   rejected by GitHub.
2. **All work happens on a feature branch**, created locally from an
   up-to-date `main`:

   ```bash
   git checkout main
   git pull origin main
   git checkout -b feature/<short-description>   # e.g. feature/login
   ```

3. **When the feature is ready**, push the branch and open a Pull Request
   (PR) into `main`:

   ```bash
   git push -u origin feature/<short-description>
   gh pr create --base main --fill
   ```

   (Or open the PR from the GitHub UI — it will show a "Compare & pull
   request" prompt for the pushed branch.)

4. **At least 1 other teammate must review and approve** the PR before it
   can be merged. GitHub blocks the merge button until that approval is
   given. Once the team grows to three active collaborators, bump the
   required approval count to 2 (see below) so both other members sign off.
5. Pushing new commits to a PR after it was approved **dismisses stale
   reviews** — get it re-approved before merging.
6. Resolve all review conversations before merging (also enforced).
7. Prefer small, focused PRs over large ones — they're faster to review.

## Branch naming

Use a short, descriptive prefix:

- `feature/<name>` — new functionality
- `fix/<name>` — bug fixes
- `docs/<name>` — documentation-only changes

## Branch protection settings (for reference)

Configured on `main` via the GitHub API:

- Require a pull request before merging
- Require **1** approving review (raise to 2 once the 3rd teammate has
  write access — see command below)
- Dismiss stale approvals when new commits are pushed
- Require approval of the most recent push
- Require conversation resolution before merging
- Enforce these rules for admins too
- Disallow force pushes and branch deletion

To raise the required approvals to 2 once everyone has access:

```bash
gh api repos/anonymous-author/eviassure/branches/main/protection/required_pull_request_reviews \
  -X PATCH -f required_approving_review_count=2
```

To add the third teammate as a collaborator:

```bash
gh api repos/anonymous-author/eviassure/collaborators/<username> -X PUT -f permission=push
```
