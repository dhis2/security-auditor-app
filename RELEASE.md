# Releasing a New Version

Releases are automated by [.github/workflows/release.yml](.github/workflows/release.yml). The workflow triggers when a PR is merged into `main` with a version label (`patch`, `minor`, or `major`). It bumps `package.json`, builds the app, tags the commit, and publishes a GitHub Release with the `.zip` artifact.

Direct pushes to `main` do NOT trigger the workflow — you must use a PR.

## Label → version bump

| Label   | Bump                                  | Use for                              |
| ------- | ------------------------------------- | ------------------------------------ |
| `patch` | `1.2.0` → `1.2.1`                     | Bug fixes, small tweaks              |
| `minor` | `1.2.0` → `1.3.0`                     | New features, backwards-compatible   |
| `major` | `1.2.0` → `2.0.0`                     | Breaking changes                     |

## Standard flow (clean branch, no manual version bump)

```bash
# 1. Create a feature branch and make changes
git checkout -b my-feature
# ... edit files ...
git add <files>
git commit -m "Describe the change"

# 2. Push the branch
git push -u origin my-feature

# 3. Open a PR
gh pr create --title "My feature" --base main --head my-feature --body ""

# 4. Apply a version label
gh pr edit --add-label minor   # or patch / major

# 5. Merge — workflow bumps version, tags, and publishes release
gh pr merge --merge --delete-branch
```

## Recovering when you've already committed to local `main`

If you committed straight to local `main` and haven't pushed yet, move the commits onto a feature branch:

```bash
# 1. Create a branch at the current HEAD (preserves your commits)
git checkout -b my-feature

# 2. Reset local main back to origin/main
git branch -f main origin/main

# 3. Push the feature branch
git push -u origin my-feature

# 4. Open the PR, label it, merge it (same as steps 3–5 above)
gh pr create --title "My feature" --base main --head my-feature --body ""
gh pr edit --add-label patch
gh pr merge --merge --delete-branch
```

If one of your local commits is a manual `package.json` version bump, you have two options:

- **Drop it** before pushing (recommended) — let the workflow do the bump:
  ```bash
  git reset --hard <sha-of-the-commit-before-the-version-bump>
  ```
- **Keep it** — apply a `patch` label so the workflow bumps once more on top (e.g. manual `1.2.0` + workflow patch = released as `1.2.1`).

## Manual release (no label, no workflow)

If you want to release without the automated workflow — for example, to ship exactly the version in `package.json` without a further bump — skip the label and tag manually:

```bash
git checkout main && git pull
VERSION=$(node -p "require('./package.json').version")
git tag "v$VERSION"
git push origin "v$VERSION"

# Build and attach the .zip to the release
yarn install --frozen-lockfile
yarn build
gh release create "v$VERSION" build/bundle/*.zip --generate-notes
```

## Bumping the version manually (outside a PR)

```bash
npm version patch --no-git-tag-version   # or minor / major
git add package.json
git commit -m "chore: bump version"
```

Then follow the standard PR flow above. Note this will result in a double bump if you also apply a version label — see the "Keep it" option in the recovery section.
