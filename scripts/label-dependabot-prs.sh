#!/usr/bin/env bash
set -euo pipefail

BATCH_BRANCH="dependabot-batch"

prs=$(gh pr list --author "app/dependabot" --json number,title,headRefName --jq '.[]')

if [ -z "$prs" ]; then
  echo "No open Dependabot PRs found."
  exit 0
fi

semver_gt() {
  [ "$(printf '%s\n%s' "$1" "$2" | sort -V | tail -1)" = "$1" ] && [ "$1" != "$2" ]
}

bump_priority() {
  case "$1" in
    major) echo 3 ;;
    minor) echo 2 ;;
    patch) echo 1 ;;
    *)     echo 0 ;;
  esac
}

highest_label="patch"
valid_prs=()

while IFS= read -r pr; do
  number=$(echo "$pr" | jq -r '.number')
  title=$(echo "$pr" | jq -r '.title')
  branch=$(echo "$pr" | jq -r '.headRefName')
  package=$(echo "$title" | grep -oP 'Bump \K\S+' || echo "")
  to=$(echo "$title" | grep -oP 'to \K[\d]+\.[\d]+\.[\d]+' || echo "")

  if [ -z "$package" ] || [ -z "$to" ]; then
    echo "PR #$number: could not parse \"$title\", skipping."
    continue
  fi

  installed=$(yarn list --depth=0 2>/dev/null | grep -oP "(?<= )${package}@\K[\d]+\.[\d]+\.[\d]+" | head -1 || echo "")

  if [ -z "$installed" ]; then
    echo "PR #$number: $package not found in installed packages, skipping."
    continue
  fi

  if semver_gt "$installed" "$to" || [ "$installed" = "$to" ]; then
    echo "PR #$number: $package installed=$installed >= target=$to → closing as outdated"
    gh pr close "$number" --comment "Closing: installed version ($installed) is already at or above the target ($to)."
    continue
  fi

  from=$(echo "$title" | grep -oP 'from \K[\d]+\.[\d]+\.[\d]+' || echo "")
  from_major=$(echo "$from" | cut -d. -f1)
  from_minor=$(echo "$from" | cut -d. -f2)
  to_major=$(echo "$to" | cut -d. -f1)
  to_minor=$(echo "$to" | cut -d. -f2)

  if [ "$to_major" -gt "$from_major" ]; then
    label="major"
  elif [ "$to_minor" -gt "$from_minor" ]; then
    label="minor"
  else
    label="patch"
  fi

  if [ "$(bump_priority "$label")" -gt "$(bump_priority "$highest_label")" ]; then
    highest_label="$label"
  fi

  echo "PR #$number: $package $from → $to ($label)"
  valid_prs+=("$number:$branch")
done <<< "$prs"

if [ ${#valid_prs[@]} -eq 0 ]; then
  echo "No valid Dependabot PRs to batch."
  exit 0
fi

echo ""
echo "Creating batch branch '$BATCH_BRANCH' with label '$highest_label'..."

git fetch origin
git checkout -B "$BATCH_BRANCH" origin/main

for entry in "${valid_prs[@]}"; do
  number="${entry%%:*}"
  branch="${entry##*:}"
  echo "Merging PR #$number (branch: $branch)..."
  git fetch origin "$branch"
  git merge --no-edit "origin/$branch" || {
    echo "Merge conflict on PR #$number — skipping."
    git merge --abort
  }
done

git push -u origin "$BATCH_BRANCH"

gh pr create \
  --title "chore: batch Dependabot updates" \
  --body "Combines ${#valid_prs[@]} Dependabot PRs into a single release." \
  --label "$highest_label" \
  --base main \
  --head "$BATCH_BRANCH"

echo ""
echo "Closing individual Dependabot PRs..."
for entry in "${valid_prs[@]}"; do
  number="${entry%%:*}"
  gh pr close "$number" --comment "Closing in favour of batch PR on branch '$BATCH_BRANCH'."
done

echo ""
echo "Done. Merge the '$BATCH_BRANCH' PR to trigger a $highest_label release."
