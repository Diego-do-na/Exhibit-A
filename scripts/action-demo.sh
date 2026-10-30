#!/usr/bin/env bash
# Prepare the two demo branches for the live pull-request demo and print the commands to
# publish them. Run from a clean checkout:
#   scripts/action-demo.sh
# It only creates local branches and commits. It never pushes, never calls the GitHub API
# and never reads or writes a secret; the printed commands are for the owner to run.
#   BASE_BRANCH   branch the demo branches start from (default: main)
#   DEMO_PREFIX   branch name prefix (default: demo)
set -euo pipefail

base=${BASE_BRANCH:-main}
prefix=${DEMO_PREFIX:-demo}
app=examples/action-demo
vuln_branch="$prefix/path-traversal"
safe_branch="$prefix/harmless-refactor"

die() { echo "action-demo: $*" >&2; exit 1; }

root=$(git rev-parse --show-toplevel 2>/dev/null) || die "run it inside the repository"
cd "$root"
[[ -z "$(git status --porcelain)" ]] || die "the working tree is not clean; commit or stash first"
git rev-parse --verify --quiet "refs/heads/$base" > /dev/null || die "local branch '$base' does not exist"
git cat-file -e "$base:$app/pamphlets.py" 2> /dev/null || die "'$base' has no $app yet; merge the demo app first"
for branch in "$vuln_branch" "$safe_branch"; do
  if git rev-parse --verify --quiet "refs/heads/$branch" > /dev/null; then
    die "branch '$branch' already exists; delete it first (git branch -D $branch)"
  fi
done

# Read the patches once, from this checkout, so they can be applied after switching branches.
work=$(mktemp -d)
original=$(git symbolic-ref --quiet --short HEAD || git rev-parse HEAD)
cleanup() { git switch --quiet "$original" 2> /dev/null || true; rm -rf "$work"; }
trap cleanup EXIT
cp "$app/patches/01-path-traversal.patch" "$app/patches/02-harmless-refactor.patch" "$work/"

make_branch() {  # <branch> <patch file> <commit subject>
  git switch --quiet --create "$1" "$base"
  if ! git apply --index "$2"; then
    git switch --quiet "$original"
    git branch --quiet -D "$1"
    die "the patch $(basename "$2") does not apply to '$base'"
  fi
  git commit --quiet --no-verify -m "$3"
  echo "created $1 ($(git rev-parse --short HEAD))"
}

make_branch "$vuln_branch" "$work/01-path-traversal.patch" \
  "demo: serve pamphlets from nested folders"
make_branch "$safe_branch" "$work/02-harmless-refactor.patch" \
  "demo: tidy the pamphlet app"

cat <<MSG

Local branches are ready. Nothing was pushed. To publish and open the two pull requests
(this needs the gh CLI logged in to your account), run:

  git push -u origin $vuln_branch
  gh pr create --base $base --head $vuln_branch \\
    --title "Demo: serve pamphlets from nested folders (expected: red)" \\
    --body "Live demo of the Exhibit A Action. Expected: a proven path traversal, red check."

  git push -u origin $safe_branch
  gh pr create --base $base --head $safe_branch \\
    --title "Demo: tidy the pamphlet app (expected: green)" \\
    --body "Live demo of the Exhibit A Action. Expected: nothing could be proven, green check."

Full procedure: docs/ci/live-pr-demo.md
MSG
