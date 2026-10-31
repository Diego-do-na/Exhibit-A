# Verified fix pull requests

Set `suggest-fixes: "true"` to post the verified `fix.patch` hunks as GitHub
review suggestions. Hunks that do not overlap a line changed by the pull
request are posted as ordinary comments because GitHub cannot anchor them to
the review diff.

Set `open-fix-pr: "true"` to create a branch named
`exhibit-a/fix-<pr>-<finding>`. The branch contains the verified patch and the
proof exploit copied to `tests/exhibit_a/` as a regression test. The action
opens a pull request against the original PR's base branch. Both features
require the calling workflow to grant `pull-requests: write`; opening a fix
PR additionally requires `contents: write`.

Fork pull requests are always excluded. The action checks that the PR head
repository is the current repository before posting suggestions or pushing a
branch. The proof test is copied exactly from the verified bundle; it is
expected to pass on the fixed corpus tree.
