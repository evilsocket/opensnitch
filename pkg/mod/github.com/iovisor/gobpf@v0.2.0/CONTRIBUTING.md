Please consider the following points for your pull requests:

* We aim to follow https://tbaggery.com/2008/04/19/a-note-about-git-commit-messages.html
  for commit messages, please try to write and format yours accordingly.
* Try to put relevant information for a change into the commit message.
  If your commit consists of multiple commits, it's OK to refer to the
  individual commits for context (i.e. no need to copy all information
  into the PR body).
* Prefix the subject line of your commit with the corresponding
  module (`bcc` or `elf`) if sensible.
* Don't mix different changes in a single commit (for example, a bug fix
  should not be mixed with a new feature).
* Rebase your branch to keep it up-to-date, don't merge master.
* Rebase your commits to keep the history clean and consistent, we
  don't merge "fixups" (for example a commit "Fixes from review").
