# gitops-trust

The trust policy for the hosts that `Darkflib/gitops` deploys to: which container images may run,
and how each one is verified. [`policy.toml`](policy.toml) says what each image must be signed by.

This lives apart from the gitops repository on purpose. A verifier that reads its rules from the
tree it is verifying can be talked round by anyone who can write that tree. Here, the hosts' agent
(installed by infra-core at a pinned digest, not read from the gitops checkout) accepts only a
release of this repository, signed keyless by [`release.yml`](.github/workflows/release.yml) on
tag `vN`, where `N` is the `[release] version` written in the file itself. A host never goes
back to a lower version than the one it last accepted.

## Changing the policy

1. Open a PR that edits `policy.toml` and bumps `[release] version` by one. CI lints it
   ([`bin/lint.py`](bin/lint.py)).
2. Merge it, then tag the merge commit `v<version>` and push the tag. The release workflow signs
   and publishes; hosts pick it up on their next tick.
3. Only then open the gitops PR that pins an image the new rule covers: gitops CI checks pins
   against the latest release, so the order matters.

## Custody

Everything rests on who can push to `main` and push `v*` tags here, and on `release.yml`:

- No collaborators. No GitHub App or token used by gitops promotion has any access.
- A ruleset on `main`: PR required, required check `Policy lint`, no force pushes or deletions.
- A tag ruleset on `v*`: no updates or deletions, so a published version can't be re-pointed.
