#!/usr/bin/env python3
"""Check policy.toml before it is released (python3 bin/lint.py [--tag vN] [--after N]).

- it parses, and [release] version is a positive integer
- with --tag: the tag is exactly v<version>, so the signature names the version it vouches for
- with --after: the version is higher than the last release's, so hosts will accept it
- every keyless rule names one image and one repository's workflow, literally (no org-wide rule)
- every `attest` table is one promote.py can enforce

The last two repeat Darkflib/gitops's check.py, which runs them again on each release it
fetches. They are here so a bad rule is refused before it is signed, not after.
"""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from pathlib import Path

ATTEST_KINDS = ("github", "cosign")
SOURCE_REPO = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9._-]+")
ONE_IMAGE = re.compile(r"[^/]+/[^/]+/.*[^/]")
_NAME = r"((?:[A-Za-z0-9_-]|\\\.)+)"
ONE_WORKFLOW = re.compile(rf"\^https://github\\\.com/{_NAME}/{_NAME}/\\\.github/workflows/{_NAME}@refs/")
MODES = ("keyless", "key", "digest-only")


def kinds(value: object) -> list[str] | None:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and value and all(isinstance(v, str) for v in value):
        return list(value)
    return None


def rule_problems(rule: dict) -> list[str]:
    problems = []
    mode = rule.get("mode", "keyless")
    if not isinstance(rule.get("prefix"), str) or not rule["prefix"]:
        return ["a rule needs a prefix"]
    if mode not in MODES:
        problems.append(f"mode = {mode!r} isn't one of {', '.join(MODES)}")
    if mode == "keyless":
        if not ONE_IMAGE.fullmatch(rule["prefix"]):
            problems.append("a keyless prefix must name one image (registry/owner/image), not an org or registry")
        identity = rule.get("identity", "")
        m = ONE_WORKFLOW.match(identity)
        if not m or not identity.endswith("$"):
            problems.append(r"a keyless identity must be anchored and name one repository and one workflow: "
                            r"'^https://github\.com/<owner>/<repo>/\.github/workflows/<file>@refs/<ref>$'")
        else:
            repo = f"{m[1]}/{m[2]}".replace("\\", "")
            source = rule.get("attest", {}).get("source") if isinstance(rule.get("attest"), dict) else None
            if source is not None and repo != source:
                problems.append(f"its identity names {repo}, but attest.source is {source}")
    if mode == "key" and not rule.get("key"):
        problems.append("mode = \"key\" needs key = <path on the host>")
    attest = rule.get("attest")
    if attest is None:
        return problems
    if not isinstance(attest, dict):
        return problems + ["attest must be a table"]
    problems += [f"attest.{k} isn't a known key" for k in attest if k not in ("provenance", "sbom", "source")]
    if mode != "keyless":
        problems.append("attest needs mode = \"keyless\"")
    for what in ("provenance", "sbom"):
        if what in attest:
            got = kinds(attest[what])
            if got is None:
                problems.append(f"attest.{what} must be a kind or a list of kinds")
            else:
                problems += [f"attest.{what} = {k!r} isn't supported (only: {', '.join(ATTEST_KINDS)})"
                             for k in got if k not in ATTEST_KINDS]
    if "provenance" not in attest and "sbom" not in attest:
        problems.append("attest requires nothing: set provenance and/or sbom, or remove the table")
    source = attest.get("source")
    if "provenance" in attest and source is None:
        problems.append("attest.source (owner/repo) is needed with provenance")
    if source is not None and not (isinstance(source, str) and SOURCE_REPO.fullmatch(source)):
        problems.append(f"attest.source = {source!r} must be owner/repo")
    return problems


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("policy", nargs="?", type=Path, default=Path(__file__).resolve().parent.parent / "policy.toml")
    ap.add_argument("--tag", help="the tag being released: must be v<version>")
    ap.add_argument("--after", type=int, help="the last released version: this one must be higher")
    args = ap.parse_args(argv)
    try:
        data = tomllib.loads(args.policy.read_text())
    except tomllib.TOMLDecodeError as e:
        print(f"::error::policy.toml doesn't parse: {e}")
        return 1
    problems = []
    version = data.get("release", {}).get("version")
    if type(version) is not int or version < 1:
        problems.append("[release] version must be a positive integer")
    else:
        if args.tag is not None and args.tag != f"v{version}":
            problems.append(f"tag {args.tag} isn't v{version}, the version policy.toml names")
        if args.after is not None and version <= args.after:
            problems.append(f"version {version} isn't higher than the last release's, {args.after}: hosts would refuse it")
    rules = data.get("image", [])
    prefixes = [r.get("prefix") for r in rules]
    problems += [f"prefix {p!r} has more than one rule" for p in sorted({p for p in prefixes if prefixes.count(p) > 1})]
    for rule in rules:
        problems += [f"rule {rule.get('prefix')!r}: {p}" for p in rule_problems(rule)]
    for p in problems:
        print(f"::error::{p}")
    print(f"policy v{version}: {len(rules)} rule(s), {len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
