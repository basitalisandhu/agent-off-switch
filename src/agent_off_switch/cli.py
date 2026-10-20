"""The aos command: inventory, review, off and drift over a folder of saved exports."""

from __future__ import annotations

import argparse
import difflib
import sys
from pathlib import Path

from . import __version__, drift, inventory, review, runbook
from .exports import find_identity
from .util import InputError, as_of, write_text

# How alike a name must be to be offered as "did you mean" (difflib ratio; 0.6 is the difflib default).
SUGGEST_CUTOFF = 0.6

EXIT_HELP = "Exit codes: 0 nothing to act on, 1 something needs a person, 2 bad input."


def _common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--as-of", metavar="YYYY-MM-DD", help="date the exports are judged against (default today, UTC)")
    p.add_argument(
        "--unused-days", type=int, default=90, metavar="N", help="days without use that count as unused (90)"
    )
    p.add_argument(
        "--max-credential-age", type=int, default=90, metavar="N", help="days after which a credential is stale (90)"
    )
    p.add_argument(
        "--include-aws-managed-roles",
        action="store_true",
        help="keep AWS service-linked and IAM Identity Center roles (skipped by default)",
    )
    p.add_argument("--out", metavar="FILE", help="write to FILE instead of standard output")


def parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="aos",
        description="Find every AI agent identity in Microsoft 365, AWS and GitHub from saved exports, see what it "
        "can reach, and print the runbook to switch it off. Reads files only; runs no cloud command.",
        epilog=EXIT_HELP,
    )
    ap.add_argument("--version", action="version", version=f"aos {__version__}")
    sub = ap.add_subparsers(dest="command", required=True, metavar="COMMAND")

    p = sub.add_parser("inventory", help="table of every agent identity", epilog=EXIT_HELP)
    p.add_argument("exports", help="folder of saved exports (see docs/exports.md)")
    p.add_argument("--format", choices=("md", "csv", "json"), default="md")
    p.add_argument("--agents-only", action="store_true", help="only identities that look like agents")
    p.add_argument("--fail-on-flags", action="store_true", help="exit 1 when an identity is flagged")
    _common(p)

    p = sub.add_parser("review", help="findings ranked by blast radius, with the fix for each", epilog=EXIT_HELP)
    p.add_argument("exports", help="folder of saved exports, or an inventory JSON file")
    p.add_argument("--format", choices=("md", "json", "sarif"), default="md")
    p.add_argument(
        "--fail-on",
        choices=review.LEVELS,
        default="error",
        help="exit 1 when a finding is at or above this level (default error; none never fails)",
    )
    _common(p)

    p = sub.add_parser("off", help="print the ordered off-switch runbook for one identity", epilog=EXIT_HELP)
    p.add_argument("exports", help="folder of saved exports, or an inventory JSON file")
    p.add_argument("identity", help="identity id, name, app id, object id, ARN or role name")
    p.add_argument("--format", choices=("md", "json"), default="md")
    _common(p)

    p = sub.add_parser("drift", help="compare two inventories; exit 1 on unreviewed changes", epilog=EXIT_HELP)
    p.add_argument("old", help="earlier inventory JSON (or export folder)")
    p.add_argument("new", help="later inventory JSON (or export folder)")
    p.add_argument("--accept", metavar="FILE", help="reviewed changes, one key per line")
    p.add_argument("--format", choices=("md", "json"), default="md")
    _common(p)
    return ap


def _load(source: str, args) -> inventory.Inventory:
    return inventory.load(
        Path(source),
        as_of(args.as_of),
        unused_days=args.unused_days,
        max_credential_age=args.max_credential_age,
        include_aws_managed_roles=args.include_aws_managed_roles,
    )


def run(args) -> int:
    if args.command == "inventory":
        inv = _load(args.exports, args)
        if args.agents_only:
            inv.identities = [i for i in inv.identities if i.agent]
        render = {"md": inventory.to_markdown, "csv": inventory.to_csv, "json": inventory.to_json}[args.format]
        write_text(render(inv), args.out)
        flagged = any({"no-owner", "unused", "never-used", "stale-credential"} & set(i.flags) for i in inv.identities)
        return 1 if args.fail_on_flags and flagged else 0
    if args.command == "review":
        inv = _load(args.exports, args)
        found = review.review(inv)
        if args.format == "sarif":
            text = review.to_sarif(inv, found)
        elif args.format == "json":
            text = review.to_json(inv, found)
        else:
            text = review.to_markdown(inv, found, args.exports)
        write_text(text, args.out)
        return review.exit_code(found, args.fail_on)
    if args.command == "off":
        inv = _load(args.exports, args)
        ident = find_identity({i.id: i for i in inv.identities}, args.identity)
        if ident is None:
            names = list(dict.fromkeys([i.id for i in inv.identities] + [i.name for i in inv.identities]))
            near = difflib.get_close_matches(args.identity, names, n=3, cutoff=SUGGEST_CUTOFF)
            hint = f"; did you mean {', '.join(near)}?" if near else "; run aos inventory to list identities"
            raise InputError(f"no identity {args.identity!r} in {args.exports}{hint}")
        rb = runbook.runbook(ident)
        text = runbook.to_json(rb, inv.as_of) if args.format == "json" else runbook.to_markdown(rb, inv.as_of)
        write_text(text, args.out)
        return 1 if rb.not_covered else 0
    if args.command == "drift":
        old, new = _load(args.old, args), _load(args.new, args)
        accepted = drift.load_accepted(Path(args.accept) if args.accept else None)
        changes = drift.compare(old, new, accepted)
        text = drift.to_json(old, new, changes) if args.format == "json" else drift.to_markdown(old, new, changes)
        write_text(text, args.out)
        return 1 if drift.unreviewed(changes) else 0
    raise InputError(f"unknown command {args.command}")


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return run(args)
    except InputError as exc:
        print(f"aos {args.command}: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"aos {args.command}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
