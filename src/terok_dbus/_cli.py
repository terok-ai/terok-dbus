# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""CLI entry point for ``terok-dbus`` — desktop notification tools.

Builds the argument parser from the :data:`COMMANDS` registry so the
standalone CLI and the terok integration layer share a single source
of truth for subcommand definitions.
"""

import argparse
import asyncio
import sys

from terok_dbus._registry import COMMANDS, ArgDef


def _add_arg(parser: argparse.ArgumentParser, arg: ArgDef) -> None:
    """Register an :class:`ArgDef` with an argparse parser."""
    kwargs: dict = {}
    if arg.help:
        kwargs["help"] = arg.help
    for field in ("type", "default", "action", "dest", "nargs"):
        val = getattr(arg, field)
        if val is not None:
            kwargs[field] = val
    # Support multiple flag names separated by "/" (e.g. "-t/--timeout")
    names = arg.name.split("/")
    parser.add_argument(*names, **kwargs)


def _build_parser() -> argparse.ArgumentParser:
    """Build the top-level argument parser from the command registry."""
    parser = argparse.ArgumentParser(
        prog="terok-dbus",
        description="Desktop notification tools for the terok ecosystem.",
    )
    sub = parser.add_subparsers(dest="command")

    for cmd in COMMANDS:
        cmd_parser = sub.add_parser(cmd.name, help=cmd.help)
        for arg in cmd.args:
            _add_arg(cmd_parser, arg)

    return parser


def main() -> None:
    """Entry point for ``terok-dbus``."""
    parser = _build_parser()
    args = parser.parse_args()

    cmd_lookup = {cmd.name: cmd for cmd in COMMANDS}
    cmd_def = cmd_lookup.get(args.command)

    if cmd_def is None or cmd_def.handler is None:
        parser.print_help()
        sys.exit(2)

    # Build kwargs from parsed args, excluding the 'command' key
    kwargs = {k: v for k, v in vars(args).items() if k != "command"}

    try:
        asyncio.run(cmd_def.handler(**kwargs))
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
