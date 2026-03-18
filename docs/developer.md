# Contributing

## Development setup

```bash
git clone git@github.com:terok-ai/terok-dbus.git
cd terok-dbus
make install-dev
```

## Commands

```bash
# Before every commit
make lint             # ruff check + format check
make format           # auto-fix lint issues

# Before pushing
make test-unit        # unit tests with coverage
make check            # core local suite (lint + test-unit + tach + security + docstrings + deadcode + reuse)

# Other
make tach             # check module boundary rules
make security         # bandit SAST scan
make docstrings       # docstring coverage (95% minimum)
make reuse            # SPDX license compliance
make docs             # serve documentation locally
```

## Conventions

- **Python 3.12+** with modern type hints (`X | None`, not `Optional[X]`)
- **ruff** for linting and formatting (100 char line length)
- **SPDX headers** on all `.py` files — use `make spdx NAME="Real Human Name" FILES="path"`
- **Docstrings** on all public functions (95% coverage enforced in CI)
- **Module boundaries** enforced by tach (`tach.toml`) — run `make tach` after changing imports
- **Documentation filenames** under `docs/` use `lowercase.md` (e.g. `developer.md`) to match MkDocs convention; root-level files (`README.md`, `AGENTS.md`) stay UPPERCASE

## Testing

### Unit tests

```bash
make test-unit    # runs tests/ with coverage
```

Unit tests mock all D-Bus calls. No desktop session or notification daemon
required. Generated reports go under `reports/`.

## Architecture

### Module structure

```
_constants    — D-Bus bus name, object path, interface, close reason codes
_protocol     — Notifier Protocol (PEP 544, runtime_checkable)
_null         — NullNotifier (no-op fallback)
_notifier     — DesktopNotifier (dbus-fast implementation)
_cli          — terok-dbus-notify CLI (dev/testing tool)
__init__      — public API + create_notifier() factory
```

### Dependency rules (tach.toml)

```
_constants, _protocol, _null → no dependencies
_notifier → depends on _constants only
_cli → depends on terok_dbus (public API)
```
