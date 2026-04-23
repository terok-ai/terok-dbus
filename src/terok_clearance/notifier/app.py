# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Bridge clearance-hub events to desktop popups.

Runs as ``terok-clearance-notifier.service`` — a systemd user unit
paired with the hub's own.  Splitting the roles means headless hosts
(CI, servers) run the hub without pulling in a desktop stack, and
notifier crashes never take the firewall or the hub with them.

Previously lived in the terok package; moved here because nothing in
the notifier is orchestration-specific — any clearance-capable
deployment (with or without terok) benefits from the desktop bridge,
and the task-name enrichment is fed through the
``ai.terok.task_meta_path`` annotation data contract (see
:mod:`terok_clearance.client.identity_resolver`).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging

from terok_clearance.client.identity_resolver import IdentityResolver
from terok_clearance.client.subscriber import EventSubscriber
from terok_clearance.domain.inspector import ContainerInspector, NullInspector
from terok_clearance.notifications.factory import create_notifier
from terok_clearance.notifications.protocol import Notifier
from terok_clearance.runtime.service import configure_logging, wait_for_shutdown_signal

_log = logging.getLogger(__name__)

#: Seconds granted to each teardown step during shutdown.  Prevents a
#: flaky session bus (unresponsive freedesktop notifications daemon,
#: hung varlink stream) from burning systemd's stop-sigterm deadline.
_CLEANUP_STEP_TIMEOUT_S = 2.0


async def run_notifier() -> None:
    """Run the notifier until SIGINT/SIGTERM."""
    configure_logging()
    notifier = await create_notifier("terok-clearance")
    inspector = _pick_inspector()
    subscriber = EventSubscriber(notifier, identity_resolver=IdentityResolver(inspector))
    try:
        await subscriber.start()
    except Exception:
        _log.exception("clearance subscriber failed to connect to hub — exiting")
        with contextlib.suppress(Exception):
            await notifier.disconnect()
        raise SystemExit(1) from None

    _log.info("terok-clearance-notifier online")
    try:
        await wait_for_shutdown_signal()
    finally:
        await _teardown(subscriber, notifier)


def _pick_inspector() -> ContainerInspector:
    """Return the best available :class:`ContainerInspector` at boot time.

    Runtime selection is a sandbox concern — if terok-sandbox is
    installed, its ``create_container_inspector`` factory hands back an
    implementation matched to the active runtime (podman today, krun
    or something else tomorrow).  Without sandbox, clearance still
    boots; notifications render with raw container ids via
    :class:`NullInspector`.
    """
    try:
        from terok_sandbox import create_container_inspector
    except ImportError:
        _log.info(
            "terok_sandbox not importable — running with NullInspector; "
            "notifications will carry container ids only"
        )
        return NullInspector()
    return create_container_inspector()


async def _teardown(subscriber: EventSubscriber, notifier: Notifier) -> None:
    """Stop subscriber + disconnect notifier under per-step timeouts."""
    for name, coro in (
        ("subscriber", subscriber.stop()),
        ("notifier", notifier.disconnect()),
    ):
        try:
            await asyncio.wait_for(coro, timeout=_CLEANUP_STEP_TIMEOUT_S)
        except TimeoutError:
            _log.warning(
                "clearance-notifier shutdown: %s didn't finish within %gs",
                name,
                _CLEANUP_STEP_TIMEOUT_S,
            )
        except Exception as exc:  # noqa: BLE001 — shutdown must continue past any step
            _log.warning("clearance-notifier shutdown: %s failed (%s)", name, exc)


def main() -> None:  # pragma: no cover — CLI entry point
    """Systemd-unit ``ExecStart`` target — launches :func:`run_notifier` on an event loop."""
    asyncio.run(run_notifier())


if __name__ == "__main__":
    # Without this guard ``python -m terok_clearance.notifier.app`` under
    # systemd would import the module, define ``main``, and exit 0 without
    # running it — the notifier silently never started and every desktop
    # popup went missing.
    main()
