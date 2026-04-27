# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Clearance-notifier daemon entrypoint.

The ``terok-clearance-notifier`` systemd user unit targets
[`terok_clearance.notifier.app.main`][terok_clearance.notifier.app.main].  Keeping the daemon in its
own feature dir (alongside ``hub/`` and ``verdict/``) mirrors the
lifecycle-split the rest of the clearance service uses.
"""
