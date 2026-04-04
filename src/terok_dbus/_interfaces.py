# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""D-Bus interface definitions for terok Shield1 and Clearance1.

Canonical bus names, object paths, interface names, and introspection XML
for the terok D-Bus contracts. The XML strings allow proxy creation via
``dbus_fast.introspection.Node.parse()`` without runtime introspection of
the remote service.
"""

# ── Shield1 ────────────────────────────────────────────────────────────

SHIELD_BUS_NAME = "org.terok.Shield"
"""Well-known bus name for the shield D-Bus bridge."""

SHIELD_OBJECT_PATH = "/org/terok/Shield"
"""Object path for the Shield1 interface."""

SHIELD_INTERFACE_NAME = "org.terok.Shield1"
"""Versioned interface name for shield signals and methods."""

SHIELD_XML = """\
<node>
  <interface name="org.terok.Shield1">
    <signal name="ConnectionBlocked">
      <arg type="s" name="container" direction="out"/>
      <arg type="s" name="dest" direction="out"/>
      <arg type="q" name="port" direction="out"/>
      <arg type="q" name="proto" direction="out"/>
      <arg type="s" name="domain" direction="out"/>
      <arg type="s" name="request_id" direction="out"/>
    </signal>
    <method name="Verdict">
      <arg type="s" name="request_id" direction="in"/>
      <arg type="s" name="action" direction="in"/>
      <arg type="b" name="ok" direction="out"/>
    </method>
    <signal name="VerdictApplied">
      <arg type="s" name="container" direction="out"/>
      <arg type="s" name="dest" direction="out"/>
      <arg type="s" name="request_id" direction="out"/>
      <arg type="s" name="action" direction="out"/>
      <arg type="b" name="ok" direction="out"/>
    </signal>
  </interface>
</node>"""
"""Introspection XML for ``org.terok.Shield1``."""

# ── Clearance1 ─────────────────────────────────────────────────────────

CLEARANCE_BUS_NAME = "org.terok.Clearance"
"""Well-known bus name for the clearance daemon."""

CLEARANCE_OBJECT_PATH = "/org/terok/Clearance"
"""Object path for the Clearance1 interface."""

CLEARANCE_INTERFACE_NAME = "org.terok.Clearance1"
"""Versioned interface name for clearance signals and methods."""

CLEARANCE_XML = """\
<node>
  <interface name="org.terok.Clearance1">
    <signal name="RequestReceived">
      <arg type="s" name="request_id" direction="out"/>
      <arg type="s" name="project" direction="out"/>
      <arg type="s" name="task" direction="out"/>
      <arg type="s" name="dest" direction="out"/>
      <arg type="q" name="port" direction="out"/>
      <arg type="s" name="reason" direction="out"/>
    </signal>
    <method name="Resolve">
      <arg type="s" name="request_id" direction="in"/>
      <arg type="s" name="action" direction="in"/>
      <arg type="b" name="ok" direction="out"/>
    </method>
    <method name="ListPending">
      <arg type="a(ssssqs)" name="requests" direction="out"/>
    </method>
    <signal name="RequestResolved">
      <arg type="s" name="request_id" direction="out"/>
      <arg type="s" name="action" direction="out"/>
      <arg type="as" name="ips" direction="out"/>
    </signal>
  </interface>
</node>"""
"""Introspection XML for ``org.terok.Clearance1``."""
