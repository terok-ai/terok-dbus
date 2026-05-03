#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0
#
# Install terok-clearance's optional MAC hardening assets.
#
# Parallel of terok-sandbox's ``install_hardening.sh``, scoped to
# clearance's own units (``terok-clearance-hub.service``,
# ``terok-clearance-notifier.service``).  Hub and notifier each get a
# confined SELinux domain or AppArmor profile; the verdict daemon is
# intentionally NOT confined because it execs ``terok-shield
# allow|deny`` (``podman unshare nsenter nft``) which doesn't
# tolerate tight labelling — see the unit comment in
# ``terok-clearance-verdict.service``.
#
# Two scripts (sandbox + clearance) instead of one because each
# package owns its own assets and units; a user who installs only
# clearance shouldn't depend on sandbox files.  ``terok setup``
# orchestrates running both when the full stack is installed.
#
# Coordination note: drop-in qualifier ``hardening-mac.conf`` is
# distinct from any future drop-in layer (auditd, namespacing tweaks
# would get their own qualifier).  Clearance unit templates already
# carry strong systemd-native hardening
# (``ProtectSystem=full``, ``MemoryDenyWriteExecute=yes``, …); this
# layer stacks on top, doesn't substitute.
#
# Usage:
#
#     sudo bash /path/to/install_hardening.sh           # install
#     sudo bash /path/to/install_hardening.sh --remove  # uninstall

set -euo pipefail

# -------- ANSI helpers ----------------------------------------------------

if [[ -t 1 ]]; then
    _bold=$'\033[1m' _dim=$'\033[2m' _reset=$'\033[0m'
    _green=$'\033[32m' _yellow=$'\033[33m' _red=$'\033[31m'
else
    _bold="" _dim="" _reset="" _green="" _yellow="" _red=""
fi

log()  { echo "${_bold}==>${_reset} $*"; }
info() { echo "    $*"; }
warn() { echo "${_yellow}    warn:${_reset} $*" >&2; }
ok()   { echo "${_green}    ok:${_reset} $*"; }
die()  { echo "${_red}error:${_reset} $*" >&2; exit 1; }

# -------- Action selection ------------------------------------------------

ACTION=install
case "${1:-}" in
    "")          ;;
    --install)   ACTION=install ;;
    --remove)    ACTION=remove ;;
    --uninstall) ACTION=remove ;;
    *)           die "unknown argument: $1 (try --install or --remove)" ;;
esac

# -------- Anti-tampering integrity checks ---------------------------------

assert_safe_path() {
    local f=$1
    if [[ -L "$f" ]]; then
        die "$f is a symlink; refuse to load attacker-redirectable content"
    fi
    if [[ ! -f "$f" ]]; then
        die "$f is not a regular file"
    fi
    local _perm
    _perm=$(stat -c '%a' "$f")
    if (( 8#$_perm & 8#022 )); then
        die "$f is group/world-writable (mode $_perm); refuse to load"
    fi
    local _dir_perm
    _dir_perm=$(stat -c '%a' "$(dirname "$f")")
    if (( 8#$_dir_perm & 8#022 )); then
        die "parent of $f is group/world-writable (mode $_dir_perm); refuse to load"
    fi
}

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
assert_safe_path "${BASH_SOURCE[0]}"

selinux_dir="${script_dir}/selinux"
apparmor_dir="${script_dir}/apparmor"

# -------- Invoking-user discovery -----------------------------------------

resolve_invoking_user() {
    if [[ -z "${SUDO_USER:-}" ]] || [[ "${SUDO_USER}" == "root" ]]; then
        die "must be run via 'sudo' from a regular user, not as root directly"
    fi
    local _home
    _home=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    if [[ -z "$_home" ]] || [[ ! -d "$_home" ]]; then
        die "could not resolve home directory for user '$SUDO_USER'"
    fi
    echo "$_home"
}

# -------- Backend detection -----------------------------------------------

has_selinux() { [[ -r /sys/fs/selinux/enforce ]]; }
has_apparmor() {
    [[ -d /sys/kernel/security/apparmor ]] && command -v apparmor_parser >/dev/null 2>&1
}

# -------- SELinux module install / remove ---------------------------------

SELINUX_MODULES=(terok_clearance_hub terok_clearance_notifier)
SELINUX_PERMISSIVE_DOMAINS=(terok_clearance_hub_t terok_clearance_notifier_t)

selinux_install() {
    has_selinux || { info "SELinux not active; skipping SELinux modules"; return; }
    log "Installing SELinux modules"

    for tool in checkmodule semodule_package semodule semanage; do
        command -v "$tool" >/dev/null 2>&1 \
            || die "$tool not found (need: dnf install selinux-policy-devel policycoreutils-python-utils)"
    done

    local workdir
    workdir=$(mktemp -d -t terok-clearance-hardening-XXXXXX)
    trap 'rm -rf "$workdir"' EXIT

    local mod
    for mod in "${SELINUX_MODULES[@]}"; do
        local te="${selinux_dir}/${mod}.te"
        [[ -f "$te" ]] || { warn "missing ${mod}.te; skipping"; continue; }
        assert_safe_path "$te"

        info "compiling ${mod}.te"
        checkmodule -M -m -o "${workdir}/${mod}.mod" "$te"
        semodule_package -o "${workdir}/${mod}.pp" -m "${workdir}/${mod}.mod"

        info "loading ${mod}"
        semodule -i "${workdir}/${mod}.pp"
    done

    local dom
    for dom in "${SELINUX_PERMISSIVE_DOMAINS[@]}"; do
        info "marking $dom permissive (initial soak posture)"
        semanage permissive -a "$dom" 2>/dev/null \
            || warn "could not mark $dom permissive (already set?)"
    done

    ok "SELinux modules loaded: ${SELINUX_MODULES[*]}"
}

selinux_remove() {
    has_selinux || return
    log "Removing SELinux modules"
    local mod
    for mod in "${SELINUX_MODULES[@]}"; do
        if semodule -l 2>/dev/null | grep -qwF "$mod"; then
            info "unloading $mod"
            semodule -r "$mod" 2>/dev/null || warn "semodule -r $mod failed"
        fi
    done
    local dom
    for dom in "${SELINUX_PERMISSIVE_DOMAINS[@]}"; do
        semanage permissive -d "$dom" 2>/dev/null || true
    done
    ok "SELinux modules removed"
}

# -------- AppArmor profile install / remove -------------------------------

APPARMOR_PROFILES=(terok-clearance-hub terok-clearance-notifier)

apparmor_install() {
    has_apparmor || { info "AppArmor not active; skipping AppArmor profiles"; return; }
    log "Installing AppArmor profiles"

    install -d -m 0755 /etc/apparmor.d
    local prof
    for prof in "${APPARMOR_PROFILES[@]}"; do
        local src="${apparmor_dir}/${prof}"
        [[ -f "$src" ]] || { warn "missing profile $prof; skipping"; continue; }
        assert_safe_path "$src"
        info "loading profile $prof"
        install -m 0644 "$src" "/etc/apparmor.d/${prof}"
        apparmor_parser -r "/etc/apparmor.d/${prof}"
        if command -v aa-complain >/dev/null 2>&1; then
            aa-complain "/etc/apparmor.d/${prof}" >/dev/null
        fi
    done
    ok "AppArmor profiles loaded: ${APPARMOR_PROFILES[*]}"
}

apparmor_remove() {
    has_apparmor || return
    log "Removing AppArmor profiles"
    local prof
    for prof in "${APPARMOR_PROFILES[@]}"; do
        local installed="/etc/apparmor.d/${prof}"
        if [[ -f "$installed" ]]; then
            info "unloading $prof"
            apparmor_parser -R "$installed" 2>/dev/null || warn "apparmor_parser -R $prof failed"
            rm -f "$installed"
        fi
    done
    ok "AppArmor profiles removed"
}

# -------- systemd unit drop-ins -------------------------------------------
#
# Verdict service is NOT in this list — see header comment.

SERVICE_UNITS=(
    "terok-clearance-hub.service:terok_clearance_hub_t:terok-clearance-hub"
    "terok-clearance-notifier.service:terok_clearance_notifier_t:terok-clearance-notifier"
)

dropin_install() {
    local user_home=$1
    local unit_dir="${user_home}/.config/systemd/user"
    [[ -d "$unit_dir" ]] || {
        warn "$unit_dir missing — install clearance units first"
        warn "  (terok-clearance-hub install-service as $SUDO_USER)"
        return
    }

    log "Installing systemd unit overrides"
    local entry unit selinux_type apparmor_profile
    for entry in "${SERVICE_UNITS[@]}"; do
        IFS=: read -r unit selinux_type apparmor_profile <<<"$entry"
        local d="${unit_dir}/${unit}.d"
        install -d -m 0755 -o "$SUDO_USER" -g "$SUDO_USER" "$d"
        local f="${d}/hardening-mac.conf"
        {
            echo "# Installed by terok-clearance install_hardening.sh"
            echo "[Service]"
            # Best-effort SELinuxContext (leading '-') — see sandbox
            # script's matching comment for the rationale.
            has_selinux  && echo "SELinuxContext=-system_u:system_r:${selinux_type}:s0"
            has_apparmor && echo "AppArmorProfile=${apparmor_profile}"
        } >"$f"
        chown "$SUDO_USER:$SUDO_USER" "$f"
        chmod 0644 "$f"
        info "wrote $f"
    done
    ok "drop-ins installed; run as $SUDO_USER:"
    ok "  systemctl --user daemon-reload && systemctl --user restart terok-clearance-hub terok-clearance-notifier"
}

dropin_remove() {
    local user_home=$1
    local unit_dir="${user_home}/.config/systemd/user"
    [[ -d "$unit_dir" ]] || return

    log "Removing systemd unit overrides"
    local entry unit
    for entry in "${SERVICE_UNITS[@]}"; do
        IFS=: read -r unit _ _ <<<"$entry"
        local f="${unit_dir}/${unit}.d/hardening-mac.conf"
        if [[ -f "$f" ]]; then
            rm -f "$f"
            rmdir --ignore-fail-on-non-empty "${unit_dir}/${unit}.d" 2>/dev/null || true
            info "removed $f"
        fi
    done
    ok "drop-ins removed"
}

# -------- Main ------------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
    die "must be run as root (use 'sudo bash $0')"
fi

user_home=$(resolve_invoking_user)

case "$ACTION" in
    install)
        selinux_install
        apparmor_install
        dropin_install "$user_home"
        echo
        log "${_green}terok-clearance hardening installed.${_reset}"
        info "Status:    ${_dim}terok sickbay${_reset}"
        info "Soak:      domains start in permissive (SELinux) / complain (AppArmor)"
        info "Uninstall: ${_dim}sudo bash $0 --remove${_reset}"
        ;;
    remove)
        dropin_remove "$user_home"
        apparmor_remove
        selinux_remove
        echo
        log "${_green}terok-clearance hardening removed.${_reset}"
        ;;
esac
