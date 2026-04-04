#!/bin/bash
# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0
#
# Multi-distro integration test runner for terok-dbus.
#
# Builds test containers for each target distro and runs the
# unit + integration test suite inside them.  Each container
# provides a D-Bus session bus and dunst notification daemon.
#
# Usage:
#   ./tests/containers/run-matrix.sh              # run all distros
#   ./tests/containers/run-matrix.sh debian12      # run one distro
#   ./tests/containers/run-matrix.sh --build-only  # build images only
#   ./tests/containers/run-matrix.sh --list        # list available distros

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
IMAGE_PREFIX="terok-dbus-test"
SOURCE_MOUNT="/src"
WORKSPACE_DIR="/workspace"
PYTHON_VERSION="3.12"

# ── Terminal colors (disabled when stdout is not a tty) ──
if [[ -t 1 ]]; then
    C_BOLD='\033[1m'
    C_CYAN='\033[1;36m'
    C_YELLOW='\033[1;33m'
    C_GREEN='\033[1;32m'
    C_RED='\033[1;31m'
    C_DIM='\033[2m'
    C_RESET='\033[0m'
else
    C_BOLD='' C_CYAN='' C_YELLOW='' C_GREEN='' C_RED='' C_DIM='' C_RESET=''
fi

# Target distros: name -> Containerfile suffix
declare -A DISTROS=(
    [debian12]="debian12"
    [ubuntu2404]="ubuntu2404"
    [debian13]="debian13"
    [fedora43]="fedora43"
    [podman]="podman"
)

# Expected platform info (for reporting)
declare -A EXPECTED_PLATFORMS=(
    [debian12]="Debian 12 Bookworm"
    [ubuntu2404]="Ubuntu 24.04 Noble"
    [debian13]="Debian 13 Trixie"
    [fedora43]="Fedora 43"
    [podman]="Podman stable (rawhide)"
)

# Non-root user baked into each Containerfile.
# The podman image uses its pre-existing 'podman' user.
declare -A TEST_USERS=(
    [debian12]="testrunner"
    [ubuntu2404]="testrunner"
    [debian13]="testrunner"
    [fedora43]="testrunner"
    [podman]="podman"
)

usage() {
    echo "Usage: $0 [OPTIONS] [DISTRO...]"
    echo ""
    echo "Options:"
    echo "  --build-only   Build images without running tests"
    echo "  --no-cache     Rebuild images from scratch (ignore layer cache)"
    echo "  --list         List available distros"
    echo "  --unit-only    Run only unit tests (fast)"
    echo "  --integ-only   Run only integration tests"
    echo "  -h, --help     Show this help"
    echo ""
    echo "Default: run unit + integration tests."
    echo ""
    echo "Available distros: ${!DISTROS[*]}"
    return 0
}

warn_keyring() {
    # Warn when the host's containers.conf does not disable kernel keyrings.
    # Matrix runs cycle many containers and can exhaust the per-user 200-key
    # quota, causing misleading "Disk quota exceeded" (EDQUOT) from crun.
    local conf="${CONTAINERS_CONF:-}"
    if [[ -z "$conf" ]]; then
        for candidate in "$HOME/.config/containers/containers.conf" \
                         /etc/containers/containers.conf; do
            [[ -f "$candidate" ]] && conf="$candidate" && break
        done
    fi
    if [[ -z "$conf" ]] || ! grep -qE '^\s*keyring\s*=\s*false' "$conf" 2>/dev/null; then
        echo -e "${C_YELLOW}WARNING: kernel keyring is not disabled in containers.conf"
        echo -e ""
        echo -e "  Matrix tests create many containers and may exhaust the per-user"
        echo -e "  keyring quota (200 keys), causing spurious EDQUOT errors."
        echo -e ""
        echo -e "  Add to ${C_BOLD}~/.config/containers/containers.conf${C_YELLOW}:"
        echo -e ""
        echo -e "    ${C_BOLD}[containers]${C_YELLOW}"
        echo -e "    ${C_BOLD}keyring = false${C_YELLOW}"
        echo -e ""
        echo -e "  See: https://terok-ai.github.io/terok/kernel-keyring/${C_RESET}"
        echo ""
    fi
}

build_image() {
    local name="$1"
    local file="$SCRIPT_DIR/Containerfile.${DISTROS[$name]}"
    local image="$IMAGE_PREFIX:$name"
    local -a build_args=()

    $NO_CACHE && build_args+=(--no-cache)

    echo -e "${C_CYAN}==> Building ${C_BOLD}$image${C_CYAN} from $file${C_RESET}"
    podman build "${build_args[@]}" -t "$image" -f "$file" "$REPO_ROOT"
    return $?
}

run_tests() {
    local name="$1"
    local test_scope="${2:-all}"
    local image="$IMAGE_PREFIX:$name"
    local ctr_name="$IMAGE_PREFIX-$name"
    local test_user="${TEST_USERS[$name]}"

    echo ""
    echo -e "${C_CYAN}==> Testing ${C_BOLD}$name${C_CYAN} (${EXPECTED_PLATFORMS[$name]})${C_RESET}"
    echo -e "    ${C_DIM}scope: $test_scope, user: $test_user${C_RESET}"
    echo ""

    podman run --rm --name "$ctr_name" \
        -v "$REPO_ROOT:$SOURCE_MOUNT:ro,Z" \
        "$image" \
        bash -c "
            set -e

            # ── Prepare workspace (as root) ──
            cp -a $SOURCE_MOUNT $WORKSPACE_DIR
            chown -R $test_user:$test_user $WORKSPACE_DIR

            # ── Run everything as the test user ──
            su - $test_user -c '
                set -e
                cd $WORKSPACE_DIR

                # dbusmock handles private bus lifecycle via fixtures.

                # ── Python + Poetry setup ──
                if command -v uv >/dev/null 2>&1; then
                    uv venv --python $PYTHON_VERSION .venv
                    . .venv/bin/activate
                    uv pip install poetry
                else
                    python${PYTHON_VERSION} -m venv .venv 2>/dev/null \
                        || python3 -m venv .venv
                    . .venv/bin/activate
                    pip install --quiet --upgrade pip
                    pip install --quiet poetry
                fi

                echo \"--- python version ---\"
                python --version
                poetry install --with test --no-interaction
                echo \"--- deps installed ---\"

                # ── Test execution ──
                case \"$test_scope\" in
                    unit)
                        echo \"\"
                        echo \"--- unit tests ---\"
                        poetry run pytest tests/ --ignore=tests/integration -v --tb=short
                        ;;
                    integ)
                        echo \"\"
                        echo \"--- integration tests ---\"
                        poetry run pytest tests/integration/ -v --tb=short
                        ;;
                    all)
                        _rc=0

                        echo \"\"
                        echo \"--- unit tests ---\"
                        poetry run pytest tests/ --ignore=tests/integration -v --tb=short || _rc=\$?

                        echo \"\"
                        echo \"--- integration tests ---\"
                        poetry run pytest tests/integration/ -v --tb=short || { _integ_rc=\$?; [ \$_rc -eq 0 ] && _rc=\$_integ_rc; }

                        exit \$_rc
                        ;;
                esac

                # dbusmock fixtures handle cleanup automatically.
            '
        "

    local status=$?
    if [[ $status -eq 0 ]]; then
        echo -e "${C_GREEN}==> $name: PASS${C_RESET}"
    else
        echo -e "${C_RED}==> $name: FAIL${C_RESET}" >&2
    fi
    return "$status"
}

BUILD_ONLY=false
LIST_ONLY=false
NO_CACHE=false
TEST_SCOPE="all"
TARGETS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --build-only) BUILD_ONLY=true ;;
        --no-cache) NO_CACHE=true ;;
        --list) LIST_ONLY=true ;;
        --unit-only)
            [[ "$TEST_SCOPE" != "all" ]] && { echo "Error: --unit-only and --integ-only are mutually exclusive" >&2; exit 1; }
            TEST_SCOPE="unit" ;;
        --integ-only)
            [[ "$TEST_SCOPE" != "all" ]] && { echo "Error: --unit-only and --integ-only are mutually exclusive" >&2; exit 1; }
            TEST_SCOPE="integ" ;;
        -h|--help) usage; exit 0 ;;
        *) TARGETS+=("$1") ;;
    esac
    shift
done

if $LIST_ONLY; then
    for name in "${!DISTROS[@]}"; do
        echo "$name (${EXPECTED_PLATFORMS[$name]})"
    done | sort
    exit 0
fi

if [[ ${#TARGETS[@]} -eq 0 ]]; then
    TARGETS=("${!DISTROS[@]}")
fi

for target in "${TARGETS[@]}"; do
    if [[ -z "${DISTROS[$target]+x}" ]]; then
        echo -e "${C_RED}Error: unknown distro '$target'. Available: ${!DISTROS[*]}${C_RESET}" >&2
        exit 1
    fi
done

warn_keyring

for target in "${TARGETS[@]}"; do
    build_image "$target"
done

if $BUILD_ONLY; then
    echo -e "${C_GREEN}Images built.${C_RESET} Use '$0' without --build-only to run tests."
    exit 0
fi

PASSED=()
FAILED=()

for target in "${TARGETS[@]}"; do
    if run_tests "$target" "$TEST_SCOPE"; then
        PASSED+=("$target")
    else
        FAILED+=("$target")
    fi
done

echo ""
echo -e "${C_BOLD}===== Matrix Summary =====${C_RESET}"
for target in "${PASSED[@]}"; do
    echo -e "  ${C_GREEN}PASS${C_RESET}: $target ${C_DIM}(${EXPECTED_PLATFORMS[$target]})${C_RESET}"
done
for target in "${FAILED[@]}"; do
    echo -e "  ${C_RED}FAIL${C_RESET}: $target ${C_DIM}(${EXPECTED_PLATFORMS[$target]})${C_RESET}"
done

if [[ ${#FAILED[@]} -gt 0 ]]; then
    exit 1
fi
