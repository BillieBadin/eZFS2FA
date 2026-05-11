#!/bin/sh
# eZFS2FA+ is a hardened encrypted ZFS dataset interactive workflow offering two-factor authentication for sensitive services on FreeBSD systems, with Linux compatibility built in.
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Billie Badin, SIGORYX Engineering

set -eu

PREFIX="${PREFIX:-/usr/local}"
LIBEXEC="$PREFIX/libexec/ezfs2fa"
SBIN="$PREFIX/sbin"
DOC_DIR="$PREFIX/share/doc/ezfs2fa"
OS_NAME="$(uname -s)"
TMP_MAN=""

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: install.sh must run as root" >&2
    exit 1
fi


# ------------------------------------------------------------------------------
install_deps_freebsd() {
    if command -v pkg >/dev/null 2>&1; then
        echo "Installing FreeBSD dependencies..."
        pkg install -y python311 py311-cryptography libfido2 || \
            echo "WARNING: could not install all FreeBSD dependencies, continuing" >&2
    else
        echo "WARNING: pkg not found; skipping FreeBSD dependency installation" >&2
    fi
}
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
install_deps_linux() {
    echo "Installing Linux dependencies where available..."
    if command -v apt-get >/dev/null 2>&1; then
        if ! apt-get update; then
            echo "WARNING: apt-get update failed, continuing with existing package index" >&2
        fi
        apt-get install -y python3 python3-cryptography fido2-tools zfsutils-linux util-linux || \
            echo "WARNING: could not install all apt dependencies, continuing" >&2
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y python3 python3-cryptography fido2-tools util-linux zfs || \
            echo "WARNING: could not install all dnf dependencies. ZFS package names vary by distribution." >&2
    elif command -v pacman >/dev/null 2>&1; then
        pacman -Sy --needed --noconfirm python python-cryptography libfido2 util-linux zfs-utils || \
            echo "WARNING: could not install all pacman dependencies. ZFS package names may require an extra repository." >&2
    else
        echo "WARNING: no supported Linux package manager found; skipping dependency installation" >&2
    fi
}
# ------------------------------------------------------------------------------


case "$OS_NAME" in
    FreeBSD)
        GROUP="wheel"
        CONFIG="/usr/local/etc/ezfs2fa.json"
        MANDIR="/usr/local/man/man8"
        WRAPPER_SRC="packaging/freebsd/ezfs2fa"
        SCRATCH="mdmfs -M"
        install_deps_freebsd
        ;;
    Linux)
        GROUP="root"
        CONFIG="/etc/ezfs2fa.json"
        MANDIR="$PREFIX/share/man/man8"
        WRAPPER_SRC="packaging/linux/ezfs2fa"
        SCRATCH="ramfs"
        install_deps_linux
        ;;
    *)
        echo "ERROR: unsupported OS: $OS_NAME" >&2
        exit 1
        ;;
esac

mkdir -p "$LIBEXEC/ezfs2fa_lib" "$SBIN" "$DOC_DIR" "$MANDIR" "$(dirname "$CONFIG")"

install -o root -g "$GROUP" -m 0700 ezfs2fa.py "$LIBEXEC/ezfs2fa.py"
install -o root -g "$GROUP" -m 0600 ezfs2fa_lib/*.py "$LIBEXEC/ezfs2fa_lib/"
install -o root -g "$GROUP" -m 0755 "$WRAPPER_SRC" "$SBIN/ezfs2fa"
install -o root -g "$GROUP" -m 0755 DOCUMENTATION_to_man.py "$LIBEXEC/DOCUMENTATION_to_man.py"
install -o root -g "$GROUP" -m 0644 DOCUMENTATION.md "$DOC_DIR/DOCUMENTATION.md"

if [ ! -e "$CONFIG" ]; then
    "$SBIN/ezfs2fa" -c "$CONFIG" init >/dev/null
    if ! chown root:"$GROUP" "$CONFIG" 2>/dev/null; then
        echo "WARNING: could not set ownership on $CONFIG to root:$GROUP" >&2
    fi
    chmod 0600 "$CONFIG"
fi

if   command -v python3.11 >/dev/null 2>&1; then
    PYTHON=python3.11
elif command -v python3 >/dev/null 2>&1; then
    PYTHON=python3
else
    echo "ERROR: python3.11 or python3 is required" >&2
    exit 1
fi

TMP_MAN="$(mktemp "${TMPDIR:-/tmp}/ezfs2fa.man.8")"
cleanup_tmp() {
    if [ -n "$TMP_MAN" ] && [ -f "$TMP_MAN" ]; then
        rm -f "$TMP_MAN"
    fi
}
trap cleanup_tmp EXIT HUP INT TERM

"$PYTHON" "$LIBEXEC/DOCUMENTATION_to_man.py" "$DOC_DIR/DOCUMENTATION.md" "$TMP_MAN"
gzip -c "$TMP_MAN" > "$MANDIR/ezfs2fa.8.gz"
chmod 0644 "$MANDIR/ezfs2fa.8.gz"

cat <<DONE
Installed ezfs2fa.

Command:
    $SBIN/ezfs2fa

Python code:
    $LIBEXEC

Config:
    $CONFIG

Scratch backend:
    $SCRATCH

Man page:
    man 8 ezfs2fa
DONE
