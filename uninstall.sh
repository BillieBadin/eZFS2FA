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

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: uninstall.sh must run as root" >&2
    exit 1
fi

case "$OS_NAME" in
    FreeBSD)
        CONFIG="/usr/local/etc/ezfs2fa.json"
        MANDIR="/usr/local/man/man8"
        ;;
    Linux)
        CONFIG="/etc/ezfs2fa.json"
        MANDIR="$PREFIX/share/man/man8"
        ;;
    *)
        echo "ERROR: unsupported OS: $OS_NAME" >&2
        exit 1
        ;;
esac

if [ -f "$SBIN/ezfs2fa" ]; then
    rm -f "$SBIN/ezfs2fa"
fi

if [ -f "$LIBEXEC/ezfs2fa.py" ]; then
    rm -f "$LIBEXEC/ezfs2fa.py"
fi

if [ -d "$LIBEXEC/ezfs2fa_lib" ]; then
    rm -f "$LIBEXEC/ezfs2fa_lib"/*.py 2>/dev/null || true
    rmdir "$LIBEXEC/ezfs2fa_lib" 2>/dev/null || true
fi

if [ -f "$LIBEXEC/DOCUMENTATION_to_man.py" ]; then
    rm -f "$LIBEXEC/DOCUMENTATION_to_man.py"
fi

rmdir "$LIBEXEC" 2>/dev/null || true

if [ -f "$DOC_DIR/DOCUMENTATION.md" ]; then
    rm -f "$DOC_DIR/DOCUMENTATION.md"
fi

rmdir "$DOC_DIR" 2>/dev/null || true

if [ -f "$MANDIR/ezfs2fa.8.gz" ]; then
    rm -f "$MANDIR/ezfs2fa.8.gz"
fi

if [ -f "$CONFIG" ]; then
    cat <<WARN
WARNING: Deleting $CONFIG will prevent access to your data unless you made a backup.
Type Yes (exactly) to confirm deletion of this configuration file:
WARN
    read -r CONFIRM
    if [ "$CONFIRM" = "Yes" ]; then
        rm -f "$CONFIG"
        echo "Deleted $CONFIG"
    else
        echo "Skipped deleting $CONFIG"
    fi
fi

echo "Uninstall complete."
