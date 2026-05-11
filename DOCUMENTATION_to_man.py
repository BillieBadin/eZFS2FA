#!/usr/bin/env python3
# eZFS2FA+ is a hardened encrypted ZFS dataset interactive workflow offering two-factor authentication for sensitive services on FreeBSD systems, with Linux compatibility built in.
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Billie Badin, SIGORYX Engineering
"""
Convert README.md to a simple mdoc-style man page.

This supports only the small Markdown subset used by this
project: headings, bullets, fenced code blocks, and plain paragraphs.
"""

from   __future__ import annotations

import re
import sys
from   pathlib import Path

# ------------------------------------------------------------------------------
def esc(text: str) -> str:
    return text.replace('\\', '\\\\').replace('"', '\\"')
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def convert(md_text: str) -> str:
    lines = md_text.splitlines()
    out = [
        '.Dd May 7, 2026',
        '.Dt ezfs2fa 8',
        '.Os FreeBSD/Linux',
    ]
    in_code = False
    for line in lines:
        if line.startswith('```'):
            if in_code:
                out.append('.Ed')
                in_code = False
            else:
                out.append('.Bd -literal -offset indent')
                in_code = True
            continue
        if in_code:
            out.append(line)
            continue
        if line.startswith('# '):
            out.append(f'.Sh NAME')
            out.append(f'.Nm {esc(line[2:].strip())}')
            out.append('.Nd OpenZFS dataset protection with passphrase and FIDO2')
        elif line.startswith('## '):
            out.append(f'.Sh {esc(line[3:].strip()).upper()}')
        elif line.startswith('### '):
            out.append(f'.Ss {esc(line[4:].strip())}')
        elif line.startswith('- '):
            out.append('.Bl -bullet -compact')
            out.append(f'.It {esc(line[2:].strip())}')
            out.append('.El')
        elif not line.strip():
            out.append('.Pp')
        else:
            text = re.sub(r'`([^`]+)`', r'\\fB\1\\fP', esc(line))
            out.append(text)
    if in_code:
        out.append('.Ed')
    return '\n'.join(out) + '\n'
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def main() -> int:
    src = Path(sys.argv[1]) if len(sys.argv) > 1 else Path('README.md')
    dst = Path(sys.argv[2]) if len(sys.argv) > 2 else Path('ezfs2fa.8')
    dst.write_text(convert(src.read_text(encoding='utf-8')), encoding='utf-8')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
# ------------------------------------------------------------------------------
