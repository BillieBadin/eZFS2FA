#!/usr/bin/env python3
# eZFS2FA+ is a hardened encrypted ZFS dataset interactive workflow offering two-factor authentication for sensitive services on FreeBSD systems, with Linux compatibility built in.
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Billie Badin, SIGORYX Engineering

"""
Convert eZFS2SVG plantuml diagrams to svg using default plantUML server or alternate specified one
"""

import argparse
import pathlib
import sys
import urllib.request
import zlib


SRC_DIR="./diags_plantuml"
DST_DIR="./diags_svg"

# DEFAULT_SERVER = "https://www.plantuml.com/plantuml"
DEFAULT_SERVER = "http://plantuml.46s.fr:8080/plantuml"

PLANTUML_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_"


def encode_plantuml(data: bytes) -> str:
    compressed = zlib.compress(data, 9)[2:-4]
    result     = []
    for i in range(0, len(compressed), 3):
        chunk = compressed[i:i + 3]
        b1 = chunk[0]
        b2 = chunk[1] if len(chunk) > 1 else 0
        b3 = chunk[2] if len(chunk) > 2 else 0
        result.append(PLANTUML_CHARS[(b1 >> 2) & 0x3F])
        result.append(PLANTUML_CHARS[((b1 & 0x3) << 4) | ((b2 >> 4) & 0xF)])
        if len(chunk) > 1:
            result.append(PLANTUML_CHARS[((b2 & 0xF) << 2) | ((b3 >> 6) & 0x3)])
        if len(chunk) > 2:
            result.append(PLANTUML_CHARS[b3 & 0x3F])
    return "".join(result)


def find_plantuml_files(src_dir: pathlib.Path) -> list[pathlib.Path]:
    files = []
    for suffix in ("*.puml", "*.plantuml"):
        files.extend(src_dir.glob(suffix))
    return sorted(path for path in files if path.is_file())


def convert_file(input_path: pathlib.Path, dst_dir: pathlib.Path, server: str) -> pathlib.Path:
    output_path = dst_dir / f"{input_path.stem}.svg"
    encoded     = encode_plantuml(input_path.read_bytes())
    url         = f"{server.rstrip('/')}/svg/{encoded}"
    urllib.request.urlretrieve(url, output_path)
    return output_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Convert all .puml and .plantuml files in SRC_DIR to SVG files in DST_DIR using a PlantUML server."
    )
    parser.add_argument(
        "--server",
        default=DEFAULT_SERVER,
        help=f"PlantUML server base URL. Default: {DEFAULT_SERVER}",
    )
    parser.add_argument(
        "--src-dir",
        default=SRC_DIR,
        help=f"Directory containing PlantUML files. Default: {SRC_DIR}",
    )
    parser.add_argument(
        "--dst-dir",
        default=DST_DIR,
        help=f"Directory for generated SVG files. Default: {DST_DIR}",
    )
    return parser.parse_args()


def main() -> int:
    args    = parse_args()
    src_dir = pathlib.Path(args.src_dir)
    dst_dir = pathlib.Path(args.dst_dir)
    if not src_dir.is_dir():
        print(f"Error: source directory does not exist: {src_dir}", file=sys.stderr)
        return 1
    dst_dir.mkdir(parents=True, exist_ok=True)
    files   = find_plantuml_files(src_dir)
    if not files:
        print(f"No .puml or .plantuml files found in {src_dir}")
        return 0
    failed  = 0
    for input_path in files:
        try:
            output_path = convert_file(input_path, dst_dir, args.server)
            print(f"Wrote: {output_path}")
        except Exception as exc:
            failed += 1
            print(f"Failed: {input_path}: {exc}", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
