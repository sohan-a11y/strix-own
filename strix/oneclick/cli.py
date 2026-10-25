from __future__ import annotations

import argparse

from .app import serve


def main() -> None:
    parser = argparse.ArgumentParser(description="Launch the local Strix One-Click dashboard.")
    parser.add_argument("--port", type=int, default=8765, help="Loopback port (default: 8765)")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    serve(args.port)
