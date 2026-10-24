from __future__ import annotations

import argparse
import importlib.util
import sys


def main() -> None:
    parser = argparse.ArgumentParser(description="Launch the local Strix One-Click dashboard.")
    parser.add_argument("--port", type=int, default=8765, help="Loopback port (default: 8765)")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    if importlib.util.find_spec("uvicorn") is None:
        print("Missing dashboard dependencies. Reinstall Strix with the one-click dependencies.", file=sys.stderr)
        raise SystemExit(2)
    import uvicorn
    print("Strix One-Click is local-only: http://127.0.0.1:" + str(args.port))
    uvicorn.run("strix.oneclick.app:app", host="127.0.0.1", port=args.port, log_level="warning", access_log=False)
