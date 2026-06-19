"""Compatibility wrapper for the public CLI implementation."""

from npm_hook_risk.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
