"""Load TOML using the supported Python runtime."""

import sys

__all__ = ["tomllib"]

if sys.version_info < (3, 10):
    raise SystemExit(
        "AGY Security requires Python 3.10 or later. Set PYTHON to a supported "
        "interpreter, then restart Antigravity."
    )

try:
    import tomllib as tomllib
except ModuleNotFoundError:  # Python 3.10
    try:
        import tomli as tomllib
    except ModuleNotFoundError as exc:
        raise SystemExit(
            "AGY Security requires tomli with Python 3.10. Install tomli for the selected "
            "interpreter or set PYTHON to Python 3.11 or later, then restart Antigravity."
        ) from exc
