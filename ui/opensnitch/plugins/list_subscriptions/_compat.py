"""Runtime compatibility shim for StatsDialog across OpenSnitch versions."""


# Runtime class kept for isinstance checks.
try:
    from opensnitch.dialogs.events import StatsDialog
except ImportError:
    from opensnitch.dialogs.stats import StatsDialog  # type: ignore[assignment]

__all__ = ["StatsDialog"]
