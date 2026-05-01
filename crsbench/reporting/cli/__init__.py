"""CLI commands for the reporting module."""

from crsbench.reporting.cli.report_command import (
    add_report_subparser,
    run_report,
)

__all__ = [
    "add_report_subparser",
    "run_report",
]
