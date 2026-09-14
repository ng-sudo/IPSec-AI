"""Reusable executive and technical report generation from actual analysis results."""

from .generator import (
    ReportInputError,
    generate_executive_report,
    generate_reports,
    generate_technical_report,
    write_reports,
)
from .models import ReportBundle, ReportDocument, ReportField, ReportFinding, ReportSection

__all__ = [
    "ReportBundle",
    "ReportDocument",
    "ReportField",
    "ReportFinding",
    "ReportInputError",
    "ReportSection",
    "generate_executive_report",
    "generate_reports",
    "generate_technical_report",
    "write_reports",
]
