"""JSON report: the full ReportData, for programmatic integration."""
from __future__ import annotations

import dataclasses
import json
from pathlib import Path

from noctis.reporting.report_data import ReportData


def generate(data: ReportData, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "report.json"

    payload = dataclasses.asdict(data)
    payload["severity_counts"] = data.severity_counts

    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    return path
