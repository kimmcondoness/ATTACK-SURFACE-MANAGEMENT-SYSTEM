import json
from typing import Any, Dict, List

from scanner.base import BaseScanner, ScannerResult


class NucleiScanner(BaseScanner):
    binary_name = "nuclei"
    timeout_seconds = 180

    def build_command(self, target: str) -> List[str]:
        return [self.binary_name, "-u", target, "-jsonl", "-silent"]

    def parse_output(self, raw_output: str, target: str) -> List[Dict[str, Any]]:
        findings = []
        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = record.get("info", {})
            findings.append(
                {
                    "severity": info.get("severity", "low"),
                    "cve": ",".join(info.get("classification", {}).get("cve-id", []) or []) or None,
                    "title": info.get("name", "Unnamed finding"),
                    "description": info.get("description", ""),
                    "recommendation": info.get("remediation", ""),
                }
            )
        return findings

    def mock_result(self, target: str) -> ScannerResult:
        # Nuclei is not installed. The scan service checks is_available() first and skips
        # Nuclei (the built-in configuration checks still run), so no made-up findings are
        # ever produced; this only keeps the scanner interface complete.
        return ScannerResult(success=True, source="mock", data=[])
